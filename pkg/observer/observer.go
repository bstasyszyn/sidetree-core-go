/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

var logger = logrus.New()

// SidetreeTxn defines info about sidetree transaction
type SidetreeTxn struct {
	TransactionTime   uint64
	TransactionNumber uint64
	AnchorAddress     string
}

// Ledger interface to access ledger txn
type Ledger interface {
	RegisterForSidetreeTxn() <-chan []SidetreeTxn
}

// DCAS interface to access content addressable storage
type DCAS interface {
	Read(key string) ([]byte, error)
}

// OperationStore interface to access operation store
type OperationStore interface {
	Put(ops []*batch.Operation) error
}

// OperationStoreProvider returns an operation store for the given namespace
type OperationStoreProvider interface {
	ForNamespace(namespace string) (OperationStore, error)
}

// OperationFilter filters out operations before they are persisted
type OperationFilter interface {
	Filter(uniqueSuffix string, ops []*batch.Operation) ([]*batch.Operation, error)
}

// OperationFilterProvider returns an operation filter for the given namespace
type OperationFilterProvider interface {
	Get(namespace string) (OperationFilter, error)
}

// Providers contains all of the providers required by the TxnProcessor
type Providers struct {
	Ledger           Ledger
	DCASClient       DCAS
	OpStoreProvider  OperationStoreProvider
	OpFilterProvider OperationFilterProvider
}

// Observer receives transactions over a channel and processes them by storing them to an operation store
type Observer struct {
	*Providers

	processor *TxnProcessor
	stopCh    chan struct{}
}

// New returns a new observer
func New(providers *Providers) *Observer {
	return &Observer{
		Providers: providers,
		stopCh:    make(chan struct{}),
		processor: NewTxnProcessor(providers),
	}
}

// Start starts observer routines
func (o *Observer) Start() {
	go o.listen(o.Ledger.RegisterForSidetreeTxn())
}

// Stop stops the observer
func (o *Observer) Stop() {
	o.stopCh <- struct{}{}
}

func (o *Observer) listen(txnsCh <-chan []SidetreeTxn) {
	for {
		select {
		case <-o.stopCh:
			logger.Infof("The observer has been stopped. Exiting.")
			return

		case txns, ok := <-txnsCh:
			if !ok {
				logger.Warnf("Notification channel was closed. Exiting.")
				return
			}

			o.process(txns)
		}
	}
}

func (o *Observer) process(txns []SidetreeTxn) {
	for _, txn := range txns {
		err := o.processor.Process(txn)
		if err != nil {
			logger.Warnf("Failed to process anchor[%s]: %s", txn.AnchorAddress, err.Error())
			continue
		}
		logger.Debugf("Successfully processed anchor[%s]", txn.AnchorAddress)
	}
}

// TxnProcessor processes Sidetree transactions by persisting them to an operation store
type TxnProcessor struct {
	*Providers
}

// NewTxnProcessor returns a new document operation processor
func NewTxnProcessor(providers *Providers) *TxnProcessor {
	return &TxnProcessor{
		Providers: providers,
	}
}

// Process persists all of the operations for the given anchor
func (p *TxnProcessor) Process(sidetreeTxn SidetreeTxn) error {
	logger.Debugf("processing sidetree txn:%+v", sidetreeTxn)

	content, err := p.DCASClient.Read(sidetreeTxn.AnchorAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to retrieve content for anchor: key[%s]", sidetreeTxn.AnchorAddress)
	}

	logger.Debugf("cas content for anchor[%s]: %s", sidetreeTxn.AnchorAddress, string(content))

	af, err := getAnchorFile(content)
	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal anchor[%s]", sidetreeTxn.AnchorAddress)
	}

	return p.processBatchFile(af.BatchFileHash, sidetreeTxn)
}

func (p *TxnProcessor) processBatchFile(batchFileAddress string, sidetreeTxn SidetreeTxn) error {
	content, err := p.DCASClient.Read(batchFileAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to retrieve content for batch: key[%s]", batchFileAddress)
	}

	bf, err := getBatchFile(content)
	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal batch[%s]", batchFileAddress)
	}

	logger.Debugf("batch file operations: %s", bf.Operations)
	var ops []*batch.Operation
	for index, op := range bf.Operations {
		updatedOp, errUpdateOps := updateOperation(op, uint(index), sidetreeTxn)
		if errUpdateOps != nil {
			return errors.Wrapf(errUpdateOps, "failed to update operation with blockchain metadata")
		}

		logger.Debugf("updated operation with blockchain time: %s", updatedOp.ID)
		ops = append(ops, updatedOp)
	}

	for suffix, mapping := range mapOperationsByUniqueSuffix(ops) {
		logger.Debugf("Filtering operations for namespace [%s] and suffix [%s]", mapping.namespace, suffix)

		opFilter, err := p.OpFilterProvider.Get(mapping.namespace)
		if err != nil {
			return errors.Wrapf(err, "error getting operation filter for namespace [%s]", mapping.namespace)
		}

		validOps, err := opFilter.Filter(suffix, mapping.operations)
		if err != nil {
			return errors.Wrap(err, "error filtering invalid operations")
		}

		opStore, err := p.OpStoreProvider.ForNamespace(mapping.namespace)
		if err != nil {
			return errors.Wrapf(err, "error getting operation store for namespace [%s]", mapping.namespace)
		}

		err = opStore.Put(validOps)
		if err != nil {
			return errors.Wrapf(err, "failed to store operation from batch[%s]", batchFileAddress)
		}
	}

	return nil
}

func updateOperation(encodedOp string, index uint, sidetreeTxn SidetreeTxn) (*batch.Operation, error) {
	decodedOp, err := docutil.DecodeString(encodedOp)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode ops")
	}
	var op batch.Operation
	err = json.Unmarshal(decodedOp, &op)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal decoded ops")
	}

	//  The logical blockchain time that this operation was anchored on the blockchain
	op.TransactionTime = sidetreeTxn.TransactionTime
	// The transaction number of the transaction this operation was batched within
	op.TransactionNumber = sidetreeTxn.TransactionNumber
	// The index this operation was assigned to in the batch
	op.OperationIndex = index

	return &op, nil
}

// AnchorFile defines the schema of a Anchor File
type AnchorFile struct {
	// BatchFileHash is encoded hash of the batch file
	BatchFileHash string `json:"batchFileHash"`

	// UniqueSuffixes is an array of suffixes (the unique portion of the ID string that differentiates
	// one document from another) for all documents that are declared to have operations within the associated batch file.
	UniqueSuffixes []string `json:"uniqueSuffixes"`
}

// getAnchorFile creates new anchor file struct from bytes
var getAnchorFile = func(bytes []byte) (*AnchorFile, error) {
	return unmarshalAnchorFile(bytes)
}

// unmarshalAnchorFile creates new anchor file struct from bytes
func unmarshalAnchorFile(bytes []byte) (*AnchorFile, error) {
	af := &AnchorFile{}
	err := json.Unmarshal(bytes, af)
	if err != nil {
		return nil, err
	}

	return af, nil
}

// BatchFile defines the schema of a Batch File and its related operations.
type BatchFile struct {
	// Operations included in this batch file, each operation is an encoded string
	Operations []string `json:"operations"`
}

// getBatchFile creates new batch file struct from bytes
var getBatchFile = func(bytes []byte) (*BatchFile, error) {
	return unmarshalBatchFile(bytes)
}

// unmarshalBatchFile creates new batch file struct from bytes
func unmarshalBatchFile(bytes []byte) (*BatchFile, error) {
	bf := &BatchFile{}
	err := json.Unmarshal(bytes, bf)
	if err != nil {
		return nil, err
	}
	return bf, nil
}

type operationsMapping struct {
	namespace  string
	operations []*batch.Operation
}

func mapOperationsByUniqueSuffix(ops []*batch.Operation) map[string]*operationsMapping {
	m := make(map[string]*operationsMapping)

	for _, op := range ops {
		mapping, ok := m[op.UniqueSuffix]
		if !ok {
			ns, err := namespaceFromDocID(op.ID)
			if err != nil {
				logger.Infof("Skipping operation since could not get namespace from operation {ID: %s, UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.ID, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)
				continue
			}

			mapping = &operationsMapping{
				namespace: ns,
			}

			m[op.UniqueSuffix] = mapping
		}

		mapping.operations = append(mapping.operations, op)
	}

	return m
}

func namespaceFromDocID(id string) (string, error) {
	pos := strings.LastIndex(id, ":")
	if pos == -1 {
		return "", errors.Errorf("invalid ID [%s]", id)
	}

	return id[0:pos], nil
}
