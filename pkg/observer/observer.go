/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
)

var logger = log.New("sidetree-core-observer")

// Ledger interface to access ledger txn
type Ledger interface {
	RegisterForSidetreeTxn() <-chan []txn.SidetreeTxn
}

// OperationStore interface to access operation store
type OperationStore interface {
	Put(ops []*batch.AnchoredOperation) error
}

// OperationStoreProvider returns an operation store for the given namespace
type OperationStoreProvider interface {
	ForNamespace(namespace string) (OperationStore, error)
}

// OperationFilter filters out operations before they are persisted
type OperationFilter interface {
	Filter(uniqueSuffix string, ops []*batch.AnchoredOperation) ([]*batch.AnchoredOperation, error)
}

type TxnProcessorProviders struct {
	OpStoreProvider           OperationStoreProvider
	OperationProtocolProvider protocol.OperationProtocolProvider
}

// Providers contains all of the providers required by the TxnProcessor
type Providers struct {
	Ledger                 Ledger
	OpStoreProvider        OperationStoreProvider
	ProtocolClientProvider protocol.ClientProvider
}

// Observer receives transactions over a channel and processes them by storing them to an operation store
type Observer struct {
	*Providers

	stopCh chan struct{}
}

// New returns a new observer
func New(providers *Providers) *Observer {
	return &Observer{
		Providers: providers,
		stopCh:    make(chan struct{}, 1),
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

func (o *Observer) listen(txnsCh <-chan []txn.SidetreeTxn) {
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

func (o *Observer) process(txns []txn.SidetreeTxn) {
	for _, txn := range txns {
		pc, err := o.ProtocolClientProvider.ForNamespace(txn.Namespace)
		if err != nil {
			logger.Warnf("Failed to get protocol client for namespace [%s]: %s", txn.Namespace, err.Error())
			// TODO: Should we continue processing?
			continue
		}

		v, err := pc.Get(txn.TransactionTime)
		if err != nil {
			logger.Warnf("Failed to get processor for transaction time [%d]: %s", txn.TransactionTime, err.Error())
			// TODO: Should we continue processing?
			continue
		}

		err = v.TransactionProcessor().Process(txn)
		if err != nil {
			logger.Warnf("Failed to process anchor[%s]: %s", txn.AnchorString, err.Error())
			continue
		}
		logger.Debugf("Successfully processed anchor[%s]", txn.AnchorString)
	}
}

// TxnProcessor processes Sidetree transactions by persisting them to an operation store
type TxnProcessor struct {
	*TxnProcessorProviders
}

// NewTxnProcessor returns a new document operation processor
func NewTxnProcessor(providers *TxnProcessorProviders) *TxnProcessor {
	return &TxnProcessor{
		TxnProcessorProviders: providers,
	}
}

// Process persists all of the operations for the given anchor
func (p *TxnProcessor) Process(sidetreeTxn txn.SidetreeTxn) error {
	logger.Debugf("processing sidetree txn:%+v", sidetreeTxn)

	txnOps, err := p.OperationProtocolProvider.GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return fmt.Errorf("failed to retrieve operations for anchor string[%s]: %s", sidetreeTxn.AnchorString, err)
	}

	return p.processTxnOperations(txnOps, sidetreeTxn)
}

func (p *TxnProcessor) processTxnOperations(txnOps []*batch.AnchoredOperation, sidetreeTxn txn.SidetreeTxn) error {
	logger.Debugf("processing %d transaction operations", len(txnOps))

	batchSuffixes := make(map[string]bool)

	var ops []*batch.AnchoredOperation
	for index, op := range txnOps {
		_, ok := batchSuffixes[op.UniqueSuffix]
		if ok {
			logger.Warnf("[%s] duplicate suffix[%s] found in transaction operations: discarding operation %v", sidetreeTxn.Namespace, op.UniqueSuffix, op)
			continue
		}

		updatedOp := updateAnchoredOperation(op, uint(index), sidetreeTxn)

		logger.Debugf("updated operation with blockchain time: %s", updatedOp.UniqueSuffix)
		ops = append(ops, updatedOp)

		batchSuffixes[op.UniqueSuffix] = true
	}

	opStore, err := p.OpStoreProvider.ForNamespace(sidetreeTxn.Namespace)
	if err != nil {
		return errors.Wrapf(err, "error getting operation store for namespace [%s]", sidetreeTxn.Namespace)
	}

	err = opStore.Put(ops)
	if err != nil {
		return errors.Wrapf(err, "failed to store operation from anchor string[%s]", sidetreeTxn.AnchorString)
	}

	return nil
}

func updateAnchoredOperation(op *batch.AnchoredOperation, index uint, sidetreeTxn txn.SidetreeTxn) *batch.AnchoredOperation {
	//  The logical blockchain time that this operation was anchored on the blockchain
	op.TransactionTime = sidetreeTxn.TransactionTime
	// The transaction number of the transaction this operation was batched within
	op.TransactionNumber = sidetreeTxn.TransactionNumber
	// The index this operation was assigned to in the batch
	op.OperationIndex = index

	return op
}
