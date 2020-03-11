/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"errors"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// OperationProcessor will process document operations in chronological order and create final document during resolution.
// It uses operation store client to retrieve all operations that are related to requested document.
type OperationProcessor struct {
	name  string
	store OperationStoreClient
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {
	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*batch.Operation, error)
	// Put storing operation
	Put(op *batch.Operation) error
}

// New returns new operation processor with the given name. (Note that name is only used for logging.)
func New(name string, store OperationStoreClient) *OperationProcessor {
	return &OperationProcessor{name: name, store: store}
}

// Resolve document based on the given unique suffix
// Parameters:
// uniqueSuffix - unique portion of ID to resolve. for example "abc123" in "did:sidetree:abc123"
func (s *OperationProcessor) Resolve(uniqueSuffix string) (document.Document, error) {
	ops, err := s.store.Get(uniqueSuffix)
	if err != nil {
		return nil, err
	}

	sortOperations(ops)

	log.Infof("[%s] Found %d operations for unique suffix [%s]: %+v", s.name, len(ops), uniqueSuffix, ops)

	rm := &resolutionModel{}

	// split operations info 'full' and 'update' operations
	fullOps, updateOps := splitOperations(ops)
	if len(fullOps) == 0 {
		return nil, errors.New("missing create operation")
	}

	// apply 'full' operations first
	rm, err = s.applyOperations(fullOps, rm)
	if err != nil {
		return nil, err
	}

	if rm.Doc == nil {
		return nil, errors.New("document was deleted")
	}

	// next apply update ops since last 'full' transaction
	rm, err = s.applyOperations(getOpsWithTxnGreaterThan(updateOps, rm.LastOperationTransactionTime, rm.LastOperationTransactionNumber), rm)
	if err != nil {
		return nil, err
	}

	return rm.Doc, nil
}

func sortOperations(ops []*batch.Operation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].TransactionTime < ops[j].TransactionTime {
			return true
		}

		return ops[i].TransactionNumber < ops[j].TransactionNumber
	})
}

func splitOperations(ops []*batch.Operation) (fullOps, updateOps []*batch.Operation) {
	for _, op := range ops {
		if op.Type == batch.OperationTypeUpdate {
			updateOps = append(updateOps, op)
		} else { // Create, Recover, Delete
			fullOps = append(fullOps, op)
		}
	}

	return fullOps, updateOps
}

func getOpsWithTxnGreaterThan(ops []*batch.Operation, txnTime, txnNumber uint64) []*batch.Operation {
	for index, op := range ops {
		if op.TransactionTime < txnTime {
			continue
		}

		if op.TransactionTime > txnTime {
			return ops[index:]
		}

		if op.TransactionNumber > txnNumber {
			return ops[index:]
		}
	}

	return nil
}

func (s *OperationProcessor) applyOperations(ops []*batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	var err error

	for _, op := range ops {
		if rm, err = s.applyOperation(op, rm); err != nil {
			return nil, err
		}

		log.Infof("After applying op %+v, New doc: %s", op, rm.Doc)
	}

	return rm, nil
}

type resolutionModel struct {
	Doc                            document.Document
	LastOperationTransactionTime   uint64
	LastOperationTransactionNumber uint64
	NextUpdateOTPHash              string
	NextRecoveryOTPHash            string
}

func (s *OperationProcessor) applyOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	switch operation.Type {
	case batch.OperationTypeCreate:
		return s.applyCreateOperation(operation, rm)
	case batch.OperationTypeUpdate:
		return s.applyUpdateOperation(operation, rm)
	case batch.OperationTypeDelete:
		return s.applyDeleteOperation(operation, rm)
	default:
		return nil, errors.New("operation type not supported for process operation")
	}
}

func (s *OperationProcessor) applyCreateOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	log.Infof("[%s] Applying create operation: %+v", s.name, operation)

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	doc, err := document.FromBytes([]byte(operation.Document))
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		NextUpdateOTPHash:              operation.NextUpdateOTPHash,
		NextRecoveryOTPHash:            operation.NextRecoveryOTPHash}, nil
}

func (s *OperationProcessor) applyUpdateOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	log.Infof("[%s] Applying update operation: %+v", s.name, operation)

	if rm.Doc == nil {
		return nil, errors.New("update cannot be first operation")
	}

	err := isValidHash(operation.UpdateOTP, rm.NextUpdateOTPHash)
	if err != nil {
		return nil, err
	}

	docBytes, err := rm.Doc.Bytes()
	if err != nil {
		return nil, err
	}

	// since update will be changed to operate on did document instead of bytes
	// there will be no extra conversions from/to bytes
	updatedDocBytes, err := operation.Patch.Apply(docBytes)
	if err != nil {
		return nil, err
	}

	log.Infof("[%s] After applying update operation: %+v, New doc: %s", s.name, operation, updatedDocBytes)

	doc, err := document.FromBytes(updatedDocBytes)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionNumber: operation.TransactionNumber,
		NextUpdateOTPHash:              operation.NextUpdateOTPHash,
		NextRecoveryOTPHash:            operation.NextRecoveryOTPHash}, nil
}

func (s *OperationProcessor) applyDeleteOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	log.Infof("[%s] Applying delete operation: %+v", s.name, operation)

	if rm.Doc == nil {
		return nil, errors.New("delete can only be applied to an existing document")
	}

	err := isValidHash(operation.RecoveryOTP, rm.NextRecoveryOTPHash)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            nil,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		NextUpdateOTPHash:              "",
		NextRecoveryOTPHash:            ""}, nil
}

func isValidHash(encodedContent, encodedMultihash string) error {
	content, err := docutil.DecodeString(encodedContent)
	if err != nil {
		return err
	}

	code, err := docutil.GetMultihashCode(encodedMultihash)
	if err != nil {
		return err
	}

	computedMultihash, err := docutil.ComputeMultihash(uint(code), content)
	if err != nil {
		return err
	}

	encodedComputedMultihash := docutil.EncodeToString(computedMultihash)

	if encodedComputedMultihash != encodedMultihash {
		return errors.New("supplied hash doesn't match original content")
	}

	return nil
}
