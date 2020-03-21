/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
)

// OperationFilter filters out invalid operations.
type OperationFilter struct {
	*OperationProcessor
}

// NewOperationFilter returns new operation filter with the given name. (Note that name is only used for logging.)
func NewOperationFilter(name string, store OperationStoreClient) *OperationFilter {
	return &OperationFilter{
		OperationProcessor: New(name, store),
	}
}

// Filter filters out the invalid operations and returns only the valid ones
func (s *OperationFilter) Filter(uniqueSuffix string, newOps []*batch.Operation) ([]*batch.Operation, error) {
	log.Infof("[%s] Validating operations for unique suffix [%s]...", s.name, uniqueSuffix)

	ops, err := s.store.Get(uniqueSuffix)
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			return nil, err
		}

		log.Infof("[%s] Unique suffix not found in the store [%s]", s.name, uniqueSuffix)
	}

	ops = append(ops, newOps...)

	sortOperations(ops)

	log.Infof("[%s] Found %d operations for unique suffix [%s]: %+v", s.name, len(ops), uniqueSuffix, ops)

	// split operations info 'full' and 'update' operations
	fullOps, updateOps := splitOperations(ops)
	if len(fullOps) == 0 {
		return nil, errors.New("missing create operation")
	}

	// apply 'full' operations first
	validFullOps, rm := s.getValidOperations(fullOps, &resolutionModel{})

	var validUpdateOps []*batch.Operation
	if rm.Doc == nil {
		log.Infof("[%s] Document was revoked [%s]", s.name, uniqueSuffix)
	} else {
		// next apply update ops since last 'full' transaction
		validUpdateOps, _ = s.getValidOperations(getOpsWithTxnGreaterThan(updateOps, rm.LastOperationTransactionTime, rm.LastOperationTransactionNumber), rm)
	}

	var validNewOps []*batch.Operation
	for _, op := range append(validFullOps, validUpdateOps...) {
		if contains(newOps, op) {
			validNewOps = append(validNewOps, op)
		}
	}

	return validNewOps, nil
}

func (s *OperationFilter) getValidOperations(ops []*batch.Operation, rm *resolutionModel) ([]*batch.Operation, *resolutionModel) {
	var validOps []*batch.Operation
	for _, op := range ops {
		m, err := s.applyOperation(op, rm)
		if err != nil {
			log.Warnf("[%s] Rejecting invalid operation {ID: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.ID, op.Type, op.TransactionTime, op.TransactionNumber, err)
			continue
		}

		validOps = append(validOps, op)
		rm = m

		log.Infof("[%s] After applying op %+v, New doc: %s", s.name, op, rm.Doc)
	}

	return validOps, rm
}
