/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

import (
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

var logger = logrus.New()

// OperationQueue defines the functions for adding and removing operations from a queue
type OperationQueue interface {
	// Add adds the given operation to the tail of the queue and returns the new length of the queue
	Add(data *batch.OperationInfo) (uint, error)
	// Remove removes (up to) the given number of operations from the head of the queue. The operation are returned
	// along with the new length of the queue.
	Remove(num uint) ([]*batch.OperationInfo, uint, error)
	// Peek returns (up to) the given number of operations from the head of the queue but does not remove them.
	Peek(num uint) ([]*batch.OperationInfo, error)
	// Len returns the number of operation in the queue
	Len() uint
}

// Committer is invoked to commit the Cut operation.
// The new number of pending items in the queue is returned, and an err if any.
type Committer = func() (pending uint, err error)

// BatchCutter implements batch cutting
type BatchCutter struct {
	pendingBatch OperationQueue
	client       protocol.Client
}

// New creates a batchCutter implementation
func New(client protocol.Client, queue OperationQueue) *BatchCutter {
	return &BatchCutter{
		client:       client,
		pendingBatch: queue,
	}
}

// Add adds the given Data to pending batch queue and returns the total
// number of pending operations.
func (r *BatchCutter) Add(operation *batch.OperationInfo) (uint, error) {
	// Enqueuing operation into batch
	return r.pendingBatch.Add(operation)
}

// Cut returns the current batch along with number of items that should be remaining in the queue after commit is called.
// If force is false then the batch will be cut only if it has reached the max batch size (as specified in the protocol)
// If force is true then the batch will be cut if there is at least one Data in the batch
// Note that the operations are removed from the queue when the committer is invoked, otherwise they remain in the queue.
func (r *BatchCutter) Cut(force bool) ([]*batch.OperationInfo, uint, Committer, error) {
	pending := r.pendingBatch.Len()

	maxOperationsPerBatch := r.client.Current().MaxOperationsPerBatch
	if !force && pending < maxOperationsPerBatch {
		return nil, pending, nil, nil
	}

	batchSize := min(pending, maxOperationsPerBatch)
	ops, err := r.pendingBatch.Peek(batchSize)
	if err != nil {
		return nil, pending, nil, err
	}

	pending -= batchSize

	logger.Debugf("Pending Size: %d, MaxOperationsPerBatch: %d, Batch Size: %d", pending, maxOperationsPerBatch, batchSize)

	committer := func() (uint, error) {
		logger.Infof("Removing %d operations from the queue", batchSize)
		_, p, err := r.pendingBatch.Remove(batchSize)
		return p, err
	}

	return ops, pending, committer, nil
}

func min(i, j uint) uint {
	if i < j {
		return i
	}
	return j
}
