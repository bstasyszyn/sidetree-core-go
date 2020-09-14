/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

const anchorString = "1.anchorAddress"

func TestStartObserver(t *testing.T) {
	t.Run("test channel close", func(t *testing.T) {
		sidetreeTxnCh := make(chan []txn.SidetreeTxn, 100)

		providers := &Providers{
			Ledger: mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		close(sidetreeTxnCh)
		time.Sleep(200 * time.Millisecond)
	})

	t.Run("test success", func(t *testing.T) {
		sidetreeTxnCh := make(chan []txn.SidetreeTxn, 100)

		tp := &mocks.TxnProcessor{}

		pv := &mocks.ProtocolVersion{}
		pv.TransactionProcessorReturns(tp)

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0] = pv
		pcp := mocks.NewMockProtocolClientProvider().WithProtocolClient("", pc)

		providers := &Providers{
			Ledger:                 mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
			ProtocolClientProvider: pcp,
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		sidetreeTxnCh <- []txn.SidetreeTxn{{TransactionTime: 20, TransactionNumber: 2, AnchorString: "1.address"}}
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 1, tp.ProcessCallCount())
	})
}

func TestTxnProcessor_Process(t *testing.T) {
	t.Run("test error from txn operations provider", func(t *testing.T) {
		errExpected := fmt.Errorf("txn operations provider error")

		opp := &mockTxnOpsProvider{
			err: errExpected,
		}

		providers := &TxnProcessorProviders{
			OpStore:                   &mockOperationStore{},
			OperationProtocolProvider: opp,
		}

		p := NewTxnProcessor(providers)
		err := p.Process(txn.SidetreeTxn{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestProcessTxnOperations(t *testing.T) {
	t.Run("test error from operationStore Put", func(t *testing.T) {
		providers := &TxnProcessorProviders{
			OpStore: &mockOperationStore{putFunc: func(ops []*batch.AnchoredOperation) error {
				return fmt.Errorf("put error")
			}},
		}

		p := NewTxnProcessor(providers)
		err := p.processTxnOperations([]*batch.AnchoredOperation{{UniqueSuffix: "abc"}}, txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store operation from anchor string")
	})

	t.Run("test success", func(t *testing.T) {
		providers := &TxnProcessorProviders{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore:                   &mockOperationStore{},
		}

		p := NewTxnProcessor(providers)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		err = p.processTxnOperations(batchOps, txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)
	})

	t.Run("success - multiple operations with same suffix in transaction operations", func(t *testing.T) {
		providers := &TxnProcessorProviders{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore:                   &mockOperationStore{},
		}

		p := NewTxnProcessor(providers)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		// add same operations again to create scenario where batch has multiple operations with same suffix
		// only first operation will be processed, subsequent operations will be discarded
		batchOps = append(batchOps, batchOps...)

		err = p.processTxnOperations(batchOps, txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)
	})
}

func TestUpdateOperation(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		updatedOps := updateAnchoredOperation(&batch.AnchoredOperation{UniqueSuffix: "abc"},
			1, txn.SidetreeTxn{TransactionTime: 20, TransactionNumber: 2})
		require.Equal(t, uint64(20), updatedOps.TransactionTime)
		require.Equal(t, uint64(2), updatedOps.TransactionNumber)
		require.Equal(t, uint(1), updatedOps.OperationIndex)
	})
}

type mockLedger struct {
	registerForSidetreeTxnValue chan []txn.SidetreeTxn
}

func (m mockLedger) RegisterForSidetreeTxn() <-chan []txn.SidetreeTxn {
	return m.registerForSidetreeTxnValue
}

type mockDCAS struct {
	readFunc func(key string) ([]byte, error)
}

func (m mockDCAS) Read(key string) ([]byte, error) {
	if m.readFunc != nil {
		return m.readFunc(key)
	}
	return nil, nil
}

func (m mockDCAS) Write(content []byte) (string, error) {
	return "", errors.New("not implemented")
}

type mockOperationStore struct {
	putFunc func(ops []*batch.AnchoredOperation) error
	getFunc func(suffix string) ([]*batch.AnchoredOperation, error)
}

func (m *mockOperationStore) Put(ops []*batch.AnchoredOperation) error {
	if m.putFunc != nil {
		return m.putFunc(ops)
	}
	return nil
}

func (m *mockOperationStore) Get(suffix string) ([]*batch.AnchoredOperation, error) {
	if m.getFunc != nil {
		return m.getFunc(suffix)
	}
	return nil, nil
}

type mockOperationStoreProvider struct {
	opStore OperationStore
	err     error
}

func (m *mockOperationStoreProvider) ForNamespace(string) (OperationStore, error) {
	if m.err != nil {
		return nil, m.err
	}

	return m.opStore, nil
}

type mockTxnOpsProvider struct {
	err error
}

func (m *mockTxnOpsProvider) GetTxnOperations(txn *txn.SidetreeTxn) ([]*batch.AnchoredOperation, error) {
	if m.err != nil {
		return nil, m.err
	}

	op := &batch.AnchoredOperation{
		UniqueSuffix: "abc",
	}

	return []*batch.AnchoredOperation{op}, nil
}
