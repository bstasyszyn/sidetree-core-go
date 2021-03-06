/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	"github.com/stretchr/testify/require"
)

func TestStartObserver(t *testing.T) {

	t.Run("test error from processSidetreeTxn", func(t *testing.T) {
		sidetreeTxnCh := make(chan []SidetreeTxn, 100)
		isCalled := false
		var rw sync.RWMutex
		readFunc := func(key string) ([]byte, error) {
			rw.Lock()
			isCalled = true
			rw.Unlock()
			return nil, fmt.Errorf("read error")
		}
		Start(mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh}, mockDACS{readFunc: readFunc}, nil)
		sidetreeTxnCh <- []SidetreeTxn{{TransactionTime: 20, TransactionNumber: 2, AnchorAddress: "address"}}
		time.Sleep(200 * time.Millisecond)
		rw.RLock()
		require.True(t, isCalled)
		rw.RUnlock()

	})

	t.Run("test channel close", func(t *testing.T) {
		sidetreeTxnCh := make(chan []SidetreeTxn, 100)
		Start(mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh}, nil, nil)
		close(sidetreeTxnCh)
		time.Sleep(200 * time.Millisecond)
	})

	t.Run("test success", func(t *testing.T) {
		sidetreeTxnCh := make(chan []SidetreeTxn, 100)
		isCalled := false
		var rw sync.RWMutex
		Start(mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh}, mockDACS{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&AnchorFile{})
			}
			b, err := json.Marshal(batch.Operation{})
			require.NoError(t, err)
			return json.Marshal(&BatchFile{Operations: []string{docutil.EncodeToString(b)}})
		}}, mockOperationStore{putFunc: func(ops []batch.Operation) error {
			rw.Lock()
			isCalled = true
			rw.Unlock()
			return nil
		}})
		sidetreeTxnCh <- []SidetreeTxn{{TransactionTime: 20, TransactionNumber: 2, AnchorAddress: "address"}}
		time.Sleep(200 * time.Millisecond)
		rw.RLock()
		require.True(t, isCalled)
		rw.RUnlock()
	})
}

func TestProcessSidetreeTxn(t *testing.T) {
	t.Run("test error from dacs read", func(t *testing.T) {
		err := processSidetreeTxn(SidetreeTxn{}, mockDACS{readFunc: func(key string) ([]byte, error) { return nil, fmt.Errorf("read error") }}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to retrieve content for anchor")
	})

	t.Run("test error from getAnchorFile", func(t *testing.T) {
		err := processSidetreeTxn(SidetreeTxn{}, mockDACS{readFunc: func(key string) ([]byte, error) { return []byte("1"), nil }}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal anchor")
	})

	t.Run("test error from processBatchFile", func(t *testing.T) {
		err := processSidetreeTxn(SidetreeTxn{AnchorAddress: "anchorAddress"}, mockDACS{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&AnchorFile{})
			}
			return nil, fmt.Errorf("read error")
		}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to retrieve content for batch")
	})
}

func TestProcessBatchFile(t *testing.T) {
	t.Run("test error from getBatchFile", func(t *testing.T) {
		err := processBatchFile("", SidetreeTxn{AnchorAddress: "anchorAddress"}, mockDACS{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&AnchorFile{})
			}
			return []byte("1"), nil
		}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal batch")
	})

	t.Run("test error from updateOperation", func(t *testing.T) {
		err := processBatchFile("", SidetreeTxn{AnchorAddress: "anchorAddress"}, mockDACS{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&AnchorFile{})
			}

			return json.Marshal(&BatchFile{Operations: []string{"1"}})
		}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update operation with blockchain metadata")
	})

	t.Run("test error from operationStore Put", func(t *testing.T) {
		err := processBatchFile("", SidetreeTxn{AnchorAddress: "anchorAddress"}, mockDACS{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&AnchorFile{})
			}
			b, err := json.Marshal(batch.Operation{})
			require.NoError(t, err)
			return json.Marshal(&BatchFile{Operations: []string{docutil.EncodeToString(b)}})
		}}, mockOperationStore{putFunc: func(ops []batch.Operation) error {
			return fmt.Errorf("put error")
		}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store operation from batch")
	})

	t.Run("test success", func(t *testing.T) {
		err := processBatchFile("", SidetreeTxn{AnchorAddress: "anchorAddress"}, mockDACS{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&AnchorFile{})
			}
			b, err := json.Marshal(batch.Operation{})
			require.NoError(t, err)
			return json.Marshal(&BatchFile{Operations: []string{docutil.EncodeToString(b)}})
		}}, mockOperationStore{})
		require.NoError(t, err)
	})

}

func TestUpdateOperation(t *testing.T) {
	t.Run("test error from unmarshal decoded ops", func(t *testing.T) {
		_, err := updateOperation(docutil.EncodeToString([]byte("ops")), 1, SidetreeTxn{AnchorAddress: "anchorAddress"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal decoded ops")
	})

	t.Run("test success", func(t *testing.T) {
		b, err := json.Marshal(batch.Operation{})
		require.NoError(t, err)
		updatedOps, err := updateOperation(docutil.EncodeToString(b), 1, SidetreeTxn{TransactionTime: 20, TransactionNumber: 2})
		require.NoError(t, err)
		require.Equal(t, uint64(20), updatedOps.TransactionTime)
		require.Equal(t, uint64(2), updatedOps.TransactionNumber)
		require.Equal(t, uint(1), updatedOps.OperationIndex)
	})

}

type mockLedger struct {
	registerForSidetreeTxnValue chan []SidetreeTxn
}

func (m mockLedger) RegisterForSidetreeTxn() <-chan []SidetreeTxn {
	return m.registerForSidetreeTxnValue

}

type mockDACS struct {
	readFunc func(key string) ([]byte, error)
}

func (m mockDACS) Read(key string) ([]byte, error) {
	if m.readFunc != nil {
		return m.readFunc(key)
	}
	return nil, nil
}

type mockOperationStore struct {
	putFunc func(ops []batch.Operation) error
}

func (m mockOperationStore) Put(ops []batch.Operation) error {
	if m.putFunc != nil {
		return m.putFunc(ops)
	}
	return nil
}
