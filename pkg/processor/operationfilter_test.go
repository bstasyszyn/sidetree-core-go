/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestOperationFilter_Filter(t *testing.T) {
	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected store error")
		store := mocks.NewMockOperationStore(nil)
		store.Validate = false
		store.Err = errExpected

		createOp := getCreateOperation()

		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp.UniqueSuffix, []*batch.Operation{createOp})
		require.EqualError(t, err, err.Error())
		require.Empty(t, validOps)
	})

	t.Run("No create operation error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp := getCreateOperation()
		updateOp1 := getUpdateOperation(createOp.UniqueSuffix, 1)

		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp.UniqueSuffix, []*batch.Operation{updateOp1})
		require.EqualError(t, err, "missing create operation")
		require.Empty(t, validOps)
	})

	t.Run("Unique suffix not found in store", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp := getCreateOperation()

		updateOp1 := getUpdateOperation(createOp.UniqueSuffix, 1)
		updateOp2 := getUpdateOperation(createOp.UniqueSuffix, 3)

		// The second update should be discarded
		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp.UniqueSuffix, []*batch.Operation{createOp, updateOp1, updateOp2})
		require.NoError(t, err)
		require.Len(t, validOps, 2)
		require.True(t, validOps[0] == createOp)
		require.True(t, validOps[1] == updateOp1)
	})

	t.Run("Unique suffix exists in store", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp1 := getCreateOperation()
		err := store.Put(createOp1)
		require.Nil(t, err)

		createOp2 := getCreateOperation()
		updateOp1 := getUpdateOperation(createOp1.UniqueSuffix, 1)
		updateOp2 := getUpdateOperation(createOp1.UniqueSuffix, 3)

		// The create and second update should be discarded
		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp1.UniqueSuffix, []*batch.Operation{createOp2, updateOp1, updateOp2})
		require.NoError(t, err)
		require.Len(t, validOps, 1)
		require.True(t, validOps[0] == updateOp1)
	})

	t.Run("With revoke operation", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp1 := getCreateOperation()
		err := store.Put(createOp1)
		require.Nil(t, err)

		createOp2 := getCreateOperation()
		updateOp := getUpdateOperation(createOp1.UniqueSuffix, 1)
		revokeOp := getRevokeOperation(createOp1.UniqueSuffix, 2)

		// The create should be discarded (since there's already a create) and update should be discarded since the document was revoked
		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp1.UniqueSuffix, []*batch.Operation{createOp2, updateOp, revokeOp})
		require.NoError(t, err)
		require.Len(t, validOps, 1)
		require.True(t, validOps[0] == revokeOp)
	})
}
