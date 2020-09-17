/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func TestParseUpdateOperation(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
		SignatureAlgorithms:          []string{"alg"},
		KeyAlgorithms:                []string{"crv"},
	}

	parser := NewParser(p)

	t.Run("success", func(t *testing.T) {
		payload, err := getUpdateRequestBytes()
		require.NoError(t, err)

		op, err := parser.ParseUpdateOperation(payload)
		require.NoError(t, err)
		require.Equal(t, batch.OperationTypeUpdate, op.Type)
	})
	t.Run("invalid json", func(t *testing.T) {
		schema, err := parser.ParseUpdateOperation([]byte(""))
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})
	t.Run("validate update request error", func(t *testing.T) {
		req, err := getDefaultUpdateRequest()
		require.NoError(t, err)
		req.DidSuffix = ""

		payload, err := json.Marshal(req)
		require.NoError(t, err)

		schema, err := parser.ParseUpdateOperation(payload)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "missing did suffix")
	})
	t.Run("invalid next update commitment hash", func(t *testing.T) {
		delta, err := getUpdateDelta()
		require.NoError(t, err)
		delta.UpdateCommitment = ""

		req, err := getUpdateRequest(delta)
		require.NoError(t, err)
		payload, err := json.Marshal(req)
		require.NoError(t, err)

		schema, err := parser.ParseUpdateOperation(payload)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the required supported hash algorithm")
	})
	t.Run("invalid signed data", func(t *testing.T) {
		delta, err := getUpdateDelta()
		require.NoError(t, err)

		req, err := getUpdateRequest(delta)
		require.NoError(t, err)

		req.SignedData = "."
		payload, err := json.Marshal(req)
		require.NoError(t, err)

		schema, err := parser.ParseUpdateOperation(payload)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "invalid JWS compact format")
	})
	t.Run("parse signed data error - unmarshal failed", func(t *testing.T) {
		req, err := getDefaultUpdateRequest()
		require.NoError(t, err)

		compactJWS, err := signutil.SignPayload([]byte("payload"), NewMockSigner())
		require.NoError(t, err)

		req.SignedData = compactJWS
		request, err := json.Marshal(req)
		require.NoError(t, err)

		op, err := parser.ParseUpdateOperation(request)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for update")
		require.Nil(t, op)
	})
}

func TestParseSignedDataForUpdate(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
		SignatureAlgorithms:          []string{"alg"},
		KeyAlgorithms:                []string{"crv"},
	}

	parser := NewParser(p)

	t.Run("success", func(t *testing.T) {
		req, err := getDefaultUpdateRequest()
		require.NoError(t, err)

		schema, err := parser.ParseSignedDataForUpdate(req.SignedData)
		require.NoError(t, err)
		require.NotNil(t, schema)
	})
	t.Run("invalid JWS compact format", func(t *testing.T) {
		schema, err := parser.ParseSignedDataForUpdate("invalid")
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "invalid JWS compact format")
	})
	t.Run("hash not computed with latest algorithm", func(t *testing.T) {
		signedModel := model.UpdateSignedDataModel{
			DeltaHash: "hash",
			UpdateKey: testJWK,
		}

		payload, err := json.Marshal(signedModel)
		require.NoError(t, err)

		compactJWS, err := signutil.SignPayload(payload, NewMockSigner())

		schema, err := parser.ParseSignedDataForUpdate(compactJWS)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "delta hash is not computed with the required hash algorithm: 18")
	})
	t.Run("payload not JSON object", func(t *testing.T) {
		compactJWS, err := signutil.SignPayload([]byte("test"), NewMockSigner())
		require.NoError(t, err)

		schema, err := parser.ParseSignedDataForUpdate(compactJWS)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func TestValidateUpdateDelta(t *testing.T) {
	t.Run("invalid next update commitment hash", func(t *testing.T) {
		p := protocol.Protocol{
			HashAlgorithmInMultiHashCode: sha2_256,
		}

		parser := NewParser(p)

		delta, err := getUpdateDelta()
		require.NoError(t, err)

		delta.UpdateCommitment = ""
		err = parser.validateDelta(delta)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the required supported hash algorithm")
	})
}

func TestValidateUpdateRequest(t *testing.T) {
	parser := NewParser(protocol.Protocol{})

	t.Run("success", func(t *testing.T) {
		update, err := getDefaultUpdateRequest()
		require.NoError(t, err)

		err = parser.validateUpdateRequest(update)
		require.NoError(t, err)
	})
	t.Run("missing signed data", func(t *testing.T) {
		update, err := getDefaultUpdateRequest()
		require.NoError(t, err)
		update.SignedData = ""

		err = parser.validateUpdateRequest(update)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signed data")
	})
	t.Run("missing did suffix", func(t *testing.T) {
		update, err := getDefaultUpdateRequest()
		require.NoError(t, err)
		update.DidSuffix = ""

		err = parser.validateUpdateRequest(update)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing did suffix")
	})
	t.Run("missing delta", func(t *testing.T) {
		update, err := getDefaultUpdateRequest()
		require.NoError(t, err)
		update.Delta = ""

		err = parser.validateUpdateRequest(update)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing delta")
	})
}

func getUpdateRequest(delta *model.DeltaModel) (*model.UpdateRequest, error) {
	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	updateKey := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
	}

	signedModel := model.UpdateSignedDataModel{
		DeltaHash: computeMultihash(deltaBytes),
		UpdateKey: updateKey}

	compactJWS, err := signutil.SignModel(signedModel, NewMockSigner())
	if err != nil {
		return nil, err
	}

	return &model.UpdateRequest{
		DidSuffix:  "suffix",
		SignedData: compactJWS,
		Operation:  model.OperationTypeUpdate,
		Delta:      docutil.EncodeToString(deltaBytes),
	}, nil
}

func getDefaultUpdateRequest() (*model.UpdateRequest, error) {
	delta, err := getUpdateDelta()
	if err != nil {
		return nil, err
	}
	return getUpdateRequest(delta)
}

func getUpdateRequestBytes() ([]byte, error) {
	req, err := getDefaultUpdateRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}

func getUpdateDelta() (*model.DeltaModel, error) {
	jsonPatch, err := patch.NewJSONPatch(getTestPatch())
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		UpdateCommitment: computeMultihash([]byte("updateReveal")),
		Patches:          []patch.Patch{jsonPatch},
	}, nil
}

func getTestPatch() string {
	return `[{"op": "replace", "path": "/name", "value": "Jane"}]`
}

var testJWK = &jws.JWK{
	Crv: "crv",
	Kty: "kty",
	X:   "x",
}
