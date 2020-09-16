/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package applier

import (
	"crypto"
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
)

var logger = log.New("sidetree-core-processor")

type Applier struct {
	protocol.Protocol
	protocol.OperationParser
	protocol.DocumentComposer
}

func NewApplier(p protocol.Protocol, parser protocol.OperationParser, dc protocol.DocumentComposer) *Applier {
	return &Applier{
		Protocol:         p,
		OperationParser:  parser,
		DocumentComposer: dc,
	}
}

func (s *Applier) ApplyCreateOperation(op *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	logger.Debugf("Applying create operation: %+v", op)

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	suffixData, err := s.ParseSuffixData(op.SuffixData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse suffix data: %s", err.Error())
	}

	// verify actual delta hash matches expected delta hash
	err = docutil.IsValidHash(op.Delta, suffixData.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("create delta doesn't match suffix data delta hash: %s", err.Error())
	}

	delta, err := s.ParseDelta(op.Delta)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delta: %s", err.Error())
	}

	doc, err := s.ApplyPatches(make(document.Document), delta.Patches)
	if err != nil {
		return nil, err
	}

	return &protocol.ResolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   op.TransactionTime,
		LastOperationTransactionNumber: op.TransactionNumber,
		UpdateCommitment:               delta.UpdateCommitment,
		RecoveryCommitment:             suffixData.RecoveryCommitment,
	}, nil
}

func (s *Applier) ApplyUpdateOperation(op *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) { //nolint:dupl
	logger.Debugf("Applying update operation: %+v", op)

	if rm.Doc == nil {
		return nil, errors.New("update cannot be first operation")
	}

	signedDataModel, err := s.ParseSignedDataForUpdate(op.SignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model while applying update: %s", err.Error())
	}

	updateCommitment, err := commitment.Calculate(signedDataModel.UpdateKey, s.HashAlgorithmInMultiHashCode, crypto.Hash(s.HashAlgorithm))
	if err != nil {
		return nil, err
	}

	// verify that update commitments match
	if updateCommitment != rm.UpdateCommitment {
		return nil, fmt.Errorf("commitment generated from update key doesn't match update commitment: [%s][%s]", updateCommitment, rm.UpdateCommitment)
	}

	// verify the delta against the signed delta hash
	err = docutil.IsValidHash(op.Delta, signedDataModel.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("update delta doesn't match delta hash: %s", err.Error())
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.UpdateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	delta, err := s.ParseDelta(op.Delta)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delta: %s", err.Error())
	}

	doc, err := s.ApplyPatches(rm.Doc, delta.Patches)
	if err != nil {
		return nil, err
	}

	return &protocol.ResolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   op.TransactionTime,
		LastOperationTransactionNumber: op.TransactionNumber,
		UpdateCommitment:               delta.UpdateCommitment,
		RecoveryCommitment:             rm.RecoveryCommitment}, nil
}

func (s *Applier) ApplyDeactivateOperation(op *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	logger.Debugf("Applying deactivate operation: %+v", op)

	if rm.Doc == nil {
		return nil, errors.New("deactivate can only be applied to an existing document")
	}

	signedDataModel, err := s.ParseSignedDataForDeactivate(op.SignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data model while applying deactivate: %s", err.Error())
	}

	// verify signed did suffix against actual did suffix
	if op.UniqueSuffix != signedDataModel.DidSuffix {
		return nil, errors.New("did suffix doesn't match signed value")
	}

	recoveryCommitment, err := commitment.Calculate(signedDataModel.RecoveryKey, s.HashAlgorithmInMultiHashCode, crypto.Hash(s.HashAlgorithm))
	if err != nil {
		return nil, err
	}

	// verify that recovery commitments match
	if recoveryCommitment != rm.RecoveryCommitment {
		return nil, fmt.Errorf("commitment generated from recovery key doesn't match recovery commitment: [%s][%s]", recoveryCommitment, rm.RecoveryCommitment)
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	return &protocol.ResolutionModel{
		Doc:                            nil,
		LastOperationTransactionTime:   op.TransactionTime,
		LastOperationTransactionNumber: op.TransactionNumber,
		UpdateCommitment:               "",
		RecoveryCommitment:             ""}, nil
}

func (s *Applier) ApplyRecoverOperation(op *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) { //nolint:dupl
	logger.Debugf("Applying recover operation: %+v", op)

	if rm.Doc == nil {
		return nil, errors.New("recover can only be applied to an existing document")
	}

	signedDataModel, err := s.ParseSignedDataForRecover(op.SignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data model while applying recover: %s", err.Error())
	}

	recoveryCommitment, err := commitment.Calculate(signedDataModel.RecoveryKey, s.HashAlgorithmInMultiHashCode, crypto.Hash(s.HashAlgorithm))
	if err != nil {
		return nil, err
	}

	// verify that recovery commitments match
	if recoveryCommitment != rm.RecoveryCommitment {
		return nil, fmt.Errorf("commitment generated from recovery key doesn't match recovery commitment: [%s][%s]", recoveryCommitment, rm.RecoveryCommitment)
	}

	// verify the delta against the signed delta hash
	err = docutil.IsValidHash(op.Delta, signedDataModel.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("recover delta doesn't match delta hash: %s", err.Error())
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	delta, err := s.ParseDelta(op.Delta)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delta: %s", err.Error())
	}

	doc, err := s.ApplyPatches(make(document.Document), delta.Patches)
	if err != nil {
		return nil, err
	}

	return &protocol.ResolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   op.TransactionTime,
		LastOperationTransactionNumber: op.TransactionNumber,
		UpdateCommitment:               delta.UpdateCommitment,
		RecoveryCommitment:             signedDataModel.RecoveryCommitment}, nil
}
