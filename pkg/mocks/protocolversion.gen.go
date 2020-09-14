// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

type ProtocolVersion struct {
	ProtocolStub        func() protocol.Protocol
	protocolMutex       sync.RWMutex
	protocolArgsForCall []struct{}
	protocolReturns     struct {
		result1 protocol.Protocol
	}
	protocolReturnsOnCall map[int]struct {
		result1 protocol.Protocol
	}
	TransactionProcessorStub        func() protocol.TxnProcessor
	transactionProcessorMutex       sync.RWMutex
	transactionProcessorArgsForCall []struct{}
	transactionProcessorReturns     struct {
		result1 protocol.TxnProcessor
	}
	transactionProcessorReturnsOnCall map[int]struct {
		result1 protocol.TxnProcessor
	}
	OperationParserStub        func() protocol.OperationParser
	operationParserMutex       sync.RWMutex
	operationParserArgsForCall []struct{}
	operationParserReturns     struct {
		result1 protocol.OperationParser
	}
	operationParserReturnsOnCall map[int]struct {
		result1 protocol.OperationParser
	}
	OperationApplierStub        func() protocol.OperationApplier
	operationApplierMutex       sync.RWMutex
	operationApplierArgsForCall []struct{}
	operationApplierReturns     struct {
		result1 protocol.OperationApplier
	}
	operationApplierReturnsOnCall map[int]struct {
		result1 protocol.OperationApplier
	}
	DocumentComposerStub        func() protocol.DocumentComposer
	documentComposerMutex       sync.RWMutex
	documentComposerArgsForCall []struct{}
	documentComposerReturns     struct {
		result1 protocol.DocumentComposer
	}
	documentComposerReturnsOnCall map[int]struct {
		result1 protocol.DocumentComposer
	}
	TransactionHandlerStub        func() protocol.TxnHandler
	transactionHandlerMutex       sync.RWMutex
	transactionHandlerArgsForCall []struct{}
	transactionHandlerReturns     struct {
		result1 protocol.TxnHandler
	}
	transactionHandlerReturnsOnCall map[int]struct {
		result1 protocol.TxnHandler
	}
	OperationProtocolProviderStub        func() protocol.OperationProtocolProvider
	operationProtocolProviderMutex       sync.RWMutex
	operationProtocolProviderArgsForCall []struct{}
	operationProtocolProviderReturns     struct {
		result1 protocol.OperationProtocolProvider
	}
	operationProtocolProviderReturnsOnCall map[int]struct {
		result1 protocol.OperationProtocolProvider
	}
	DocumentValidatorStub        func() protocol.DocumentValidator
	documentValidatorMutex       sync.RWMutex
	documentValidatorArgsForCall []struct{}
	documentValidatorReturns     struct {
		result1 protocol.DocumentValidator
	}
	documentValidatorReturnsOnCall map[int]struct {
		result1 protocol.DocumentValidator
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ProtocolVersion) Protocol() protocol.Protocol {
	fake.protocolMutex.Lock()
	ret, specificReturn := fake.protocolReturnsOnCall[len(fake.protocolArgsForCall)]
	fake.protocolArgsForCall = append(fake.protocolArgsForCall, struct{}{})
	fake.recordInvocation("Protocol", []interface{}{})
	fake.protocolMutex.Unlock()
	if fake.ProtocolStub != nil {
		return fake.ProtocolStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.protocolReturns.result1
}

func (fake *ProtocolVersion) ProtocolCallCount() int {
	fake.protocolMutex.RLock()
	defer fake.protocolMutex.RUnlock()
	return len(fake.protocolArgsForCall)
}

func (fake *ProtocolVersion) ProtocolReturns(result1 protocol.Protocol) {
	fake.ProtocolStub = nil
	fake.protocolReturns = struct {
		result1 protocol.Protocol
	}{result1}
}

func (fake *ProtocolVersion) ProtocolReturnsOnCall(i int, result1 protocol.Protocol) {
	fake.ProtocolStub = nil
	if fake.protocolReturnsOnCall == nil {
		fake.protocolReturnsOnCall = make(map[int]struct {
			result1 protocol.Protocol
		})
	}
	fake.protocolReturnsOnCall[i] = struct {
		result1 protocol.Protocol
	}{result1}
}

func (fake *ProtocolVersion) TransactionProcessor() protocol.TxnProcessor {
	fake.transactionProcessorMutex.Lock()
	ret, specificReturn := fake.transactionProcessorReturnsOnCall[len(fake.transactionProcessorArgsForCall)]
	fake.transactionProcessorArgsForCall = append(fake.transactionProcessorArgsForCall, struct{}{})
	fake.recordInvocation("TransactionProcessor", []interface{}{})
	fake.transactionProcessorMutex.Unlock()
	if fake.TransactionProcessorStub != nil {
		return fake.TransactionProcessorStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.transactionProcessorReturns.result1
}

func (fake *ProtocolVersion) TransactionProcessorCallCount() int {
	fake.transactionProcessorMutex.RLock()
	defer fake.transactionProcessorMutex.RUnlock()
	return len(fake.transactionProcessorArgsForCall)
}

func (fake *ProtocolVersion) TransactionProcessorReturns(result1 protocol.TxnProcessor) {
	fake.TransactionProcessorStub = nil
	fake.transactionProcessorReturns = struct {
		result1 protocol.TxnProcessor
	}{result1}
}

func (fake *ProtocolVersion) TransactionProcessorReturnsOnCall(i int, result1 protocol.TxnProcessor) {
	fake.TransactionProcessorStub = nil
	if fake.transactionProcessorReturnsOnCall == nil {
		fake.transactionProcessorReturnsOnCall = make(map[int]struct {
			result1 protocol.TxnProcessor
		})
	}
	fake.transactionProcessorReturnsOnCall[i] = struct {
		result1 protocol.TxnProcessor
	}{result1}
}

func (fake *ProtocolVersion) OperationParser() protocol.OperationParser {
	fake.operationParserMutex.Lock()
	ret, specificReturn := fake.operationParserReturnsOnCall[len(fake.operationParserArgsForCall)]
	fake.operationParserArgsForCall = append(fake.operationParserArgsForCall, struct{}{})
	fake.recordInvocation("OperationParser", []interface{}{})
	fake.operationParserMutex.Unlock()
	if fake.OperationParserStub != nil {
		return fake.OperationParserStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.operationParserReturns.result1
}

func (fake *ProtocolVersion) OperationParserCallCount() int {
	fake.operationParserMutex.RLock()
	defer fake.operationParserMutex.RUnlock()
	return len(fake.operationParserArgsForCall)
}

func (fake *ProtocolVersion) OperationParserReturns(result1 protocol.OperationParser) {
	fake.OperationParserStub = nil
	fake.operationParserReturns = struct {
		result1 protocol.OperationParser
	}{result1}
}

func (fake *ProtocolVersion) OperationParserReturnsOnCall(i int, result1 protocol.OperationParser) {
	fake.OperationParserStub = nil
	if fake.operationParserReturnsOnCall == nil {
		fake.operationParserReturnsOnCall = make(map[int]struct {
			result1 protocol.OperationParser
		})
	}
	fake.operationParserReturnsOnCall[i] = struct {
		result1 protocol.OperationParser
	}{result1}
}

func (fake *ProtocolVersion) OperationApplier() protocol.OperationApplier {
	fake.operationApplierMutex.Lock()
	ret, specificReturn := fake.operationApplierReturnsOnCall[len(fake.operationApplierArgsForCall)]
	fake.operationApplierArgsForCall = append(fake.operationApplierArgsForCall, struct{}{})
	fake.recordInvocation("OperationApplier", []interface{}{})
	fake.operationApplierMutex.Unlock()
	if fake.OperationApplierStub != nil {
		return fake.OperationApplierStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.operationApplierReturns.result1
}

func (fake *ProtocolVersion) OperationApplierCallCount() int {
	fake.operationApplierMutex.RLock()
	defer fake.operationApplierMutex.RUnlock()
	return len(fake.operationApplierArgsForCall)
}

func (fake *ProtocolVersion) OperationApplierReturns(result1 protocol.OperationApplier) {
	fake.OperationApplierStub = nil
	fake.operationApplierReturns = struct {
		result1 protocol.OperationApplier
	}{result1}
}

func (fake *ProtocolVersion) OperationApplierReturnsOnCall(i int, result1 protocol.OperationApplier) {
	fake.OperationApplierStub = nil
	if fake.operationApplierReturnsOnCall == nil {
		fake.operationApplierReturnsOnCall = make(map[int]struct {
			result1 protocol.OperationApplier
		})
	}
	fake.operationApplierReturnsOnCall[i] = struct {
		result1 protocol.OperationApplier
	}{result1}
}

func (fake *ProtocolVersion) DocumentComposer() protocol.DocumentComposer {
	fake.documentComposerMutex.Lock()
	ret, specificReturn := fake.documentComposerReturnsOnCall[len(fake.documentComposerArgsForCall)]
	fake.documentComposerArgsForCall = append(fake.documentComposerArgsForCall, struct{}{})
	fake.recordInvocation("DocumentComposer", []interface{}{})
	fake.documentComposerMutex.Unlock()
	if fake.DocumentComposerStub != nil {
		return fake.DocumentComposerStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.documentComposerReturns.result1
}

func (fake *ProtocolVersion) DocumentComposerCallCount() int {
	fake.documentComposerMutex.RLock()
	defer fake.documentComposerMutex.RUnlock()
	return len(fake.documentComposerArgsForCall)
}

func (fake *ProtocolVersion) DocumentComposerReturns(result1 protocol.DocumentComposer) {
	fake.DocumentComposerStub = nil
	fake.documentComposerReturns = struct {
		result1 protocol.DocumentComposer
	}{result1}
}

func (fake *ProtocolVersion) DocumentComposerReturnsOnCall(i int, result1 protocol.DocumentComposer) {
	fake.DocumentComposerStub = nil
	if fake.documentComposerReturnsOnCall == nil {
		fake.documentComposerReturnsOnCall = make(map[int]struct {
			result1 protocol.DocumentComposer
		})
	}
	fake.documentComposerReturnsOnCall[i] = struct {
		result1 protocol.DocumentComposer
	}{result1}
}

func (fake *ProtocolVersion) TransactionHandler() protocol.TxnHandler {
	fake.transactionHandlerMutex.Lock()
	ret, specificReturn := fake.transactionHandlerReturnsOnCall[len(fake.transactionHandlerArgsForCall)]
	fake.transactionHandlerArgsForCall = append(fake.transactionHandlerArgsForCall, struct{}{})
	fake.recordInvocation("TransactionHandler", []interface{}{})
	fake.transactionHandlerMutex.Unlock()
	if fake.TransactionHandlerStub != nil {
		return fake.TransactionHandlerStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.transactionHandlerReturns.result1
}

func (fake *ProtocolVersion) TransactionHandlerCallCount() int {
	fake.transactionHandlerMutex.RLock()
	defer fake.transactionHandlerMutex.RUnlock()
	return len(fake.transactionHandlerArgsForCall)
}

func (fake *ProtocolVersion) TransactionHandlerReturns(result1 protocol.TxnHandler) {
	fake.TransactionHandlerStub = nil
	fake.transactionHandlerReturns = struct {
		result1 protocol.TxnHandler
	}{result1}
}

func (fake *ProtocolVersion) TransactionHandlerReturnsOnCall(i int, result1 protocol.TxnHandler) {
	fake.TransactionHandlerStub = nil
	if fake.transactionHandlerReturnsOnCall == nil {
		fake.transactionHandlerReturnsOnCall = make(map[int]struct {
			result1 protocol.TxnHandler
		})
	}
	fake.transactionHandlerReturnsOnCall[i] = struct {
		result1 protocol.TxnHandler
	}{result1}
}

func (fake *ProtocolVersion) OperationProtocolProvider() protocol.OperationProtocolProvider {
	fake.operationProtocolProviderMutex.Lock()
	ret, specificReturn := fake.operationProtocolProviderReturnsOnCall[len(fake.operationProtocolProviderArgsForCall)]
	fake.operationProtocolProviderArgsForCall = append(fake.operationProtocolProviderArgsForCall, struct{}{})
	fake.recordInvocation("OperationProtocolProvider", []interface{}{})
	fake.operationProtocolProviderMutex.Unlock()
	if fake.OperationProtocolProviderStub != nil {
		return fake.OperationProtocolProviderStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.operationProtocolProviderReturns.result1
}

func (fake *ProtocolVersion) OperationProtocolProviderCallCount() int {
	fake.operationProtocolProviderMutex.RLock()
	defer fake.operationProtocolProviderMutex.RUnlock()
	return len(fake.operationProtocolProviderArgsForCall)
}

func (fake *ProtocolVersion) OperationProtocolProviderReturns(result1 protocol.OperationProtocolProvider) {
	fake.OperationProtocolProviderStub = nil
	fake.operationProtocolProviderReturns = struct {
		result1 protocol.OperationProtocolProvider
	}{result1}
}

func (fake *ProtocolVersion) OperationProtocolProviderReturnsOnCall(i int, result1 protocol.OperationProtocolProvider) {
	fake.OperationProtocolProviderStub = nil
	if fake.operationProtocolProviderReturnsOnCall == nil {
		fake.operationProtocolProviderReturnsOnCall = make(map[int]struct {
			result1 protocol.OperationProtocolProvider
		})
	}
	fake.operationProtocolProviderReturnsOnCall[i] = struct {
		result1 protocol.OperationProtocolProvider
	}{result1}
}

func (fake *ProtocolVersion) DocumentValidator() protocol.DocumentValidator {
	fake.documentValidatorMutex.Lock()
	ret, specificReturn := fake.documentValidatorReturnsOnCall[len(fake.documentValidatorArgsForCall)]
	fake.documentValidatorArgsForCall = append(fake.documentValidatorArgsForCall, struct{}{})
	fake.recordInvocation("DocumentValidator", []interface{}{})
	fake.documentValidatorMutex.Unlock()
	if fake.DocumentValidatorStub != nil {
		return fake.DocumentValidatorStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.documentValidatorReturns.result1
}

func (fake *ProtocolVersion) DocumentValidatorCallCount() int {
	fake.documentValidatorMutex.RLock()
	defer fake.documentValidatorMutex.RUnlock()
	return len(fake.documentValidatorArgsForCall)
}

func (fake *ProtocolVersion) DocumentValidatorReturns(result1 protocol.DocumentValidator) {
	fake.DocumentValidatorStub = nil
	fake.documentValidatorReturns = struct {
		result1 protocol.DocumentValidator
	}{result1}
}

func (fake *ProtocolVersion) DocumentValidatorReturnsOnCall(i int, result1 protocol.DocumentValidator) {
	fake.DocumentValidatorStub = nil
	if fake.documentValidatorReturnsOnCall == nil {
		fake.documentValidatorReturnsOnCall = make(map[int]struct {
			result1 protocol.DocumentValidator
		})
	}
	fake.documentValidatorReturnsOnCall[i] = struct {
		result1 protocol.DocumentValidator
	}{result1}
}

func (fake *ProtocolVersion) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.protocolMutex.RLock()
	defer fake.protocolMutex.RUnlock()
	fake.transactionProcessorMutex.RLock()
	defer fake.transactionProcessorMutex.RUnlock()
	fake.operationParserMutex.RLock()
	defer fake.operationParserMutex.RUnlock()
	fake.operationApplierMutex.RLock()
	defer fake.operationApplierMutex.RUnlock()
	fake.documentComposerMutex.RLock()
	defer fake.documentComposerMutex.RUnlock()
	fake.transactionHandlerMutex.RLock()
	defer fake.transactionHandlerMutex.RUnlock()
	fake.operationProtocolProviderMutex.RLock()
	defer fake.operationProtocolProviderMutex.RUnlock()
	fake.documentValidatorMutex.RLock()
	defer fake.documentValidatorMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ProtocolVersion) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ protocol.Version = new(ProtocolVersion)
