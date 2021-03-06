// Code generated by counterfeiter. DO NOT EDIT.
package jwtfakes

import (
	"context"
	"sync"

	"github.com/smartatransit/api-gateway/jwt"
)

type FakeTokener struct {
	GetTokenStub        func(context.Context) (string, error)
	getTokenMutex       sync.RWMutex
	getTokenArgsForCall []struct {
		arg1 context.Context
	}
	getTokenReturns struct {
		result1 string
		result2 error
	}
	getTokenReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeTokener) GetToken(arg1 context.Context) (string, error) {
	fake.getTokenMutex.Lock()
	ret, specificReturn := fake.getTokenReturnsOnCall[len(fake.getTokenArgsForCall)]
	fake.getTokenArgsForCall = append(fake.getTokenArgsForCall, struct {
		arg1 context.Context
	}{arg1})
	fake.recordInvocation("GetToken", []interface{}{arg1})
	fake.getTokenMutex.Unlock()
	if fake.GetTokenStub != nil {
		return fake.GetTokenStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getTokenReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeTokener) GetTokenCallCount() int {
	fake.getTokenMutex.RLock()
	defer fake.getTokenMutex.RUnlock()
	return len(fake.getTokenArgsForCall)
}

func (fake *FakeTokener) GetTokenCalls(stub func(context.Context) (string, error)) {
	fake.getTokenMutex.Lock()
	defer fake.getTokenMutex.Unlock()
	fake.GetTokenStub = stub
}

func (fake *FakeTokener) GetTokenArgsForCall(i int) context.Context {
	fake.getTokenMutex.RLock()
	defer fake.getTokenMutex.RUnlock()
	argsForCall := fake.getTokenArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeTokener) GetTokenReturns(result1 string, result2 error) {
	fake.getTokenMutex.Lock()
	defer fake.getTokenMutex.Unlock()
	fake.GetTokenStub = nil
	fake.getTokenReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeTokener) GetTokenReturnsOnCall(i int, result1 string, result2 error) {
	fake.getTokenMutex.Lock()
	defer fake.getTokenMutex.Unlock()
	fake.GetTokenStub = nil
	if fake.getTokenReturnsOnCall == nil {
		fake.getTokenReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.getTokenReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeTokener) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getTokenMutex.RLock()
	defer fake.getTokenMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeTokener) recordInvocation(key string, args []interface{}) {
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

var _ jwt.Tokener = new(FakeTokener)
