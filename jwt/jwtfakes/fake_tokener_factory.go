// Code generated by counterfeiter. DO NOT EDIT.
package jwtfakes

import (
	"sync"

	"github.com/smartatransit/api-gateway/jwt"
)

type FakeTokenerFactory struct {
	Stub        func(string, string) jwt.Tokener
	mutex       sync.RWMutex
	argsForCall []struct {
		arg1 string
		arg2 string
	}
	returns struct {
		result1 jwt.Tokener
	}
	returnsOnCall map[int]struct {
		result1 jwt.Tokener
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeTokenerFactory) Spy(arg1 string, arg2 string) jwt.Tokener {
	fake.mutex.Lock()
	ret, specificReturn := fake.returnsOnCall[len(fake.argsForCall)]
	fake.argsForCall = append(fake.argsForCall, struct {
		arg1 string
		arg2 string
	}{arg1, arg2})
	fake.recordInvocation("TokenerFactory", []interface{}{arg1, arg2})
	fake.mutex.Unlock()
	if fake.Stub != nil {
		return fake.Stub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.returns.result1
}

func (fake *FakeTokenerFactory) CallCount() int {
	fake.mutex.RLock()
	defer fake.mutex.RUnlock()
	return len(fake.argsForCall)
}

func (fake *FakeTokenerFactory) Calls(stub func(string, string) jwt.Tokener) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.Stub = stub
}

func (fake *FakeTokenerFactory) ArgsForCall(i int) (string, string) {
	fake.mutex.RLock()
	defer fake.mutex.RUnlock()
	return fake.argsForCall[i].arg1, fake.argsForCall[i].arg2
}

func (fake *FakeTokenerFactory) Returns(result1 jwt.Tokener) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.Stub = nil
	fake.returns = struct {
		result1 jwt.Tokener
	}{result1}
}

func (fake *FakeTokenerFactory) ReturnsOnCall(i int, result1 jwt.Tokener) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.Stub = nil
	if fake.returnsOnCall == nil {
		fake.returnsOnCall = make(map[int]struct {
			result1 jwt.Tokener
		})
	}
	fake.returnsOnCall[i] = struct {
		result1 jwt.Tokener
	}{result1}
}

func (fake *FakeTokenerFactory) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.mutex.RLock()
	defer fake.mutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeTokenerFactory) recordInvocation(key string, args []interface{}) {
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

var _ jwt.TokenerFactory = new(FakeTokenerFactory).Spy