// Copyright 2020 Thinkium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

import (
	"reflect"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

type (
	funcSet struct {
		m map[reflect.Value]struct{} // de-duplication of functions
		s []reflect.Value            // list of functions
		l sync.RWMutex
	}

	eventOperations struct {
		opMap map[OperatorType]map[EventType]*funcSet
		lock  sync.RWMutex
	}
)

var (
	EventProcs = newEventOperations()
)

func newFuncSet() *funcSet {
	return &funcSet{
		m: make(map[reflect.Value]struct{}),
		s: make([]reflect.Value, 0),
	}
}

func (s *funcSet) Add(fn reflect.Value) {
	s.l.Lock()
	defer s.l.Unlock()

	_, exist := s.m[fn]
	if exist {
		// log.Debug("duplcate found", fn)
		return
	}
	s.m[fn] = common.EmptyPlaceHolder
	s.s = append(s.s, fn)
}

func (s funcSet) List() []reflect.Value {
	s.l.RLock()
	defer s.l.RUnlock()
	return s.s
}

func newEventOperations() *eventOperations {
	return &eventOperations{
		opMap: make(map[OperatorType]map[EventType]*funcSet),
	}
}

func (p *eventOperations) Register(operator Operator) {
	if operator.Operations == nil {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()

	omap, ok := p.opMap[operator.Type]
	// if ok {
	// 	log.Warnf("Operator[%s] operations has already been initialed", operator.Type)
	// 	return
	// }
	if !ok || omap == nil {
		omap = make(map[EventType]*funcSet)
		p.opMap[operator.Type] = omap
	}

	for _, fn := range operator.Operations {
		typ := reflect.TypeOf(fn)
		if typ.Kind() != reflect.Func {
			log.Errorf("%v is not an function", fn)
			continue
		}

		paramLen := typ.NumIn()
		if paramLen != 2 {
			log.Error("parameter number is not 2 but", paramLen)
			continue
		}
		paramType1 := typ.In(0)
		if paramType1 != TypeOfContextPtr {
			log.Errorf("1st parameter must be a controller.Context (%s)", paramType1)
			continue
		}
		paramType2 := typ.In(1)
		if paramType2.Kind() != reflect.Ptr {
			log.Errorf("2nd parameter must be a pointer")
			continue
		}
		eventType, ok := FindEventTypeByObjectType(paramType2.Elem())
		if !ok {
			log.Errorf("2nd parameter (%s) type is not a legal events", paramType2)
			continue
		}

		fns, ok := omap[eventType]
		if !ok {
			fns = newFuncSet()
			omap[eventType] = fns
		}
		rv := reflect.ValueOf(fn)
		fns.Add(rv)
		log.WithField("OPERATOR", operator.Type).Infof("add one operation to %s", eventType)
	}
}

func (p *eventOperations) ListFuncs(eventType EventType, opTypes ...OperatorType) []reflect.Value {
	if len(opTypes) == 0 {
		return nil
	}
	p.lock.RLock()
	defer p.lock.RUnlock()
	if len(opTypes) == 1 {
		omap, ok := p.opMap[opTypes[0]]
		if !ok {
			panic(opTypes[0].String() + " not registerred")
		}

		fns, ok := omap[eventType]
		if !ok || fns == nil || len(fns.s) == 0 {
			return nil
		}
		return fns.List()
	}

	funcs := newFuncSet()
	// de-duplicate
	for _, opType := range opTypes {
		omap, ok := p.opMap[opType]
		if !ok {
			panic(opType.String() + " not registerred")
		}

		fns, ok := omap[eventType]
		if !ok || fns == nil || len(fns.s) == 0 {
			continue
		}

		for _, fn := range fns.s {
			funcs.Add(fn)
		}
	}
	if len(funcs.s) > 0 {
		return funcs.List()
	}
	return nil
}

func RegisterOperator(operator Operator) {
	EventProcs.Register(operator)
}

func ListOperatorFuncs(eventType EventType, opTypes ...OperatorType) []reflect.Value {
	return EventProcs.ListFuncs(eventType, opTypes...)
}
