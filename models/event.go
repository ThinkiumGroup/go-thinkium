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
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

type (
	EventType uint16

	Sourcer interface {
		Source() common.NodeID
		// SourcePAS() *PubAndSig
	}

	Equaler interface {
		Equals(interface{}) bool
	}
)

func (t EventType) String() string {
	if v, ok := eventDict.GetName(t); ok {
		return v
	}
	return "EventType" + strconv.Itoa(int(t))
}

func (t EventType) Bytes() (b []byte) {
	b = make([]byte, EventTypeLength)
	b[0] = byte(t >> 8)
	b[1] = byte(t)
	return b
}

func ToEventType(b []byte) EventType {
	var et EventType
	if len(b) > 0 {
		et = EventType(uint16(b[0]) << 8)
		if len(b) > 1 {
			et += EventType(b[1])
		}
	}
	return et
}

const (
	// basic event types, the number of these types should not exceed 255, otherwise it will
	// confilict with consensus event
	TextEvent EventType = 0x0000 + iota
	ToOneEvent
	JustHashEvent
	WantDetailEvent
	TxEvent
	ReportBlockEvent
	ReportCommEvent
	BlockEvent
	StartEvent
	LastBlockEvent
	LastReportEvent
	SyncRequestEvent
	NeedCommitteeEvent
	RelayEvent
	StopEvent
	ShardDeltaEvent
	DeltaRequestEvent
	LastHeightEvent
	BlockRequestEvent
	SyncFinishEvent
	HistoryBlockEvent
	RewardRequestEvent
	RRProofsRequestEvent
	RRProofsMessageEvent
	ReportNodeInfoEvent
	LastCommEvent
	StartCommEvent
	StartConsEvent
	PreelectionStartEvent
	PreelectionConnectEvent
	PreelectionSyncEvent
	PreelectionExamineEvent
	PreelectionExitEvent
	MissingChainEvent
	SevereErrEvent
	DeltasPackEvent
	NodeStateEvent

	UNSETEVENT EventType = 0xFFFF // This is the last EventType, ADD A NEW EventType BEFORE THIS PLEASE.
)

var (
	ErrUnrecognized = errors.New("unrecognized")

	eventTypeMap = map[EventType]reflect.Type{
		TextEvent:               reflect.TypeOf((*TextEMessage)(nil)).Elem(),
		ToOneEvent:              reflect.TypeOf((*ToOneEMessage)(nil)).Elem(),
		JustHashEvent:           reflect.TypeOf((*JustHashEMessage)(nil)).Elem(),
		WantDetailEvent:         reflect.TypeOf((*WantDetailEMessage)(nil)).Elem(),
		TxEvent:                 reflect.TypeOf((*Transaction)(nil)).Elem(),
		ReportBlockEvent:        reflect.TypeOf((*BlockReport)(nil)).Elem(),
		ReportCommEvent:         reflect.TypeOf((*CommReport)(nil)).Elem(),
		BlockEvent:              reflect.TypeOf((*BlockEMessage)(nil)).Elem(),
		StartEvent:              reflect.TypeOf((*StartEMessage)(nil)).Elem(),
		LastBlockEvent:          reflect.TypeOf((*LastBlockMessage)(nil)).Elem(),
		LastReportEvent:         reflect.TypeOf((*LastReportMessage)(nil)).Elem(),
		SyncRequestEvent:        reflect.TypeOf((*SyncRequest)(nil)).Elem(),
		SyncFinishEvent:         reflect.TypeOf((*SyncFinish)(nil)).Elem(),
		NeedCommitteeEvent:      reflect.TypeOf((*ElectMessage)(nil)).Elem(),
		RelayEvent:              reflect.TypeOf((*RelayEventMsg)(nil)).Elem(),
		StopEvent:               reflect.TypeOf((*StopEMessage)(nil)).Elem(),
		ShardDeltaEvent:         reflect.TypeOf((*ShardDeltaMessage)(nil)).Elem(),
		DeltaRequestEvent:       reflect.TypeOf((*DeltaRequestMessage)(nil)).Elem(),
		LastHeightEvent:         reflect.TypeOf((*LastHeightMessage)(nil)).Elem(),
		BlockRequestEvent:       reflect.TypeOf((*BlockRequest)(nil)).Elem(),
		HistoryBlockEvent:       reflect.TypeOf((*HistoryBlock)(nil)).Elem(),
		RewardRequestEvent:      reflect.TypeOf((*RewardRequest)(nil)).Elem(),
		RRProofsRequestEvent:    reflect.TypeOf((*RRProofsRequest)(nil)).Elem(),
		RRProofsMessageEvent:    reflect.TypeOf((*RRProofsMessage)(nil)).Elem(),
		ReportNodeInfoEvent:     reflect.TypeOf((*ReportNodeInfoEMessage)(nil)).Elem(),
		LastCommEvent:           reflect.TypeOf((*LastCommEMessage)(nil)).Elem(),
		StartCommEvent:          reflect.TypeOf((*StartCommEMessage)(nil)).Elem(),
		StartConsEvent:          reflect.TypeOf((*StartConsEMessage)(nil)).Elem(),
		PreelectionStartEvent:   reflect.TypeOf((*PreelectionStart)(nil)).Elem(),
		PreelectionConnectEvent: reflect.TypeOf((*PreelectionConnect)(nil)).Elem(),
		PreelectionSyncEvent:    reflect.TypeOf((*PreelectionSync)(nil)).Elem(),
		PreelectionExamineEvent: reflect.TypeOf((*PreelectionExamine)(nil)).Elem(),
		PreelectionExitEvent:    reflect.TypeOf((*PreelectionExit)(nil)).Elem(),
		MissingChainEvent:       reflect.TypeOf((*MissingChainEventMsg)(nil)).Elem(),
		SevereErrEvent:          reflect.TypeOf((*SevereErrorEventMsg)(nil)).Elem(),
		DeltasPackEvent:         reflect.TypeOf((*DeltasPack)(nil)).Elem(),
		NodeStateEvent:          reflect.TypeOf((*NodeState)(nil)).Elem(),
	}

	// reversedEventTypeMap = reverseEventTypeMap(eventTypeMap)
	eventTypeNames = map[EventType]string{
		TextEvent:               "TextEvent",
		ToOneEvent:              "ToOneEvent",
		JustHashEvent:           "JustHashEvent",
		WantDetailEvent:         "WantDetailEvent",
		TxEvent:                 "TxEvent",
		ReportBlockEvent:        "ReportBlockEvent",
		ReportCommEvent:         "ReportCommEvent",
		BlockEvent:              "BlockEvent",
		StartEvent:              "Start",
		LastBlockEvent:          "LastBlock",
		LastReportEvent:         "LastReport",
		SyncRequestEvent:        "SyncRequest",
		NeedCommitteeEvent:      "NeedCommittee",
		RelayEvent:              "Ctrl-RelayEvent",
		StopEvent:               "StopEvent",
		ShardDeltaEvent:         "ShardDeltaEvent",
		DeltaRequestEvent:       "DeltaRequestEvent",
		LastHeightEvent:         "LastHeightEvent",
		BlockRequestEvent:       "BlockRequestEvent",
		UNSETEVENT:              "UNSET",
		SyncFinishEvent:         "SyncFinishEvent",
		HistoryBlockEvent:       "HistoryBlockEvent",
		RewardRequestEvent:      "RewardRequestEvent",
		RRProofsRequestEvent:    "RRProofsRequestEvent",
		RRProofsMessageEvent:    "RRProofsMessageEvent",
		ReportNodeInfoEvent:     "ReportNodeInfoEvent",
		LastCommEvent:           "LastCommEvent",
		StartCommEvent:          "StartCommEvent",
		StartConsEvent:          "StartConsensus",
		PreelectionStartEvent:   "PEStart",
		PreelectionConnectEvent: "PEConnect",
		PreelectionSyncEvent:    "PESync",
		PreelectionExamineEvent: "PEExamine",
		PreelectionExitEvent:    "PEExit",
		MissingChainEvent:       "Ctrl-MissingChain",
		SevereErrEvent:          "Ctrl-SevereErr",
		DeltasPackEvent:         "DeltasPack",
		NodeStateEvent:          "NodeStateEvent",
	}
)

func init() {
	RegisterEvents(eventTypeMap, eventTypeNames)
}

// func reverseEventTypeMap(m map[EventType]reflect.Type) map[reflect.Type]EventType {
// 	ret := make(map[reflect.Type]EventType, len(m))
// 	for k, v := range m {
// 		ret[v] = k
// 	}
// 	return ret
// }

func FindObjectTypeByEventType(eventType EventType) (t reflect.Type, ok bool) {
	// t, ok = eventTypeMap[eventType]
	return eventDict.GetObjectType(eventType)
}

func FindEventTypeByObjectType(typ reflect.Type) (t EventType, ok bool) {
	switch typ.Kind() {
	case reflect.Ptr:
		return eventDict.GetEventType(typ.Elem())
		// t, ok = reversedEventTypeMap[typ.Elem()]
	default:
		return eventDict.GetEventType(typ)
		// t, ok = reversedEventTypeMap[typ]
	}
	// return
}

func MarshalEvent(m interface{}) (EventType, []byte, error) {
	if m == nil {
		return 0, nil, common.ErrNil
	}
	typ := reflect.TypeOf(m)
	eventType, ok := FindEventTypeByObjectType(typ)
	if !ok {
		return 0, nil, NewUnknownEventTypeError(typ)
	}

	body, err := rtl.Marshal(m)
	if err != nil {
		return eventType, nil, common.NewDvppError("marshal message error:", err)
	}

	return eventType, body, nil
}

func UnmarshalEvent(eventType EventType, body []byte) (interface{}, error) {
	if len(body) == 0 {
		return nil, nil
	}
	msgType, exist := FindObjectTypeByEventType(eventType)
	if !exist {
		return nil, fmt.Errorf("object type not found with events.EventType(%s)", eventType)
	}

	msg := reflect.New(msgType)
	err := rtl.Unmarshal(body, msg.Interface())
	if err != nil {
		return nil, common.NewDvppError("unmarshal message error:", err)
	}

	return msg.Interface(), nil
}

func NewUnknownEventTypeError(typ reflect.Type) error {
	return common.NewFormatError("event type not found by object type(%s)", typ.String())
}
