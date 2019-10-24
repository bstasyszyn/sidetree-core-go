/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"encoding/json"
)

// OperationType is the operation type
// swagger:model OperationType
type OperationType string

const (
	// OperationTypeCreate captures enum value "create"
	OperationTypeCreate OperationType = "create"

	// OperationTypeUpdate captures enum value "update"
	OperationTypeUpdate OperationType = "update"
)

// for schema
var operationTypeEnum []interface{}

func init() {
	var res []OperationType
	if err := json.Unmarshal([]byte(`["create","update"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		operationTypeEnum = append(operationTypeEnum, v)
	}
}
