package model

import (
	"encoding/json"
	"fmt"

	"github.com/etda-uaf/uaf-server/fido/status"
)

type GetUAFRequest struct {
	// Context corresponds to the JSON schema field "context".
	Context *string `json:"context,omitempty"`

	// Op corresponds to the JSON schema field "op".
	Op Operation `json:"op,omitempty"`

	// PreviousRequest corresponds to the JSON schema field "previousRequest".
	PreviousRequest *string `json:"previousRequest,omitempty"`

	QrCodeToken *string `json:"qrCodeToken,omitempty"`

	Endpoint_url *string `json:"endpoint_url,omitempty"`
}

type ServerResponse struct {
	// AdditionalTokens corresponds to the JSON schema field "additionalTokens".
	AdditionalTokens []Token `json:"additionalTokens,omitempty"`

	// Description corresponds to the JSON schema field "description".
	Description *string `json:"description,omitempty"`

	// Location corresponds to the JSON schema field "location".
	Location *string `json:"location,omitempty"`

	// NewUAFRequest corresponds to the JSON schema field "newUAFRequest".
	NewUAFRequest *string `json:"newUAFRequest,omitempty"`

	// PostData corresponds to the JSON schema field "postData".
	PostData *string `json:"postData,omitempty"`

	// StatusCode corresponds to the JSON schema field "statusCode".
	StatusCode int `json:"statusCode"`
}

type ReturnUAFRequest struct {
	// DX addition
	Details *string `json:"details,omitempty"`

	// LifetimeMillis corresponds to the JSON schema field "lifetimeMillis".
	LifetimeMillis *int `json:"lifetimeMillis,omitempty"`

	// Op corresponds to the JSON schema field "op".
	Op ReturnUAFRequestOp `json:"op,omitempty"`

	// StatusCode corresponds to the JSON schema field "statusCode".
	StatusCode int `json:"statusCode"`

	// UafRequest corresponds to the JSON schema field "uafRequest".
	UafRequest *string `json:"uafRequest,omitempty"`

	// error message
	Err string `json:"err,omitempty"`
}

type UAFMessage struct {
	// AdditionalData corresponds to the JSON schema field "additionalData".
	AdditionalData interface{} `json:"additionalData,omitempty"`

	// UafProtocolMessage corresponds to the JSON schema field "uafProtocolMessage".
	UafProtocolMessage string `json:"uafProtocolMessage"`
}

type SendUAFResponse struct {
	// Context corresponds to the JSON schema field "context".
	Context *string `json:"context,omitempty"`

	// UafResponse corresponds to the JSON schema field "uafResponse".
	UafResponse *string `json:"uafResponse"`
}

type ReturnUAFRequestOp interface{}

// Response from client
type OperationResponse struct {
	Header OperationHeader `json:"header"`
}

type OperationHeader struct {
	// AppID corresponds to the JSON schema field "appID".
	AppID string `json:"appID"`

	// Exts corresponds to the JSON schema field "exts".
	Exts []interface{} `json:"exts,omitempty"`

	// Op corresponds to the JSON schema field "op".
	Op Operation `json:"op"`

	// ServerData corresponds to the JSON schema field "serverData".
	ServerData *string `json:"serverData,omitempty"`

	// Upv corresponds to the JSON schema field "upv".
	Upv Version `json:"upv"`
}

type OperationHeaderOp Operation

func UAFResponse(op Operation, stat status.Status, response []interface{}, err error) ReturnUAFRequest {

	var uafRequest ReturnUAFRequest
	uafRequest.StatusCode = int(stat)
	if stat != status.Ok {
		if err != nil {
			uafRequest.Err = err.Error()
		}
		return uafRequest
	}

	uafRequest.Op = op

	// convert response to array
	req, _ := json.Marshal(response)
	respStr := string(req)
	uafRequest.UafRequest = &respStr
	return uafRequest
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *UAFMessage) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["uafProtocolMessage"]; !ok || v == nil {
		return fmt.Errorf("field uafProtocolMessage: required")
	}
	type Plain UAFMessage
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = UAFMessage(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *SendUAFResponse) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["uafResponse"]; !ok || v == nil {
		return fmt.Errorf("field uafResponse: required")
	}
	type Plain SendUAFResponse
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = SendUAFResponse(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *ReturnUAFRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["statusCode"]; !ok || v == nil {
		return fmt.Errorf("field statusCode: required")
	}
	type Plain ReturnUAFRequest
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = ReturnUAFRequest(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *OperationHeader) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["appID"]; !ok || v == nil {
		return fmt.Errorf("field appID: required")
	}
	if v, ok := raw["op"]; !ok || v == nil {
		return fmt.Errorf("field op: required")
	}
	if v, ok := raw["upv"]; !ok || v == nil {
		return fmt.Errorf("field upv: required")
	}
	type Plain OperationHeader
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = OperationHeader(plain)
	return nil
}
