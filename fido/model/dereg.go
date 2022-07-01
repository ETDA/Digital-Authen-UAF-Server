package model

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSON implements json.Unmarshaler.
func (j *DeregistrationRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["authenticators"]; !ok || v == nil {
		return fmt.Errorf("field authenticators: required")
	}
	if v, ok := raw["header"]; !ok || v == nil {
		return fmt.Errorf("field header: required")
	}
	type Plain DeregistrationRequest
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = DeregistrationRequest(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *DeregistrationAuthenticator) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["aaid"]; !ok || v == nil {
		return fmt.Errorf("field aaid: required")
	}
	if v, ok := raw["keyID"]; !ok || v == nil {
		return fmt.Errorf("field keyID: required")
	}
	type Plain DeregistrationAuthenticator
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = DeregistrationAuthenticator(plain)
	return nil
}

type DeregistrationAuthenticator struct {
	// Aaid corresponds to the JSON schema field "aaid".
	Aaid string `json:"aaid"`

	// KeyID corresponds to the JSON schema field "keyID".
	KeyID string `json:"keyID"`
}

type DeregistrationRequest struct {
	// Authenticators corresponds to the JSON schema field "authenticators".
	Authenticators []DeregistrationAuthenticator `json:"authenticators"`

	// Header corresponds to the JSON schema field "header".
	Header OperationHeader `json:"header"`
}
