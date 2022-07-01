package model

import (
	"encoding/json"
	"fmt"
	"reflect"
)

type RegistrationRequest struct {
	// Challenge corresponds to the JSON schema field "challenge".
	Challenge string `json:"challenge"`

	// Header corresponds to the JSON schema field "header".
	Header OperationHeader `json:"header"`

	// Policy corresponds to the JSON schema field "policy".
	Policy Policy `json:"policy"`

	// Username corresponds to the JSON schema field "username".
	Username string `json:"username"`
}

type RegistrationResponse struct {
	// Assertions corresponds to the JSON schema field "assertions".
	Assertions []AuthenticatorRegistrationAssertion `json:"assertions"`

	// FcParams corresponds to the JSON schema field "fcParams".
	FcParams string `json:"fcParams"`

	// Header corresponds to the JSON schema field "header".
	Header OperationHeader `json:"header"`
}

type AuthenticatorRegistrationAssertion struct {
	// base64url encoded between 1-4096 bytes in size
	Assertion string `json:"assertion"`

	// AssertionScheme corresponds to the JSON schema field "assertionScheme".
	AssertionScheme AssertionScheme `json:"assertionScheme"`

	// Exts corresponds to the JSON schema field "exts".
	Exts []Extension `json:"exts,omitempty"`

	// TcDisplayPNGCharacteristics corresponds to the JSON schema field
	// "tcDisplayPNGCharacteristics".
	TcDisplayPNGCharacteristics []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty"`
}

type AuthenticatorRegistrationAssertionAssertionScheme AssertionScheme

func (h OperationHeader) IsEmpty() bool {
	return reflect.DeepEqual(h, OperationHeader{})
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *RegistrationResponse) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["assertions"]; !ok || v == nil {
		return fmt.Errorf("field assertions: required")
	}
	if v, ok := raw["fcParams"]; !ok || v == nil {
		return fmt.Errorf("field fcParams: required")
	}
	if v, ok := raw["header"]; !ok || v == nil {
		return fmt.Errorf("field header: required")
	}
	type Plain RegistrationResponse
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = RegistrationResponse(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *RegistrationRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["challenge"]; !ok || v == nil {
		return fmt.Errorf("field challenge: required")
	}
	if v, ok := raw["header"]; !ok || v == nil {
		return fmt.Errorf("field header: required")
	}
	if v, ok := raw["policy"]; !ok || v == nil {
		return fmt.Errorf("field policy: required")
	}
	if v, ok := raw["username"]; !ok || v == nil {
		return fmt.Errorf("field username: required")
	}
	type Plain RegistrationRequest
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = RegistrationRequest(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *AuthenticatorRegistrationAssertion) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["assertion"]; !ok || v == nil {
		return fmt.Errorf("field assertion: required")
	}
	if v, ok := raw["assertionScheme"]; !ok || v == nil {
		return fmt.Errorf("field assertionScheme: required")
	}
	type Plain AuthenticatorRegistrationAssertion
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = AuthenticatorRegistrationAssertion(plain)
	return nil
}
