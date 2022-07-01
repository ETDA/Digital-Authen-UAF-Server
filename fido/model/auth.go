package model

import (
	"encoding/json"
	"fmt"
)

type AuthenticatorSignAssertion struct {
	// base64url encoded between 1-4096 bytes in size
	Assertion string `json:"assertion"`

	// AssertionScheme corresponds to the JSON schema field "assertionScheme".
	AssertionScheme AssertionScheme `json:"assertionScheme"`

	// Exts corresponds to the JSON schema field "exts".
	Exts []Extension `json:"exts,omitempty"`
}

type AuthenticatorSignAssertionAssertionScheme AssertionScheme

type AuthenticationRequest struct {
	// Challenge corresponds to the JSON schema field "challenge".
	Challenge string `json:"challenge"`

	// Header corresponds to the JSON schema field "header".
	Header OperationHeader `json:"header"`

	// Policy corresponds to the JSON schema field "policy".
	Policy Policy `json:"policy"`

	// Transaction corresponds to the JSON schema field "transaction".
	Transaction []Transaction `json:"transaction"`
}

type AuthenticationResponse struct {
	// Assertions corresponds to the JSON schema field "assertions".
	Assertions []AuthenticatorSignAssertion `json:"assertions"`

	// FcParams corresponds to the JSON schema field "fcParams".
	FcParams string `json:"fcParams"`

	// Header corresponds to the JSON schema field "header".
	Header OperationHeader `json:"header"`
}

type ChannelBinding struct {
	// base64url or 'None'
	CidPubkey *string `json:"cid_pubkey,omitempty"`

	// base64url
	ServerEndPoint *string `json:"serverEndPoint,omitempty"`

	// base64url on 'None'
	TlsServerCertificate *string `json:"tlsServerCertificate,omitempty"`

	// base64url or 'None'
	TlsUnique *string `json:"tlsUnique,omitempty"`
}

type Transaction struct {
	// Content corresponds to the JSON schema field "content".
	Content string `json:"content"`

	// ContentType corresponds to the JSON schema field "contentType".
	ContentType TransactionContentType `json:"contentType"`

	// TcDisplayPNGCharacteristics corresponds to the JSON schema field
	// "tcDisplayPNGCharacteristics".
	TcDisplayPNGCharacteristics *DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *AuthenticationRequest) UnmarshalJSON(b []byte) error {
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
	type Plain AuthenticationRequest
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = AuthenticationRequest(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *AuthenticationResponse) UnmarshalJSON(b []byte) error {
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
	type Plain AuthenticationResponse
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = AuthenticationResponse(plain)
	return nil
}
