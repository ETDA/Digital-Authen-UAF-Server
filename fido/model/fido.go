// THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT.

package model

import (
	"fmt"
)
import "reflect"
import "encoding/json"

type DisplayPNGCharacteristicsDescriptor struct {
	// BitDepth corresponds to the JSON schema field "bitDepth".
	BitDepth float64 `json:"bitDepth"`

	// ColorType corresponds to the JSON schema field "colorType".
	ColorType float64 `json:"colorType"`

	// Compression corresponds to the JSON schema field "compression".
	Compression float64 `json:"compression"`

	// Filter corresponds to the JSON schema field "filter".
	Filter float64 `json:"filter"`

	// Height corresponds to the JSON schema field "height".
	Height int `json:"height"`

	// Interlace corresponds to the JSON schema field "interlace".
	Interlace float64 `json:"interlace"`

	// Plte corresponds to the JSON schema field "plte".
	Plte []RgbPalletteEntry `json:"plte,omitempty"`

	// Width corresponds to the JSON schema field "width".
	Width int `json:"width"`
}

type Extension struct {
	// base64url encoded between 1-8192 bytes in size
	Data string `json:"data"`

	// FailIfUnknown corresponds to the JSON schema field "fail_if_unknown".
	FailIfUnknown bool `json:"fail_if_unknown"`

	// Id corresponds to the JSON schema field "id".
	Id string `json:"id"`
}

type FinalChallengeParams struct {
	// AppID corresponds to the JSON schema field "appID".
	AppID string `json:"appID"`

	// Challenge corresponds to the JSON schema field "challenge".
	Challenge string `json:"challenge"`

	// FacetID corresponds to the JSON schema field "facetID".
	FacetID string `json:"facetID"`

	// ChannelBinding corresponds to the JSON schema field "channelBinding".
	ChannelBinding ChannelBinding `json:"channelBinding,omitempty"`
}

// base64url encoded between 32-2048 bytes in size
type KeyID string

//type MatchCriteria map[string]interface{}
type MatchCriteria struct {
	AAID                     []AAID      `json:"aaid,omitempty"`
	VendorID                 []string    `json:"vendorID,omitempty"`
	KeyIDs                   []KeyID     `json:"keyIDs,omitempty"`
	UserVerification         int32       `json:"userVerification,omitempty"`
	KeyProtection            int16       `json:"keyProtection,omitempty"`
	MatcherProtection        int16       `json:"matcherProtection,omitempty"`
	AttachmentHint           int32       `json:"attachmentHint,omitempty"`
	TcDisplay                int16       `json:"tcDisplay,omitempty"`
	AuthenticationAlgorithms []int16     `json:"authenticationAlgorithms,omitempty"`
	AssertionSchemes         []string    `json:"assertionSchemes,omitempty"`
	AssertionTypes           []int16     `json:"attestationTypes,omitempty"`
	AuthenticatorVersion     int16       `json:"authenticatorVersion,omitempty"`
	Exts                     []Extension `json:"exts,omitempty"`
}

type MetadataStatement struct {
	// Aaid corresponds to the JSON schema field "aaid".
	Aaid AAID `json:"aaid"`

	// A list of root x509 certificates for this AAID
	AttestationRootCertificates []string `json:"attestationRootCertificates,omitempty"`

	// Description corresponds to the JSON schema field "description".
	Description string `json:"description"`

	// IsSecondFactorOnly corresponds to the JSON schema field "isSecondFactorOnly".
	IsSecondFactorOnly bool `json:"isSecondFactorOnly"`

	// TcDisplay corresponds to the JSON schema field "tcDisplay".
	TcDisplay int `json:"tcDisplay"`

	// TcDisplayContentType corresponds to the JSON schema field
	// "tcDisplayContentType".
	TcDisplayContentType *TransactionContentType `json:"tcDisplayContentType,omitempty"`

	// A list valid display Characteristics
	TcDisplayPNGCharacteristics []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty"`
	AttachmentHint              int                                   `json:"attachmentHint"`
	KeyProtection               int                                   `json:"keyProtection"`
	MatcherProtection           int                                   `json:"matcherProtection"`
	AuthenticatorVersion        int                                   `json:"authenticatorVersion"`
	Icon                        string                                `json:"icon"`
	AssertionScheme             string                                `json:"assertionScheme"`
	AuthenticationAlgorithm     int                                   `json:"authenticationAlgorithm"`
	PublicKeyAlgAndEncoding     int                                   `json:"publicKeyAlgAndEncoding"`
	AttestationTypes            []int                                 `json:"attestationTypes"`
}

type Policy struct {
	// Accepted corresponds to the JSON schema field "accepted".
	Accepted [][]MatchCriteria `json:"accepted"`

	// Disallowed corresponds to the JSON schema field "disallowed".
	Disallowed []MatchCriteria `json:"disallowed"`
}

type RgbPalletteEntry struct {
	// B corresponds to the JSON schema field "b".
	B int `json:"b"`

	// G corresponds to the JSON schema field "g".
	G int `json:"g"`

	// R corresponds to the JSON schema field "r".
	R int `json:"r"`
}

type Token struct {
	// Type corresponds to the JSON schema field "type".
	Type string `json:"type"`

	// Value corresponds to the JSON schema field "value".
	Value string `json:"value"`
}

type TrustedFacets struct {
	// Ids corresponds to the JSON schema field "ids".
	Ids []string `json:"ids"`

	// Version corresponds to the JSON schema field "version".
	Version Version `json:"version"`
}

type UAFGetTrustedFacetIdsResponse struct {
	// TrustedFacets corresponds to the JSON schema field "trustedFacets".
	TrustedFacets []TrustedFacets `json:"trustedFacets"`
}

type Version struct {
	// Major corresponds to the JSON schema field "major".
	Major int `json:"major"`

	// Minor corresponds to the JSON schema field "minor".
	Minor int `json:"minor"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *Token) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["type"]; !ok || v == nil {
		return fmt.Errorf("field type: required")
	}
	if v, ok := raw["value"]; !ok || v == nil {
		return fmt.Errorf("field value: required")
	}
	type Plain Token
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = Token(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *Policy) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["accepted"]; !ok || v == nil {
		return fmt.Errorf("field accepted: required")
	}
	if v, ok := raw["disallowed"]; !ok || v == nil {
		return fmt.Errorf("field disallowed: required")
	}
	type Plain Policy
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = Policy(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *TransactionContentType) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	var ok bool
	for _, expected := range EnumTransactionContentType {
		if reflect.DeepEqual(v, expected) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("invalid value (expected one of %#v): %#v", EnumTransactionContentType, v)
	}
	*j = TransactionContentType(v)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *Operation) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	var ok bool
	for _, expected := range EnumOperation {
		if reflect.DeepEqual(v, expected) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("invalid value (expected one of %#v): %#v", EnumOperation, v)
	}
	*j = Operation(v)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *MetadataStatement) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["aaid"]; !ok || v == nil {
		return fmt.Errorf("field aaid: required")
	}
	if v, ok := raw["description"]; !ok || v == nil {
		return fmt.Errorf("field description: required")
	}
	if v, ok := raw["isSecondFactorOnly"]; !ok || v == nil {
		return fmt.Errorf("field isSecondFactorOnly: required")
	}
	if v, ok := raw["tcDisplay"]; !ok || v == nil {
		return fmt.Errorf("field tcDisplay: required")
	}
	type Plain MetadataStatement
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = MetadataStatement(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *FinalChallengeParams) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["appID"]; !ok || v == nil {
		return fmt.Errorf("field appID: required")
	}
	if v, ok := raw["challenge"]; !ok || v == nil {
		return fmt.Errorf("field challenge: required")
	}
	//if v, ok := raw["channelBinding"]; !ok || v == nil {
	//	return fmt.Errorf("field channelBinding: required")
	//}
	if v, ok := raw["facetID"]; !ok || v == nil {
		return fmt.Errorf("field facetID: required")
	}
	type Plain FinalChallengeParams
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = FinalChallengeParams(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *Version) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["major"]; !ok || v == nil {
		return fmt.Errorf("field major: required")
	}
	if v, ok := raw["minor"]; !ok || v == nil {
		return fmt.Errorf("field minor: required")
	}
	type Plain Version
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = Version(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *ServerResponse) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["statusCode"]; !ok || v == nil {
		return fmt.Errorf("field statusCode: required")
	}
	type Plain ServerResponse
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = ServerResponse(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *TokenType) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	var ok bool
	for _, expected := range EnumTokenType {
		if reflect.DeepEqual(v, expected) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("invalid value (expected one of %#v): %#v", EnumTokenType, v)
	}
	*j = TokenType(v)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *TrustedFacets) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["ids"]; !ok || v == nil {
		return fmt.Errorf("field ids: required")
	}
	if v, ok := raw["version"]; !ok || v == nil {
		return fmt.Errorf("field version: required")
	}
	type Plain TrustedFacets
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = TrustedFacets(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *AuthenticatorSignAssertion) UnmarshalJSON(b []byte) error {
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
	type Plain AuthenticatorSignAssertion
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = AuthenticatorSignAssertion(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *RgbPalletteEntry) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["b"]; !ok || v == nil {
		return fmt.Errorf("field b: required")
	}
	if v, ok := raw["g"]; !ok || v == nil {
		return fmt.Errorf("field g: required")
	}
	if v, ok := raw["r"]; !ok || v == nil {
		return fmt.Errorf("field r: required")
	}
	type Plain RgbPalletteEntry
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = RgbPalletteEntry(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *AssertionScheme) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	var ok bool
	for _, expected := range EnumAssertionScheme {
		if reflect.DeepEqual(v, expected) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("invalid value (expected one of %#v): %#v", EnumAssertionScheme, v)
	}
	*j = AssertionScheme(v)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *DisplayPNGCharacteristicsDescriptor) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["bitDepth"]; !ok || v == nil {
		return fmt.Errorf("field bitDepth: required")
	}
	if v, ok := raw["colorType"]; !ok || v == nil {
		return fmt.Errorf("field colorType: required")
	}
	if v, ok := raw["compression"]; !ok || v == nil {
		return fmt.Errorf("field compression: required")
	}
	if v, ok := raw["filter"]; !ok || v == nil {
		return fmt.Errorf("field filter: required")
	}
	if v, ok := raw["height"]; !ok || v == nil {
		return fmt.Errorf("field height: required")
	}
	if v, ok := raw["interlace"]; !ok || v == nil {
		return fmt.Errorf("field interlace: required")
	}
	if v, ok := raw["width"]; !ok || v == nil {
		return fmt.Errorf("field width: required")
	}
	type Plain DisplayPNGCharacteristicsDescriptor
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = DisplayPNGCharacteristicsDescriptor(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *Extension) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["data"]; !ok || v == nil {
		return fmt.Errorf("field data: required")
	}
	if v, ok := raw["fail_if_unknown"]; !ok || v == nil {
		return fmt.Errorf("field fail_if_unknown: required")
	}
	if v, ok := raw["id"]; !ok || v == nil {
		return fmt.Errorf("field id: required")
	}
	type Plain Extension
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = Extension(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *Transaction) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["content"]; !ok || v == nil {
		return fmt.Errorf("field content: required")
	}
	if v, ok := raw["contentType"]; !ok || v == nil {
		return fmt.Errorf("field contentType: required")
	}
	type Plain Transaction
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = Transaction(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *UAFGetTrustedFacetIdsResponse) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["trustedFacets"]; !ok || v == nil {
		return fmt.Errorf("field trustedFacets: required")
	}
	type Plain UAFGetTrustedFacetIdsResponse
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = UAFGetTrustedFacetIdsResponse(plain)
	return nil
}
