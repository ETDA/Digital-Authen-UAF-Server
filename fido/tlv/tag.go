package tlv

import (
	"encoding/base64"
	"errors"
)

type TagType int

//TAG types from uaf tlv doc
const (
	TAG_UAF_CMD_STATUS_ERR_UNKNOWN  = TagType(0x01)
	TAG_UAFV1_REG_ASSERTION         = TagType(0x3E01)
	TAG_UAFV1_AUTH_ASSERTION        = TagType(0x3E02)
	TAG_UAFV1_KRD                   = TagType(0x3E03)
	TAG_UAFV1_SIGNED_DATA           = TagType(0x3E04)
	TAG_ATTESTATION_BASIC_FULL      = TagType(0x3E07)
	TAG_ATTESTATION_BASIC_SURROGATE = TagType(0x3E08)

	TAG_ATTESTATION_CERT         = TagType(0x2E05)
	TAG_SIGNATURE                = TagType(0x2E06)
	TAG_KEYID                    = TagType(0x2E09)
	TAG_FINAL_CHALLENGE_HASH     = TagType(0x2E0A)
	TAG_AAID                     = TagType(0x2E0B)
	TAG_PUB_KEY                  = TagType(0x2E0C)
	TAG_COUNTERS                 = TagType(0x2E0D)
	TAG_ASSERTION_INFO           = TagType(0x2E0E)
	TAG_AUTHENTICATOR_NONCE      = TagType(0x2E0F)
	TAG_TRANSACTION_CONTENT_HASH = TagType(0x2E10)

	TAG_ATTESTATION_ECDAA      = TagType(0x3E09)
	TAG_EXTENSION              = TagType(0x3E11)
	TAG_EXTENSION_NON_CRITICAL = TagType(0x3E12)
	TAG_EXTENSION_ID           = TagType(0x2E13)
	TAG_EXTENSION_DATA         = TagType(0x2E14)

	TAG_RAW_USER_VERIFICATION_INDEX = TagType(0x0103)
	TAG_USER_VERIFICATION_INDEX     = TagType(0x0104)
	TAG_RAW_USER_VERIFICATION_STATE = TagType(0x0105)
	TAG_USER_VERIFICATION_STATE     = TagType(0x0106)
	TAG_USER_VERIFICATION_CACHING   = TagType(0x0108)
	TAG_RESERVED_5                  = TagType(0x0201)
)

var (
	tags = map[TagType]string{
		TAG_UAFV1_REG_ASSERTION:         "TAG_UAFV1_REG_ASSERTION",
		TAG_UAFV1_AUTH_ASSERTION:        "TAG_UAFV1_AUTH_ASSERTION",
		TAG_UAFV1_KRD:                   "TAG_UAFV1_KRD",
		TAG_UAFV1_SIGNED_DATA:           "TAG_UAFV1_SIGNED_DATA",
		TAG_ATTESTATION_CERT:            "TAG_ATTESTATION_CERT",
		TAG_SIGNATURE:                   "TAG_SIGNATURE",
		TAG_ATTESTATION_BASIC_FULL:      "TAG_ATTESTATION_BASIC_FULL",
		TAG_ATTESTATION_BASIC_SURROGATE: "TAG_ATTESTATION_BASIC_SURROGATE",
		TAG_ATTESTATION_ECDAA:           "TAG_ATTESTATION_ECDAA",
		TAG_KEYID:                       "TAG_KEYID",
		TAG_FINAL_CHALLENGE_HASH:        "TAG_FINAL_CHALLENGE_HASH",
		TAG_AAID:                        "TAG_AAID",
		TAG_PUB_KEY:                     "TAG_PUB_KEY",
		TAG_COUNTERS:                    "TAG_COUNTERS",
		TAG_ASSERTION_INFO:              "TAG_ASSERTION_INFO",
		TAG_AUTHENTICATOR_NONCE:         "TAG_AUTHENTICATOR_NONCE",
		TAG_TRANSACTION_CONTENT_HASH:    "TAG_TRANSACTION_CONTENT_HASH",
		TAG_EXTENSION:                   "TAG_EXTENSION",
		TAG_EXTENSION_NON_CRITICAL:      "TAG_EXTENSION_NON_CRITICAL",
		TAG_EXTENSION_ID:                "TAG_EXTENSION_ID",
		TAG_EXTENSION_DATA:              "TAG_EXTENSION_DATA",
		TAG_UAF_CMD_STATUS_ERR_UNKNOWN:  "TAG_UAF_CMD_STATUS_ERR_UNKNOWN",
		TAG_RAW_USER_VERIFICATION_INDEX: "TAG_RAW_USER_VERIFICATION_INDEX",
		TAG_USER_VERIFICATION_INDEX:     "TAG_USER_VERIFICATION_INDEX",
		TAG_RAW_USER_VERIFICATION_STATE: "TAG_RAW_USER_VERIFICATION_STATE",
		TAG_USER_VERIFICATION_STATE:     "TAG_USER_VERIFICATION_STATE",
		TAG_USER_VERIFICATION_CACHING:   "TAG_USER_VERIFICATION_CACHING",
		TAG_RESERVED_5:                  "TAG_RESERVED_5",
	}

	//errRangeException is thrown when there is not enough bytes to access
	ErrRangeException = errors.New("range exception")
	ErrTagNotFound    = errors.New("tag not found")
)

func (tag Tag) GetSubValue(tagTypes []TagType) []byte {
	var cursor = &tag
	for _, t := range tagTypes {
		currentTag := cursor.GetSubTag(t)
		if !currentTag.Existed {
			return nil
		}
		cursor = &currentTag
	}
	return cursor.Value
}

func (tag Tag) GetSubValueWithTagId(tagTypes []TagType) []byte {
	var cursor = &tag
	for _, t := range tagTypes {
		currentTag := cursor.GetSubTag(t)
		if !currentTag.Existed {
			return nil
		}
		cursor = &currentTag
	}
	v := make([]byte, len(cursor.Value)+4)
	for i := 0; i < len(cursor.Value); i++ {
		v[i+4] = cursor.Value[i]
	}
	v[1], v[0] = uint8(cursor.ID>>8), uint8(cursor.ID&0xff)
	v[3], v[2] = uint8(cursor.Length>>8), uint8(cursor.Length&0xff)

	return v
}

func (tag Tag) GetSubValueString(tagTypes []TagType) *string {
	val := tag.GetSubValue(tagTypes)
	if val == nil {
		return nil
	}
	str := string(val)
	return &str
}

func (tag Tag) GetEncodedSubValue(tagTypes []TagType) *string {
	val := tag.GetSubValue(tagTypes)
	if val == nil {
		return nil
	}
	enc := base64.RawURLEncoding.EncodeToString(val)
	return &enc
}
