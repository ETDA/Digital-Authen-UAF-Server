package model

type TokenType string
type AAID string
type AssertionScheme string
type TransactionContentType string
type Operation string

const OperationAuth Operation = "Auth"
const OperationDereg Operation = "Dereg"
const OperationReg Operation = "Reg"
const OperationUnknown Operation = ""

const AssertionSchemeUAFV1TLV AssertionScheme = "UAFV1TLV"

const TokenType_HTTPCOOKIE TokenType = "HTTP_COOKIE"
const TokenType_JWT TokenType = "JWT"
const TokenType_OAUTH TokenType = "OAUTH"
const TokenType_OAUTH2 TokenType = "OAUTH2"
const TokenType_OPENIDCONNECT TokenType = "OPENID_CONNECT"
const TokenType_SAML11 TokenType = "SAML1_1"
const TokenType_SAML2 TokenType = "SAML2"

const TransactionContentTypeImagePng TransactionContentType = "image/png"
const TransactionContentTypeTextPlain TransactionContentType = "text/plain"

const (
	ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW = iota + 1
	ALG_SIGN_SECP256R1_ECDSA_SHA256_DER
	ALG_SIGN_RSASSA_PSS_SHA256_RAW
	ALG_SIGN_RSASSA_PSS_SHA256_DER
	ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW
	ALG_SIGN_SECP256K1_ECDSA_SHA256_DER
	ALG_SIGN_SM2_SM3_RAW
	ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW
	ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER
)

const (
	ALG_KEY_ECC_X962_RAW = 0x0100 + iota
	ALG_KEY_ECC_X962_DER
	ALG_KEY_RSA_2048_RAW
	ALG_KEY_RSA_2048_DER
)

var UAFV1_1 = Version{
	Major: 1,
	Minor: 1,
}

var UAFV1_0 = Version{
	Major: 1,
	Minor: 0,
}
