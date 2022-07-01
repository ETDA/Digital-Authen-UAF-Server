package model

type AssertionContext struct {
	AccountId   string
	FcpHash     []byte
	Transaction *string
}

type KeyRegistrationData struct {
	AAID               string
	AssertionInfo      AssertionInfo
	FinalChallengeHash []byte
	KeyId              string
	Counter            Counter
	PublicKey          []byte
	DeviceInfo         DeviceInfo
}

type DeviceInfo struct {
	Name string
	Id   string
}

type SignedData struct {
	AAID                   string
	AssertionInfo          AssertionInfo
	FinalChallengeHash     []byte
	KeyId                  string
	Counter                Counter
	TransactionContentHash []byte
	AuthenticatorNonce     []byte
}

type Counter struct {
	SignCounter uint32
	RegCounter  uint32
}

type AssertionInfo struct {
	AuthenticatorVersion    uint16
	AuthenticationMode      uint8
	SignatureAlgAndEncoding uint16
	PublicKeyAlgAndEncoding uint16
}
