package validator

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	fidoModel "github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/status"
	"github.com/etda-uaf/uaf-server/fido/tlv"
	"github.com/etda-uaf/uaf-server/utils"
)

var (
	ErrInvalidKeyID           = errors.New("invalid key id")
	ErrInvalidAAID            = errors.New("invalid AAID")
	ErrInvalidChallengeHash   = errors.New("invalid final challenge hash")
	ErrInvalidTransactionHash = errors.New("invalid final transaction hash")
	ErrInvalidAssertionInfo   = errors.New("invalid assertion info")
	ErrInvalidCounter         = errors.New("invalid counter")
	ErrInvalidAssertionData   = errors.New("invalid assertion data")
	ErrInvalidNonce           = errors.New("invalid nonce")
	ErrInvalidTxHash          = errors.New("invalid transaction hash")
	ErrInvalidCounterValue    = errors.New("invalid counter value")
	ErrMalformedDevice        = errors.New("malformed device")

	ErrUnknownAuthenticator = errors.New("unknown authenticator")
)

func ValidateAssertions(assertions []model.AuthenticatorSignAssertion, context fidoModel.AssertionContext) ([]db.Authenticator, error) {

	if len(assertions) < 1 {
		return nil, nil
	}
	var tags tlv.Tags
	var err error
	var authenticators []db.Authenticator
	for _, assertion := range assertions {
		if assertion.AssertionScheme != model.AssertionSchemeUAFV1TLV {
			err = status.ErrUnsupportedAssertionScheme
			continue
		}

		tags, err = tlv.ParseBase64(assertion.Assertion)
		if err != nil {
			err = status.ErrInvalidAssertion
			continue
		}
		var authenticator *db.Authenticator
		if tags.GetSubTag(tlv.TAG_UAFV1_REG_ASSERTION).Existed {
			authenticator, err = ValidateRegAssertion(tags.GetSubTag(tlv.TAG_UAFV1_REG_ASSERTION), context)
		} else if tags.GetSubTag(tlv.TAG_UAFV1_AUTH_ASSERTION).Existed {
			authenticator, err = ValidateAuthAssertion(tags.GetSubTag(tlv.TAG_UAFV1_AUTH_ASSERTION), context)
		} else {
			continue
		}
		if authenticator == nil {
			continue
		}

		authenticators = append(authenticators, *authenticator)
	}
	if err != nil {
		return nil, err
	}
	return authenticators, nil
}

func ValidateRegAssertions(assertions []model.AuthenticatorRegistrationAssertion, context fidoModel.AssertionContext) ([]db.Authenticator, error) {
	var sas = make([]model.AuthenticatorSignAssertion, len(assertions))
	i := 0
	for _, a := range assertions {
		sas[i] = model.AuthenticatorSignAssertion{
			Assertion:       a.Assertion,
			AssertionScheme: a.AssertionScheme,
			Exts:            a.Exts,
		}
		i++
	}

	return ValidateAssertions(sas, context)

}
func ValidateAuthAssertions(assertions []model.AuthenticatorSignAssertion, context fidoModel.AssertionContext) ([]db.Authenticator, error) {
	return ValidateAssertions(assertions, context)
}

func ValidateAuthAssertion(tag tlv.Tag, context fidoModel.AssertionContext) (*db.Authenticator, error) {
	sd, err := ParseSignedData(tag.GetSubTag(tlv.TAG_UAFV1_SIGNED_DATA))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(context.FcpHash, sd.FinalChallengeHash) {
		return nil, ErrInvalidChallengeHash
	}

	if context.Transaction != nil {
		tx, _ := base64.RawURLEncoding.DecodeString(*context.Transaction)
		txHash := sha256.Sum256(tx)
		if bytes.Equal(txHash[:], sd.TransactionContentHash) {
			return nil, ErrInvalidTransactionHash
		}
	}

	authnr := db.FindAuthenticatorsByAccountIdAndKeyId(context.AccountId, sd.KeyId)

	if authnr == nil {
		return nil, ErrUnknownAuthenticator
	}

	if authnr.SignCounter > sd.Counter.SignCounter {
		return nil, ErrInvalidCounterValue
	}

	authnr.SignCounter = sd.Counter.SignCounter

	pk := utils.DecodeBase64Bytes(authnr.PublicKey)

	valid := false
	sdBytes := tag.GetSubValueWithTagId([]tlv.TagType{tlv.TAG_UAFV1_SIGNED_DATA})
	if tag.GetSubTag(tlv.TAG_SIGNATURE).Existed {
		valid, err = ValidateSignature(tag, sd.AAID, pk, authnr.SignatureAlgo, authnr.PublicKeyAlgo, sdBytes)
	} else {
		return nil, ErrInvalidAssertionData
	}
	if !valid {
		return nil, ErrInvalidSignature
	}
	return authnr, nil
}

func ValidateRegAssertion(tag tlv.Tag, context fidoModel.AssertionContext) (*db.Authenticator, error) {
	krd, err := ParseKrd(tag.GetSubTag(tlv.TAG_UAFV1_KRD))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(context.FcpHash, krd.FinalChallengeHash) {
		return nil, ErrInvalidChallengeHash
	}

	valid := false
	krdBytes := tag.GetSubValueWithTagId([]tlv.TagType{tlv.TAG_UAFV1_KRD})
	var assertion tlv.Tag
	if tag.GetSubTag(tlv.TAG_ATTESTATION_BASIC_SURROGATE).Existed {
		assertion = tag.GetSubTag(tlv.TAG_ATTESTATION_BASIC_SURROGATE)
	} else if tag.GetSubTag(tlv.TAG_ATTESTATION_BASIC_FULL).Existed {
		assertion = tag.GetSubTag(tlv.TAG_ATTESTATION_BASIC_FULL)
	} else if tag.GetSubTag(tlv.TAG_ATTESTATION_ECDAA).Existed {
		return nil, ErrUnsupportedAlgorithm
	} else {
		return nil, ErrInvalidAssertionData
	}

	valid, err = ValidateSignature(
		assertion,
		krd.AAID, krd.PublicKey,
		krd.AssertionInfo.SignatureAlgAndEncoding,
		krd.AssertionInfo.PublicKeyAlgAndEncoding,
		krdBytes,
	)

	if !valid {
		return nil, ErrInvalidSignature
	}
	return &db.Authenticator{
		KeyId:         &krd.KeyId,
		AAID:          &krd.AAID,
		PublicKeyAlgo: krd.AssertionInfo.PublicKeyAlgAndEncoding,
		SignatureAlgo: krd.AssertionInfo.SignatureAlgAndEncoding,
		PublicKey:     base64.RawURLEncoding.EncodeToString(krd.PublicKey),
		RegCounter:    krd.Counter.RegCounter,
		SignCounter:   krd.Counter.SignCounter,
		DeviceName:    krd.DeviceInfo.Name,
		DeviceId:      krd.DeviceInfo.Id,
	}, nil
}

func ParseSignedData(tag tlv.Tag) (*fidoModel.SignedData, error) {
	aaid := tag.GetSubValueString([]tlv.TagType{tlv.TAG_AAID})
	if aaid == nil || *aaid == "" {
		return nil, ErrInvalidAAID
	}
	keyId := tag.GetEncodedSubValue([]tlv.TagType{tlv.TAG_KEYID})
	if keyId == nil || *keyId == "" {
		return nil, ErrInvalidKeyID
	}
	challengeHash := tag.GetSubValue([]tlv.TagType{tlv.TAG_FINAL_CHALLENGE_HASH})
	if challengeHash == nil {
		return nil, ErrInvalidChallengeHash
	}
	assertionInfo := tag.GetSubValue([]tlv.TagType{tlv.TAG_ASSERTION_INFO})
	if assertionInfo == nil || len(assertionInfo) != 5 {
		return nil, ErrInvalidAssertionInfo
	}
	counter := tag.GetSubValue([]tlv.TagType{tlv.TAG_COUNTERS})
	if counter == nil {
		return nil, ErrInvalidCounter
	}
	nonce := tag.GetSubValue([]tlv.TagType{tlv.TAG_AUTHENTICATOR_NONCE})
	if nonce == nil {
		return nil, ErrInvalidNonce
	}
	txHash := tag.GetSubValue([]tlv.TagType{tlv.TAG_TRANSACTION_CONTENT_HASH})
	if txHash == nil {
		return nil, ErrInvalidTxHash
	}
	return &fidoModel.SignedData{
		AAID: *aaid,
		AssertionInfo: fidoModel.AssertionInfo{
			AuthenticatorVersion:    binary.LittleEndian.Uint16(assertionInfo[:2]),
			AuthenticationMode:      assertionInfo[2],
			SignatureAlgAndEncoding: binary.LittleEndian.Uint16(assertionInfo[3:5]),
			PublicKeyAlgAndEncoding: 0,
		},
		FinalChallengeHash: challengeHash,
		KeyId:              *keyId,
		Counter: fidoModel.Counter{
			SignCounter: binary.LittleEndian.Uint32(counter[:4]),
			RegCounter:  0,
		},
		AuthenticatorNonce:     nonce,
		TransactionContentHash: txHash,
	}, nil
}

func ParseKrd(tag tlv.Tag) (*fidoModel.KeyRegistrationData, error) {
	aaid := tag.GetSubValueString([]tlv.TagType{tlv.TAG_AAID})
	if aaid == nil || *aaid == "" {
		return nil, ErrInvalidAAID
	}
	keyId := tag.GetEncodedSubValue([]tlv.TagType{tlv.TAG_KEYID})
	if keyId == nil || *keyId == "" {
		return nil, ErrInvalidKeyID
	}
	challengeHash := tag.GetSubValue([]tlv.TagType{tlv.TAG_FINAL_CHALLENGE_HASH})
	if challengeHash == nil {
		return nil, ErrInvalidChallengeHash
	}
	assertionInfo := tag.GetSubValue([]tlv.TagType{tlv.TAG_ASSERTION_INFO})
	if assertionInfo == nil || len(assertionInfo) != 7 {
		return nil, ErrInvalidAssertionInfo
	}
	counter := tag.GetSubValue([]tlv.TagType{tlv.TAG_COUNTERS})
	if counter == nil {
		return nil, ErrInvalidCounter
	}
	publicKey := tag.GetSubValue([]tlv.TagType{tlv.TAG_PUB_KEY})
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	devId := ""
	devName := ""

	if !app.Config.ConformanceMode {
		id := tag.GetSubValue([]tlv.TagType{tlv.TAG_EXTENSION, tlv.TAG_EXTENSION_ID})
		name := tag.GetSubValue([]tlv.TagType{tlv.TAG_EXTENSION, tlv.TAG_EXTENSION_DATA})
		if id == nil || name == nil {
			devId = string("123")
			devName = string("iOS")
			//return nil, ErrMalformedDevice
		} else {
			devId = string(id)
			devName = string(name)
		}

	}

	return &fidoModel.KeyRegistrationData{
		AAID: *aaid,
		AssertionInfo: fidoModel.AssertionInfo{
			AuthenticatorVersion:    binary.LittleEndian.Uint16(assertionInfo[:2]),
			AuthenticationMode:      assertionInfo[2],
			SignatureAlgAndEncoding: binary.LittleEndian.Uint16(assertionInfo[3:5]),
			PublicKeyAlgAndEncoding: binary.LittleEndian.Uint16(assertionInfo[5:7]),
		},
		FinalChallengeHash: challengeHash,
		KeyId:              *keyId,
		Counter: fidoModel.Counter{
			SignCounter: binary.LittleEndian.Uint32(counter[:4]),
			RegCounter:  binary.LittleEndian.Uint32(counter[4:8]),
		},
		PublicKey: publicKey,
		DeviceInfo: fidoModel.DeviceInfo{
			Id:   devId,
			Name: devName,
		},
	}, nil
}
