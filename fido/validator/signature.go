package validator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/etda-uaf/uaf-server/app"
	fidoModel "github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/tlv"
	"math/big"
	"strings"
)

type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type EcdsaSignature struct {
	R *big.Int
	S *big.Int
}

type RsaSignature struct {
	N *big.Int
	E uint32
}

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidPublicKey     = errors.New("invalid public key")
)

func ValidateSignature(tag tlv.Tag, aaid string, publicKey []byte, sigAlgo uint16, publicKeyAlgo uint16, data []byte) (bool, error) {
	signature := tag.GetSubValue([]tlv.TagType{tlv.TAG_SIGNATURE})
	if len(signature) == 0 {
		return false, ErrInvalidSignature
	}

	if app.Config.ConformanceMode && strings.Index(aaid, "FFFF#FC") == 0 {
		return true, nil
	}

	krdHash := sha256.Sum256(data)

	switch sigAlgo {
	case fidoModel.ALG_SIGN_SM2_SM3_RAW:
		return false, ErrUnsupportedAlgorithm
	case fidoModel.ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER:
		return false, ErrUnsupportedAlgorithm
	case fidoModel.ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW:
		return false, ErrUnsupportedAlgorithm
	case fidoModel.ALG_SIGN_RSASSA_PSS_SHA256_DER, fidoModel.ALG_SIGN_RSASSA_PSS_SHA256_RAW:
		return verifyRSASignature(signature, krdHash[:], publicKey, publicKeyAlgo)
	case fidoModel.ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW, fidoModel.ALG_SIGN_SECP256K1_ECDSA_SHA256_DER:
		return verifyECCSignature(signature, krdHash[:], publicKey, publicKeyAlgo, secp256k1.S256())
	case fidoModel.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, fidoModel.ALG_SIGN_SECP256R1_ECDSA_SHA256_DER:
		return verifyECCSignature(signature, krdHash[:], publicKey, publicKeyAlgo, elliptic.P256())
	}

	return false, nil
}

func verifyECCSignature(signature []byte, hash []byte, pk []byte, pubKeyEncoding uint16, curve elliptic.Curve) (bool, error) {

	var publicKey *ecdsa.PublicKey
	var x, y *big.Int

	switch int(pubKeyEncoding) {
	case fidoModel.ALG_KEY_ECC_X962_DER:
		var seq SubjectPublicKeyInfo
		_, err := asn1.Unmarshal(pk, &seq)
		if err != nil {
			return false, ErrInvalidPublicKey
		}
		x, y = elliptic.Unmarshal(curve, seq.SubjectPublicKey.Bytes)
	case fidoModel.ALG_KEY_ECC_X962_RAW:
		x, y = elliptic.Unmarshal(curve, pk)
	default:
		return false, ErrInvalidPublicKey
	}

	if x == big.NewInt(0) {
		return false, ErrInvalidPublicKey
	}

	publicKey = &ecdsa.PublicKey{
		Curve: curve, X: x, Y: y,
	}

	var sig EcdsaSignature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		r, s := new(big.Int), new(big.Int)
		r.SetBytes(signature[:32])
		s.SetBytes(signature[32:64])
		return ecdsa.Verify(publicKey, hash, r, s), nil
	}

	return ecdsa.Verify(publicKey, hash, sig.R, sig.S), nil
}

func verifyRSASignature(signature []byte, hash []byte, pk []byte, pubKeyEncoding uint16) (bool, error) {

	var publicKey *rsa.PublicKey
	var n *big.Int
	var e uint32

	switch int(pubKeyEncoding) {
	case fidoModel.ALG_KEY_RSA_2048_DER:
		var seq SubjectPublicKeyInfo
		_, err := asn1.Unmarshal(pk, &seq)
		if err != nil {
			return false, ErrInvalidPublicKey
		}
		n = new(big.Int)
		n.SetBytes(seq.SubjectPublicKey.Bytes[:32])
		e = binary.LittleEndian.Uint32(seq.SubjectPublicKey.Bytes[32:])
	case fidoModel.ALG_KEY_RSA_2048_RAW:
		n = new(big.Int)
		n.SetBytes(pk[:32])
		e = binary.LittleEndian.Uint32(pk[32:])
	default:
		return false, ErrInvalidPublicKey
	}

	if n == big.NewInt(0) {
		return false, ErrInvalidPublicKey
	}

	publicKey = &rsa.PublicKey{
		N: n,
		E: int(e),
	}
	opts := rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hash, signature, &opts); err != nil {
		return false, nil
	}
	return true, nil
}
