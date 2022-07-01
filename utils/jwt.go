package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"github.com/etda-uaf/uaf-server/app"
	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/status"
	"math/big"
	"time"
)

type DefaultClaim struct {
	Data interface{} `json:"data"`
	jwt.StandardClaims
}

type ServerDataClaim struct {
	Data model.ServerData `json:"data"`
	DefaultClaim
}

func ValidateJwtToken(t string, v jwt.Claims) (*jwt.Token, error) {
	return ValidateJwtTokenWithPublicKey(t, v, app.Config.JwtSignKey.Public())
}

func ValidateJwtTokenWithPlainPublicKey(t string, v jwt.Claims, pkb64 string) (*jwt.Token, error) {
	var dst = make([]byte, base64.URLEncoding.DecodedLen(len(pkb64)))
	_, err := base64.StdEncoding.Decode(dst, []byte(pkb64))
	if err != nil {
		return nil, status.ErrInvalidToken
	}
	if dst == nil || len(dst) < 64 {
		return nil, status.ErrInvalidToken
	}
	return ValidateJwtTokenWithPublicKey(t, v, &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(dst[:32]),
		Y:     big.NewInt(0).SetBytes(dst[32:64]),
	})
}

func ValidateJwtTokenWithPublicKey(t string, v jwt.Claims, publicKey crypto.PublicKey) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(t, v,
		func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})

	if err == nil && token.Valid {
		return token, nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, status.ErrInvalidToken
		} else if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			return nil, status.ErrTokenExpired
		} else if ve.Errors&(jwt.ValidationErrorNotValidYet) != 0 {
			return nil, status.ErrTokenExpired
		} else {
			return nil, status.ErrInvalidToken
		}
	} else {
		return nil, status.ErrInvalidToken
	}
}

func JWTSign(v interface{}, iat time.Time, exp time.Time) (*string, error) {
	claims := DefaultClaim{
		v,
		jwt.StandardClaims{
			IssuedAt:  iat.Unix(),
			Issuer:    app.Config.ServiceName,
			ExpiresAt: exp.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t, err := token.SignedString(app.Config.JwtSignKey)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
