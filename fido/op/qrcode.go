package op

import (
	"encoding/json"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	fidoModel "github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/status"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/google/uuid"
)

type QrCodeClaim struct {
	Id       string `json:"id"`
	Identity string `json:"identity"`
	jwt.StandardClaims
}

func ValidateQrCodeToken(qrToken string) (*db.QrCode, error) {

	token, err := utils.ValidateJwtToken(qrToken, &QrCodeClaim{})
	if err != nil {
		if err == status.ErrTokenExpired {
			return nil, status.ErrQrCodeExpired
		}
		return nil, status.ErrInvalidQrCode
	}

	claim := token.Claims.(*QrCodeClaim)

	var qrCode = db.FindQrCodeById(claim.Id)
	return qrCode, nil
}

func GetQrIdByToken(qrToken string) (string, error) {

	token, err := utils.ValidateJwtToken(qrToken, &QrCodeClaim{})
	if err != nil {
		if err == status.ErrTokenExpired {
			return "", status.ErrQrCodeExpired
		}
		return "", status.ErrInvalidQrCode
	}

	claim := token.Claims.(*QrCodeClaim)
	return claim.Id, nil
}

func GetFidoRequest(account *db.Account, context interface{}, op fidoModel.Operation) (*string, *string, *db.QrCode, error) {

	now := time.Now()
	exp := now.Add(app.Config.JwtExpireTime)
	qrId := uuid.NewString()
	qrCode := db.QrCode{
		ID:        qrId,
		Op:        string(op),
		AccountID: account.ID,
		CreatedAt: now,
		UsedAt:    nil,
		Status:    db.QR_CODE_STATUS_NEW,
		SessionID: nil,
	}

	claims := QrCodeClaim{
		qrId,
		account.Identity,
		jwt.StandardClaims{
			IssuedAt:  now.Unix(),
			Issuer:    app.Config.ServiceName,
			ExpiresAt: exp.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t, _ := token.SignedString(app.Config.JwtSignKey)

	ctx, _ := json.Marshal(context)
	ctxStr := string(ctx)

	uafReq := fidoModel.GetUAFRequest{
		Context:      &ctxStr,
		Op:           op,
		QrCodeToken:  &t,
		Endpoint_url: &app.Config.QR_ENDPOINT,
	}
	req, _ := json.Marshal(uafReq)
	j := string(req)
	return &j, &t, &qrCode, nil
}

func GetFidoRequest_2(account_Id string, identity string, context interface{}, op fidoModel.Operation) (*string, *string, *db.QrCode, error) {

	now := time.Now()
	exp := now.Add(app.Config.JwtExpireTime)
	qrId := uuid.NewString()
	qrCode := db.QrCode{
		ID:        qrId,
		Op:        string(op),
		AccountID: account_Id,
		CreatedAt: now,
		UsedAt:    nil,
		Status:    db.QR_CODE_STATUS_NEW,
		SessionID: nil,
	}

	claims := QrCodeClaim{
		qrId,
		identity,
		jwt.StandardClaims{
			IssuedAt:  now.Unix(),
			Issuer:    app.Config.ServiceName,
			ExpiresAt: exp.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t, _ := token.SignedString(app.Config.JwtSignKey)

	ctx, _ := json.Marshal(context)
	ctxStr := string(ctx)

	uafReq := fidoModel.GetUAFRequest{
		Context:      &ctxStr,
		Op:           op,
		QrCodeToken:  &t,
		Endpoint_url: &app.Config.QR_ENDPOINT,
	}
	req, _ := json.Marshal(uafReq)
	j := string(req)
	return &j, &t, &qrCode, nil
}
