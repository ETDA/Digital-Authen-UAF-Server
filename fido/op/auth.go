package op

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"image"
	"log"
	"time"

	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/status"
	"github.com/etda-uaf/uaf-server/fido/validator"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/jinzhu/copier"
)

func GetAuth(request *model.AuthenticationContext, qrCode *db.QrCode) (*model.AuthenticationRequest, status.Status, error) {
	authnReq := model.AuthenticationRequest{}

	//Must Disable for PRD
	//request.UserName = "kod@etda.or.th"
	account := db.FindAccountByIdentity(request.UserName)

	if account == nil {
		return nil, status.NotFound, status.ErrUserNotFound
	}

	if qrCode != nil && !app.Config.ConformanceMode {
		if qrCode.AccountID != account.ID {
			return nil, status.Forbidden, status.ErrInvalidQrCode
		}
	}

	authenticators := db.FindAuthenticatorsByAccount(account.ID)
	err := copier.Copy(&authnReq.Policy, &app.Config.Policy)
	if err != nil {
		return nil, status.InternalServerError, errors.New("failed to create policy")
	}

	if authenticators == nil || len(authenticators) == 0 {
		return nil, status.NotFound, status.ErrAuthenticatorNotFound
	}

	var txs []model.Transaction
	for _, a := range authenticators {
		statement := db.FindMetadataStatementByAAID(*a.AAID)
		if statement == nil {
			continue
		}

		var tx model.Transaction

		// for Server-Auth-Req-4 P-10
		if statement.IsSecondFactorOnly == true {
			log.Printf("found 2nd factor only authenticator")
			matchCriteria := model.MatchCriteria{}
			matchCriteria.AAID = append(matchCriteria.AAID, statement.Aaid)
			matchCriteria.KeyIDs = append(matchCriteria.KeyIDs, model.KeyID(*a.KeyId))
			authnReq.Policy.Accepted = append(authnReq.Policy.Accepted, []model.MatchCriteria{matchCriteria})
		}

		if *statement.TcDisplayContentType == model.TransactionContentTypeImagePng {
			var img *image.RGBA
			var b []byte
			if request.Transaction == nil {
				img, b = utils.GetLabelImage("test tx for conformance")
				tx.Content = base64.RawURLEncoding.EncodeToString(b)
			} else {
				img, b = utils.GetLabelImage(*request.Transaction)
				tx.Content = base64.RawURLEncoding.EncodeToString(b)
			}
			tx.ContentType = model.TransactionContentTypeImagePng
			tx.TcDisplayPNGCharacteristics = &model.DisplayPNGCharacteristicsDescriptor{
				BitDepth: 8,
				Height:   img.Bounds().Size().Y,
				Width:    img.Bounds().Size().Y,
			}
		} else if *statement.TcDisplayContentType == model.TransactionContentTypeTextPlain {
			tx.ContentType = model.TransactionContentTypeTextPlain
			if request.Transaction == nil {
				tx.Content = base64.RawURLEncoding.EncodeToString([]byte("test tx for conformance"))
			} else {
				tx.Content = base64.RawURLEncoding.EncodeToString([]byte(*request.Transaction))
			}
		} else {
			// unknown content type
			continue
		}
		txs = append(txs, tx)
	}

	header, session, err := GenerateSession(account.ID, model.OperationAuth)
	if err != nil {
		return nil, status.InternalServerError, err
	}

	if request.Transaction != nil {
		session.Transaction = *request.Transaction
	}

	if res := app.Db.Create(session); res.Error != nil {
		return nil, status.InternalServerError, status.ErrDb
	}

	authnReq.Header = *header
	authnReq.Challenge = session.Challenge
	authnReq.Transaction = txs

	if qrCode != nil && !app.Config.ConformanceMode {
		qrCode.SessionID = &session.ID
		qrCode.Status = db.QR_CODE_STATUS_SCANNED

		if res := app.Db.Save(*qrCode); res.Error != nil {
			return nil, status.InternalServerError, status.ErrDb
		}
	}

	return &authnReq, status.Ok, nil
}
func PostAuth(response *model.AuthenticationResponse) (status.Status, error) {

	session, fcpHash, s, err := validator.ValidateResponse(response.FcParams, response.Header)
	if err != nil {
		return s, err
	}

	authers, err := validator.ValidateAuthAssertions(response.Assertions, model.AssertionContext{
		AccountId:   session.AccountID,
		FcpHash:     fcpHash,
		Transaction: &session.Transaction,
	})

	if len(authers) == 0 {
		return status.UnacceptableAuthenticator, validator.ErrInvalidSignature
	}

	session.AuthenticatorID = &authers[0].ID
	if res := app.Db.Save(*session); res.Error != nil {
		return status.InternalServerError, status.ErrDb
	}

	qrCode := db.FindQrCodesBySessionId(session.ID)
	if qrCode != nil {
		qrCode.Status = db.QR_CODE_STATUS_USED
		qrCode.UsedAt = &sql.NullTime{Time: time.Now(), Valid: true}
		if res := app.Db.Save(*qrCode); res.Error != nil {
			return status.InternalServerError, status.ErrDb
		}
	} else {
		if !app.Config.ConformanceMode {
			return status.Forbidden, status.ErrInvalidQrCode
		}
	}

	return status.Ok, nil
}
