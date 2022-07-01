package op

import (
	"database/sql"
	"errors"
	"log"
	"time"

	"github.com/etda-uaf/uaf-server/fido/validator"
	"github.com/go-sql-driver/mysql"
	"github.com/jinzhu/copier"

	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/status"
	"github.com/google/uuid"
)

func GetReg(context *model.RegistrationContext, qrCode *db.QrCode) (*model.RegistrationRequest, status.Status, error) {

	account := db.FindAccountByIdentity(context.UserName)
	if account == nil {
		if app.Config.ConformanceMode {
			log.Printf("create account %s for conformance", context.UserName)
			account = &db.Account{
				ID:       uuid.NewString(),
				Identity: context.UserName,
			}

			if res := app.Db.Create(account); res.Error != nil {
				log.Println(res.Error)
				return nil, status.InternalServerError, status.ErrDb
			}
		} else {
			return nil, status.NotFound, status.ErrUserNotFound

		}
	}

	if qrCode != nil && !app.Config.ConformanceMode {
		if qrCode.AccountID != account.ID {
			return nil, status.Forbidden, status.ErrInvalidQrCode
		}
	}

	header, session, err := GenerateSession(account.ID, model.OperationReg)
	if err != nil {
		return nil, status.InternalServerError, err
	}

	var regRequest model.RegistrationRequest
	regRequest.Header = *header
	regRequest.Challenge = session.Challenge
	regRequest.Username = context.UserName

	err = copier.Copy(&regRequest.Policy, &app.Config.Policy)
	if err != nil {
		return nil, status.InternalServerError, errors.New("failed to create policy")
	}

	authenticators := db.GetAuthenticators()
	for _, a := range authenticators {
		disallowedAuthenticator := model.MatchCriteria{}
		if a.KeyId != nil {
			disallowedAuthenticator.KeyIDs = append(disallowedAuthenticator.KeyIDs, model.KeyID(*a.KeyId))
		}
		if a.AAID != nil {
			disallowedAuthenticator.AAID = append(disallowedAuthenticator.AAID, model.AAID(*a.AAID))
		}
		regRequest.Policy.Disallowed = append(regRequest.Policy.Disallowed, disallowedAuthenticator)
	}

	if res := app.Db.Create(session); res.Error != nil {
		return nil, status.InternalServerError, status.ErrDb
	}

	if qrCode != nil && !app.Config.ConformanceMode {
		qrCode.SessionID = &session.ID
		qrCode.Status = db.QR_CODE_STATUS_SCANNED

		if res := app.Db.Save(*qrCode); res.Error != nil {
			return nil, status.InternalServerError, status.ErrDb
		}
	}

	return &regRequest, status.Ok, nil
}

func PostReg(response *model.RegistrationResponse) (status.Status, error) {

	session, fcpHash, s, err := validator.ValidateResponse(response.FcParams, response.Header)
	if err != nil {
		return s, err
	}

	authers, err := validator.ValidateRegAssertions(response.Assertions, model.AssertionContext{FcpHash: fcpHash[:]})
	if err != nil {
		return status.Forbidden, err
	}

	if len(authers) == 0 {
		return status.UnacceptableAuthenticator, nil
	}

	for i := range authers {
		authers[i].ID = uuid.NewString()
		authers[i].AccountID = session.AccountID
		authers[i].Activate = true
		authers[i].RegisteredAt = time.Now()
		authers[i].UsedAt = sql.NullTime{}
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

	find_authtor := db.FindAuthenticatorsByAccount(session.AccountID)

	if find_authtor != nil {

		if len(find_authtor) > 0 {
			if res := app.Db.Delete(find_authtor); res.Error != nil {
				return status.InternalServerError, status.ErrDb
			}
		}
	}

	if res := app.Db.Create(authers); res.Error != nil {
		switch res.Error.(type) {
		case *mysql.MySQLError:
			err := res.Error.(*mysql.MySQLError)
			switch err.Number {
			case 1062:
				return status.UnacceptableAuthenticator, status.ErrDuplicateAuthenticator
			}
		}

		return status.InternalServerError, status.ErrDb
	}

	session.AuthenticatorID = &authers[0].ID
	if res := app.Db.Save(*session); res.Error != nil {
		return status.InternalServerError, status.ErrDb
	}

	return status.Ok, nil
}
