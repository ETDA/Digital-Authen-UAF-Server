package op

import (
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/status"
)

func GetDereg(context *model.DeregistrationContext) (*model.DeregistrationRequest, status.Status, error) {
	account := db.FindAccountByIdentity(context.UserName)
	if account == nil {
		return nil, status.NotFound, status.ErrUserNotFound
	}

	authenticators := db.FindAuthenticatorsByAccount(account.ID)
	if len(authenticators) == 0 {
		return nil, status.UnacceptableContent, status.ErrUserNotFound
	}

	var deregAuths []model.DeregistrationAuthenticator

	if !context.DeregisterAll {

		authenticators = db.FindAuthenticatorsByAAId(account.ID, context.DeregisterAAID)
		for i := 0; i < len(authenticators); i++ {
			a := &authenticators[i]
			a.Activate = false
			if context.DeregisterAAID == "" {
				deregAuths = append(deregAuths, model.DeregistrationAuthenticator{Aaid: *a.AAID, KeyID: *a.KeyId})
			} else {
				deregAuths = append(deregAuths, model.DeregistrationAuthenticator{Aaid: *a.AAID})
			}
		}
	} else {
		authenticators = db.FindAuthenticatorsByAAId(account.ID, context.DeregisterAAID)
		for i := 0; i < len(authenticators); i++ {
			a := &authenticators[i]
			a.Activate = false
			deregAuths = append(deregAuths, model.DeregistrationAuthenticator{})
		}
	}

	if res := app.Db.Save(authenticators); res.Error != nil {
		return nil, status.BadRequest, status.ErrDb
	}
	return &model.DeregistrationRequest{
		Authenticators: deregAuths,
		Header: model.OperationHeader{
			AppID: app.Config.UAFEndpoint,
			Upv:   model.UAFV1_1,
			Op:    model.OperationDereg,
		},
	}, status.Ok, nil
}
