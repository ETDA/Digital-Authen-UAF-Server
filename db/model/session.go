package model

import (
	"database/sql"
	"time"

	"github.com/etda-uaf/uaf-server/app"
	"github.com/etda-uaf/uaf-server/fido/model"
)

type Session struct {
	ID              string
	AccountID       string
	Account         Account
	Challenge       string
	Authenticator   *Authenticator
	AuthenticatorID *string
	Transaction     string
	Hash            string
	Op              model.Operation
	CreatedAt       time.Time
	ExpireIn        sql.NullTime
	UsedAt          sql.NullTime
}

func FindSessionById(sid string) *Session {
	var sess Session
	if res := app.Db.First(&sess, []string{sid}); res.Error != nil {
		return nil
	}
	return &sess
}
