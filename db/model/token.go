package model

import (
	"time"

	"github.com/etda-uaf/uaf-server/app"
)

type Token struct {
	ID        string
	AccountID string
	ClientID  string
	QrCodeID  string
	SessionID *string
	IssueAt   time.Time
}

func FindTokenById(id string) *Token {
	var t Token
	if res := app.Db.First(&t, []string{id}); res.Error != nil {
		return nil
	}
	return &t
}
