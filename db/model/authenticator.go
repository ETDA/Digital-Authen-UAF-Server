package model

import (
	"database/sql"
	"time"

	"github.com/etda-uaf/uaf-server/app"
	"gorm.io/gorm"
)

type Authenticator struct {
	ID            string    `json:"id"`
	AccountID     string    `json:"-"`
	Account       Account   `json:"-"`
	AAID          *string   `json:"aaid"`
	KeyId         *string   `json:"-"`
	SignatureAlgo uint16    `json:"sign_algo"`
	PublicKeyAlgo uint16    `json:"pubkey_algo"`
	PublicKey     string    `json:"-"`
	Activate      bool      `json:"activate"`
	RegCounter    uint32    `json:"-"`
	SignCounter   uint32    `json:"-"`
	DeviceName    string    `json:"device_name"`
	DeviceId      string    `json:"-"`
	RegisteredAt  time.Time `json:"register_at"`
	UsedAt        sql.NullTime
}

func FindAuthenticatorById(id string) *Authenticator {
	var authenticator Authenticator

	if res := app.Db.First(&authenticator, []string{id}); res.Error != nil {
		return nil
	}
	return &authenticator
}

func FindAuthenticatorsByAccount(accId string) []Authenticator {
	var authenticator []Authenticator

	if res := app.Db.Find(&authenticator, "account_id = ?", accId); res.Error != nil {
		return nil
	}
	return authenticator
}

func FindAuthenticatorsByAccountFirst(accId string) []Authenticator {
	var authenticator []Authenticator

	if res := app.Db.First(&authenticator, "account_id = ?", accId); res.Error != nil {
		return nil
	}
	return authenticator
}

func FindAuthenticatorsByAccountIdAndKeyId(accId string, keyId string) *Authenticator {
	var authenticator Authenticator
	res := app.Db.First(&authenticator, "`key_id` = ? AND `account_id` = ?", keyId, accId)
	if res.Error != nil {
		return nil
	}
	return &authenticator
}

func FindAuthenticatorsByAAId(accId string, aaId string) []Authenticator {
	var authenticator []Authenticator
	var res *gorm.DB

	if aaId == "" {
		res = app.Db.Find(&authenticator, "account_id = ?", accId)
	} else {
		res = app.Db.Find(&authenticator, "account_id = ? AND aa_id = ?", accId, aaId)
	}
	if res.Error != nil {
		return nil
	}
	return authenticator
}

func GetAuthenticators() []Authenticator {
	var authenticator []Authenticator

	if res := app.Db.Find(&authenticator); res.Error != nil {
		return nil
	}
	return authenticator
}
