package model

import (
	"github.com/etda-uaf/uaf-server/app"
)

type Account struct {
	ID                string
	Identity          string `json:"username,omitempty"`
	Name              string `json:"name,omitempty"`
	Allow_basic_auth  string `json:"allow_basic_auth,omitempty"`
	Allow_expire_date int64  `json:"allow_expire_date"`
}

func FindAccountById(id string) *Account {
	var acc Account

	if res := app.Db.First(&acc, []string{id}); res.Error != nil {
		return nil
	}
	return &acc
}

func FindAccountByIdentity(identity string) *Account {
	var acc Account

	if res := app.Db.First(&acc, "identity = ?", identity); res.Error != nil {
		return nil
	}
	return &acc
}
