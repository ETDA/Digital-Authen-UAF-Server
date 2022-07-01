package model

import (
	"database/sql"
	"time"

	"github.com/etda-uaf/uaf-server/app"
)

const (
	QR_CODE_STATUS_NEW       = "new"
	QR_CODE_STATUS_SCANNED   = "scanned"
	QR_CODE_STATUS_USED      = "used"
	QR_CODE_STATUS_COMPLETED = "completed"
	QR_CODE_STATUS_EXPIRED   = "expired"
)

type QrCode struct {
	ID           string
	Op           string
	AccountID    string
	Account      Account
	SessionID    *string
	Session      Account
	CreatedAt    time.Time
	UsedAt       *sql.NullTime
	Status       string
	OidcClientId string
	Transaction  string
	Token_used   int
}

func FindQrCodeById(qrId string) *QrCode {
	var qrCode QrCode

	if res := app.Db.First(&qrCode, "id = ?", qrId); res.Error != nil {
		return nil
	}
	return &qrCode
}

func FindQrCodesByAccount(accountId string) []QrCode {
	var qrCodes []QrCode
	res := app.Db.Find(&qrCodes, "account_id = ?", accountId)
	if res.Error != nil {
		return nil
	}
	return qrCodes
}

func FindQrCodesBySessionId(sessionId string) *QrCode {
	var qrCode QrCode
	res := app.Db.First(&qrCode, "session_id = ?", sessionId)
	if res.Error != nil {
		return nil
	}
	return &qrCode
}

func FindNewQrCodesByAccount(accountId string) []QrCode {
	var qrCodes []QrCode
	res := app.Db.First(&qrCodes, "account_id = ? AND status = ?", accountId, QR_CODE_STATUS_NEW)
	if res.Error != nil {
		return nil
	}
	return qrCodes
}
