package op

import (
	"database/sql"
	"encoding/base64"
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/status"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/google/uuid"
	"time"
)

func GenerateSession(accountId string, operation model.Operation) (*model.OperationHeader, *db.Session, error) {
	sessionId := uuid.NewString()
	challenge := base64.RawURLEncoding.EncodeToString([]byte(utils.RandomRune(app.Config.ChallengeLength)))
	serverData := model.ServerData{
		ServiceName: app.Config.ServiceName,
		ServiceURL:  app.Config.ServiceUrl,
		Id:          sessionId,
		Challenge:   challenge,
	}

	iat := time.Now()
	exp := time.Now().Add(app.Config.JwtExpireTime)
	token, err := utils.JWTSign(serverData, iat, exp)
	if err != nil {
		return nil, nil, status.ErrTokenFailed
	}

	header := model.OperationHeader{
		// TODO: check here!
		//AppID:      app.Config.UAFEndpoint,
		//AppID:      "apk-key-hash:9vy62sonP/ObQ/mNE1jQLDzDOqs",
		ServerData: token,
		Exts:       nil,
		Op:         operation,
		Upv:        model.UAFV1_1,
	}
	hash := utils.Sha256(*token)
	session := db.Session{
		ID:        sessionId,
		Challenge: challenge,
		AccountID: accountId,
		Hash:      hash,
		Op:        operation,
		CreatedAt: iat,
		ExpireIn: sql.NullTime{
			Time:  exp,
			Valid: true,
		},
		UsedAt: sql.NullTime{},
	}

	return &header, &session, nil
}
