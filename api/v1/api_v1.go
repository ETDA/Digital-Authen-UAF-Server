package v1

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	apiModel "github.com/etda-uaf/uaf-server/api/v1/model"
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/op"
	"github.com/etda-uaf/uaf-server/fido/status"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type GetCredentials struct {
	ClientId    string
	Secret      string
	Transaction string
}

func apiKeyRequired(c *gin.Context) {
	key := c.GetHeader("X-API-KEY")
	secret := c.GetHeader("X-API-SECRET")
	ku, err := uuid.Parse(key)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, apiModel.GetErrorResponse("invalid api key"))
		return
	}
	oidcClient := db.FindOidcClient(ku.String())
	if oidcClient == nil {
		c.AbortWithStatusJSON(http.StatusForbidden, apiModel.GetErrorResponse("api key not found"))
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(oidcClient.ClientSecretHash), []byte(fmt.Sprintf("%s:%s", key, secret)))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, apiModel.GetErrorResponse("invalid api secret"))
		return
	}
	c.Set("clientId", key)
}

func InitRoute(e *gin.RouterGroup) {
	e.GET("/uaf/session", GetQrCodeSession)
	e.GET("/uaf/checkQrToken", checkQrToken)
	e.GET("/uaf/authenticators", GetAuthenticators)

	e.Use(apiKeyRequired)
	{
		e.GET("/account/{id}", GetAccountInfo)
		e.POST("/uaf/transact", Transact)
	}

}

func checkQrToken(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")

	var req GetCredentials

	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "Basic Authen Failed"})
		return
	}

	req.ClientId = id
	req.Secret = secret

	oidcClient, err := checkAuthorize(req.ClientId, req.Secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": err.Error()})
		return
	}

	if oidcClient == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "invalid client_id or client_secret"})
		return
	}

	qrToken := c.Query("qrToken")

	if qrToken == "" {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(status.ErrInvalidQrCode.Error()))
		return
	}

	qrCode, err := op.ValidateQrCodeToken(qrToken)
	if err != nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(err.Error()))
		return
	}

	if qrCode == nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(status.ErrInvalidQrCode.Error()))
		return
	}

	if qrCode.Token_used == 1 {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(status.ErrQrTokenUsed.Error()))
		return
	}

	if qrCode.Status == db.QR_CODE_STATUS_USED {

		acc_arr := db.FindAccountById(qrCode.AccountID)
		if acc_arr == nil {
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrInvalidIdentity))
			c.Abort()
			return
		}

		if err := app.Db.Model(&db.QrCode{}).Where("id = ?", qrCode.ID).Update("token_used", 1).Error; err != nil {
			c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(err.Error()))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, apiModel.GetSuccessResponse(
			apiModel.GetSessionResponse{
				Id:       qrCode.ID,
				Status:   qrCode.Status,
				Username: acc_arr.Identity,
			},
		))
		return
	}

	if qrCode.Status == db.QR_CODE_STATUS_EXPIRED {
		c.JSON(http.StatusOK, apiModel.GetErrorResponse("token expired"))
		return
	}

	c.JSON(http.StatusOK, apiModel.GetSuccessResponse(
		apiModel.GetSessionResponse{
			Id:     qrCode.ID,
			Status: qrCode.Status,
		},
	))
}

func GetAuthenticators(c *gin.Context) {

	session := utils.GetSession(c)

	if session.Get("account") == nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse("forbidden"))
		return
	}
	account := session.Get("account").(db.Account)
	auths := db.FindAuthenticatorsByAccount(account.ID)
	c.JSON(http.StatusOK, apiModel.GetSuccessResponse(auths))

}

func GetQrCodeSession(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	qrToken := c.Query("qrToken")

	if qrToken == "" {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(status.ErrInvalidQrCode.Error()))
		return
	}

	qrCode, err := op.ValidateQrCodeToken(qrToken)
	if err != nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(err.Error()))
		return
	}

	if qrCode == nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(status.ErrInvalidQrCode.Error()))
		return
	}

	if qrCode.Token_used == 1 {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(status.ErrQrTokenUsed.Error()))
		return
	}

	if qrCode.Status == db.QR_CODE_STATUS_USED {

		acc_arr := db.FindAccountById(qrCode.AccountID)
		if acc_arr == nil {
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrInvalidIdentity))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, apiModel.GetSuccessResponse(
			apiModel.GetSessionResponse{
				Id:       qrCode.ID,
				Status:   qrCode.Status,
				Username: acc_arr.Identity,
			},
		))
		return
	}

	if qrCode.Status == db.QR_CODE_STATUS_EXPIRED {
		c.JSON(http.StatusOK, apiModel.GetErrorResponse("token expired"))
		return
	}

	c.JSON(http.StatusOK, apiModel.GetSuccessResponse(
		apiModel.GetSessionResponse{
			Id:     qrCode.ID,
			Status: qrCode.Status,
		},
	))
}

func Transact(c *gin.Context) {
	var req apiModel.TransactRequest
	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(err.Error()))
		return
	}

	account := db.FindAccountByIdentity(req.Identity)
	if account == nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(status.ErrUserNotFound.Error()))
		return
	}

	request, token, qrCode, err := op.GetFidoRequest(account, model.AuthenticationContext{
		UserName:    account.Identity,
		Transaction: &req.Transaction,
	}, model.OperationAuth)

	if err != nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(err.Error()))
		return
	}

	clientId, _ := c.Get("clientId")
	qrCode.OidcClientId = clientId.(string)
	qrCode.Transaction = req.Transaction

	res := app.Db.Create(qrCode)
	if res.Error != nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(res.Error.Error()))
		return
	}

	c.JSON(http.StatusOK, apiModel.GetSuccessResponse(apiModel.TransactResponse{
		Token:    *token,
		Request:  *request,
		QrCodeId: qrCode.ID,
	}))
}

func GetAccountInfo(c *gin.Context) {
	id := c.Param("id")
	account := db.FindAccountById(id)
	if account == nil {
		c.JSON(http.StatusNotFound, apiModel.GetErrorResponse("account not found"))
		return
	}
	c.JSON(http.StatusOK, apiModel.GetSuccessResponse(
		apiModel.AccountInfo{
			Account:        *account,
			Authenticators: db.FindAuthenticatorsByAccount(account.ID),
		},
	))
}

func checkAuthorize(clientId string, secret string) (*db.OidcClient, error) {
	oidcClient := db.FindOidcClient(clientId)
	if oidcClient == nil {
		return nil, errors.New("invalid client_id")
	}

	secret_byte := []byte(secret)
	hash_byte := sha256.Sum256(secret_byte)
	secret_hash := string(fmt.Sprintf("%x", hash_byte))

	secret_db := string(oidcClient.ClientSecretHash)
	if secret_db != secret_hash {
		return nil, errors.New("invalid secret")
	}
	return oidcClient, nil
}
