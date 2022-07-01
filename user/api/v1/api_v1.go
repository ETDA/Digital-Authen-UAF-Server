package v1

import (
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
	e.GET("/uaf/authenticators", GetAuthenticators)

	e.Use(apiKeyRequired)
	{
		e.GET("/account/{id}", GetAccountInfo)
		e.POST("/uaf/transact", Transact)
	}

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

	if qrCode.Status == db.QR_CODE_STATUS_USED {
		c.JSON(http.StatusOK, apiModel.GetSuccessResponse(
			apiModel.GetSessionResponse{
				Id:     qrCode.ID,
				Status: qrCode.Status,
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
