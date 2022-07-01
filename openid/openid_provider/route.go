package openid_provider

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	apiModel "github.com/etda-uaf/uaf-server/api/v1/model"
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	fidoModel "github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/op"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

func InitRoute(e *gin.RouterGroup) {
	//e.GET("/authorize", getAuthorize)
	//e.POST("/authorize", PostAuthorize)
	e.GET("/getAuthQrCode", GetAuthorizeQrCode)
	e.POST("/checkFidoStatus", checkFidoStatus)
	e.POST("/setBasicAuth", setBasicAuth)
	//e.GET("/authorize/:identity", GetAuthorizeIdentity)
	//e.POST("/token", getToken)
	//e.GET("/userinfo", getUserInfo)
	//e.GET("/logout", logout)
	//e.GET("/.well-known/oauth-authorization-server", getOAuthMetadata)
	//e.GET("/.well-known/openid-configuration", getOidcMetadata)
}

type GetCredentials struct {
	ClientId    string
	Secret      string
	Transaction string
}

type CheckFidoUser struct {
	Username string `json:"username" binding:"required"`
}

type AllowBasicAuth struct {
	Username string `json:"username" binding:"required"`
}

func setBasicAuth(c *gin.Context) {

	c.Header("Access-Control-Allow-Origin", "*")

	fmt.Println("[info] ---------- Start Set Basic Auth Session() ----------")

	var req GetCredentials

	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		fmt.Println("[error] Basic Authen Failed")
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "Basic Authen Failed"})
		return
	}

	req.ClientId = id
	req.Secret = secret

	oidcClient, err := checkQrAuthorize(req.ClientId, req.Secret)
	if err != nil {

		fmt.Println("[info] ClientId: " + req.ClientId)
		fmt.Println("[info] Secret: " + req.Secret)
		fmt.Println("[error] " + err.Error())

		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": err.Error()})
		return
	}

	if oidcClient == nil {

		fmt.Println("[info] ClientId: " + req.ClientId)
		fmt.Println("[info] Secret: " + req.Secret)
		fmt.Println("[error] invalid client_id or client_secret")

		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "invalid client_id or client_secret"})
		return
	}

	var input AllowBasicAuth

	if err := c.ShouldBindJSON(&input); err != nil {
		fmt.Println("[error] " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "description": "The Input Invalid"})
		return
	}

	identity := input.Username

	account := db.FindAccountByIdentity(identity)

	if account == nil {
		fmt.Println("[error] The Username Invalid")
		c.JSON(http.StatusOK, gin.H{"status": "error", "description": "The Username Invalid"})
		return

	} else {

		timeNow := time.Now().Unix()
		allow_expire_date := account.Allow_expire_date
		if account.Allow_basic_auth == "Y" && timeNow < allow_expire_date {
			fmt.Println("[info] The Username was allowed")
			c.JSON(http.StatusOK, gin.H{"status": "warn", "description": "The Username was allowed", "allow_basic_auth": account.Allow_basic_auth, "allow_expire_unix": account.Allow_expire_date})
			return
		}

		if (account.Allow_basic_auth == "Y" && timeNow > allow_expire_date) || account.Allow_basic_auth == "N" {

			set_expire_time := timeNow + 43200
			if err := app.Db.Model(&db.Account{}).Where("id = ?", account.ID).Update("allow_expire_date", set_expire_time).Update("allow_basic_auth", "Y").Error; err != nil {
				fmt.Println("[error] The Username Invalid")
				c.JSON(http.StatusOK, gin.H{"status": "error", "description": "The Username Invalid"})
				c.Abort()
				return
			}

			account_res := db.FindAccountByIdentity(identity)

			fmt.Println("[info] Basic auth is set for " + identity)
			c.JSON(http.StatusOK, gin.H{"status": "success", "description": "Basic auth is set", "allow_basic_auth": account_res.Allow_basic_auth, "allow_expire_unix": account_res.Allow_expire_date})
			return
		}
	}
}

func checkFidoStatus(c *gin.Context) {

	c.Header("Access-Control-Allow-Origin", "*")

	fmt.Println("[info] ---------- Start Check Fido Status Session() ----------")

	var req GetCredentials

	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		fmt.Println("[error] Basic Authen Failed")
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "Basic Authen Failed"})
		return
	}

	req.ClientId = id
	req.Secret = secret

	oidcClient, err := checkQrAuthorize(req.ClientId, req.Secret)
	if err != nil {

		fmt.Println("[info] ClientId: " + req.ClientId)
		fmt.Println("[info] Secret: " + req.Secret)
		fmt.Println("[error] " + err.Error())

		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": err.Error()})
		return
	}

	if oidcClient == nil {

		fmt.Println("[info] ClientId: " + req.ClientId)
		fmt.Println("[info] Secret: " + req.Secret)
		fmt.Println("[error] invalid client_id or client_secret")

		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "invalid client_id or client_secret"})
		return
	}

	var input CheckFidoUser

	if err := c.ShouldBindJSON(&input); err != nil {
		fmt.Println("[error] The Input Invalid")
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "description": "The Input Invalid"})
		return
	}

	identity := input.Username

	account := db.FindAccountByIdentity(identity)

	if account == nil {
		fmt.Println("[error] The Username Invalid")
		c.JSON(http.StatusOK, gin.H{"status": "error", "description": "The Username Invalid"})
		return

	} else {

		authenticator := db.FindAuthenticatorsByAccountFirst(account.ID)

		if authenticator == nil {
			fmt.Println("[error] The Username Invalid")
			c.JSON(http.StatusOK, gin.H{"status": "error", "description": "The Username Invalid"})
			return
		} else {

			timeNow := time.Now().Unix()
			if account.Allow_basic_auth == "Y" && timeNow > account.Allow_expire_date {

				if err := app.Db.Model(&db.Account{}).Where("id = ?", account.ID).Update("allow_expire_date", 0).Update("allow_basic_auth", "N").Error; err != nil {
					fmt.Println("[error] Update Allow Basic Auth Failed")
					c.JSON(http.StatusOK, gin.H{"status": "error", "description": "Update Allow Basic Auth Failed"})
					c.Abort()
					return
				}

				account_res := db.FindAccountByIdentity(identity)

				fmt.Println("[info] The Username valid")
				c.JSON(http.StatusOK, gin.H{"status": "success", "description": "The Username valid", "allow_basic_auth": account_res.Allow_basic_auth, "allow_expire_unix": account_res.Allow_expire_date})
				return

			} else {
				fmt.Println("[info] The Username valid")
				c.JSON(http.StatusOK, gin.H{"status": "success", "description": "The Username Valid", "allow_basic_auth": account.Allow_basic_auth, "allow_expire_unix": account.Allow_expire_date})
				return
			}
		}
	}
}

func getAuthorize(c *gin.Context) {
	var req AuthorizeRequest
	err := c.BindQuery(&req)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid request")
		return
	}
	if req.ResponseType != "code" {
		c.String(http.StatusBadRequest, "unsupported response_type")
		return
	}
	oidcClient, err := checkAuthorizeRequest(req.ClientId, req.RedirectUri)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	c.HTML(http.StatusOK, "uaf_authorize.html", gin.H{
		"transaction": req.Transaction,
		"clientName":  oidcClient.Name,
	})
}

func PostAuthorize(c *gin.Context) {
	var req PostAuthorizeRequest
	err := c.Bind(&req)

	if err != nil {
		c.String(http.StatusBadRequest, "invalid request")
		return
	}
	qrCode, err := op.ValidateQrCodeToken(req.QrToken)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid qrcode token")
		return
	}

	session := utils.GetSession(c)
	state := session.Get("state")
	redirectUri := session.Get("redirect_uri")
	qrIdSess := session.Get("qrId")

	if qrCode.ID != qrIdSess || redirectUri == nil || redirectUri == "" {
		c.String(http.StatusBadRequest, "invalid request")
		return
	}

	if qrCode.Status != db.QR_CODE_STATUS_USED {
		c.String(http.StatusBadRequest, "invalid qr code state")
		return
	}
	iat := time.Now()
	claims := AuthorizationCodeClaim{
		jwt.StandardClaims{
			IssuedAt:  iat.Unix(),
			Issuer:    app.Config.ServiceName,
			ExpiresAt: iat.Add(app.Config.JwtExpireTime).Unix(),
		},
		qrCode.ID,
		qrCode.Transaction,
		qrCode.OidcClientId,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t, _ := token.SignedString(app.Config.JwtSignKey)

	p := url.Values{}
	p.Add("code", t)
	if state != nil {
		p.Add("state", state.(string))
	}
	c.Redirect(http.StatusFound, fmt.Sprintf("%s?%s", redirectUri.(string), p.Encode()))
}

func GetAuthorizeQrCode(c *gin.Context) {

	c.Header("Access-Control-Allow-Origin", "*")

	fmt.Println("[info] ---------- Start Create QrCode /authen Session() ----------")

	var req GetCredentials

	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		fmt.Println("[error] Basic Authen Failed")
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "Basic Authen Failed"})
		return
	}

	req.ClientId = id
	req.Secret = secret

	oidcClient, err := checkQrAuthorize(req.ClientId, req.Secret)
	if err != nil {

		fmt.Println("[info] ClientId: " + req.ClientId)
		fmt.Println("[info] Secret: " + req.Secret)
		fmt.Println("[error] " + err.Error())

		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": err.Error()})
		return
	}

	if oidcClient == nil {

		fmt.Println("[info] ClientId: " + req.ClientId)
		fmt.Println("[info] Secret: " + req.Secret)
		fmt.Println("[error] invalid client_id or client_secret")

		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "invalid client_id or client_secret"})
		return
	}

	identity := ""
	account_Id := "wating for account_id"
	if req.Transaction == "" {
		req.Transaction = "login"
	}

	request, token, qrCode, err := op.GetFidoRequest_2(account_Id, identity, fidoModel.AuthenticationContext{
		UserName:    identity,
		Transaction: &req.Transaction,
	}, fidoModel.OperationAuth)

	if err != nil {
		fmt.Println("[error] qrcode failed")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "description": "qrcode failed"})
		return
	}

	png, _ := qrcode.Encode(*request, qrcode.Low, 256)

	qrCode.Transaction = req.Transaction
	qrCode.OidcClientId = oidcClient.ClientID

	if res := app.Db.Create(qrCode); res.Error != nil {
		fmt.Println("[error] failed to create qrcode")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "description": "failed to create qrcode"})
		return
	} else {

		fmt.Println("[info] Create QrCode /authen OK")
		c.JSON(http.StatusOK, gin.H{
			"result":      "success",
			"description": "ok",
			"qrcode":      template.URL(fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(png))),
			"qrToken":     token,
		})
		return
	}

}

func checkQrAuthorize(clientId string, secret string) (*db.OidcClient, error) {
	oidcClient := db.FindOidcClient(clientId)
	if oidcClient == nil {
		return nil, errors.New("invalid client_id")
	}
	return oidcClient, nil
}

func GetAuthorizeIdentity(c *gin.Context) {
	session := utils.GetSession(c)
	var req AuthorizeRequest
	err := c.BindQuery(&req)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid request")
		return
	}

	if req.ResponseType != "code" {
		c.String(http.StatusBadRequest, "unsupported response_type")
		return
	}

	oidcClient, err := checkAuthorizeRequest(req.ClientId, req.RedirectUri)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid client_id")
		return
	}

	identity := c.Param("identity")
	account := db.FindAccountByIdentity(identity)
	if account == nil {
		c.HTML(http.StatusBadRequest, "uaf_authorize.html",
			gin.H{
				"error":       "invalid identity",
				"clientName":  oidcClient.Name,
				"transaction": req.Transaction,
			})
		return
	}

	if req.Transaction == "" {
		req.Transaction = "login"
	}

	request, token, qrCode, err := op.GetFidoRequest(account, fidoModel.AuthenticationContext{
		UserName:    account.Identity,
		Transaction: &req.Transaction,
	}, fidoModel.OperationAuth)

	if err != nil {
		c.HTML(http.StatusBadRequest, "uaf_authorize.html",
			gin.H{
				"error":       "qrcode failed",
				"transaction": req.Transaction,
			})
		return
	}

	png, _ := qrcode.Encode(*request, qrcode.Low, 256)

	qrCode.Transaction = req.Transaction
	qrCode.OidcClientId = oidcClient.ClientID

	if res := app.Db.Create(qrCode); res.Error != nil {
		c.String(http.StatusInternalServerError, "failed to create qrcode")
		return
	}

	session.Set("state", req.State)
	session.Set("qrId", qrCode.ID)
	session.Set("redirect_uri", req.RedirectUri)

	_ = session.Save()

	c.HTML(http.StatusOK, "uaf_authorize.html", gin.H{
		"transaction": req.Transaction,
		"clientName":  oidcClient.Name,
		"identity":    identity,
		"qrcode":      template.URL(fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(png))),
		"qrToken":     token,
	})
}

func introspect(c *gin.Context) {

}

func revoke(c *gin.Context) {

}

func logout(c *gin.Context) {

}

func getKeys(c *gin.Context) {

}

func getToken(c *gin.Context) {
	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse("invalid client_id or client_secret"))
		return
	}

	if !checkOidcClient(id, secret) {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse("invalid client_id or client_secret"))
		return
	}

	var req TokenRequest
	err := c.Bind(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, apiModel.GetErrorResponse("invalid request"))
		return
	}

	if req.GrantType != "authorization_code" {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse("unsupported grant_type"))
		return
	}

	token, err := utils.ValidateJwtToken(req.Code, &AuthorizationCodeClaim{})
	if err != nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse("invalid token"))
		return
	}

	oidcClient, err := checkAuthorizeRequest(id, req.RedirectUri)

	if err != nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse("invalid redirect_uri"))
		return
	}

	code := token.Claims.(*AuthorizationCodeClaim)
	if oidcClient.ClientID != code.ClientId {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse("code is not issued by this client_id"))
		return
	}
	qrCode := db.FindQrCodeById(code.QrCodeId)
	if qrCode == nil {
		c.JSON(http.StatusNotFound, apiModel.GetErrorResponse("qr code not found"))
		return
	}
	if qrCode.Status != db.QR_CODE_STATUS_USED {
		c.JSON(http.StatusNotFound, apiModel.GetErrorResponse("qr code expired"))
		return
	}
	qrCode.UsedAt = &sql.NullTime{Time: time.Now(), Valid: true}
	qrCode.Status = db.QR_CODE_STATUS_COMPLETED

	if res := app.Db.Save(*qrCode); res.Error != nil {
		c.JSON(http.StatusInternalServerError, apiModel.GetErrorResponse("failed to update qrcode info"))
		return
	}

	idToken := db.Token{
		ID:        uuid.NewString(),
		AccountID: qrCode.AccountID,
		SessionID: qrCode.SessionID,
		QrCodeID:  qrCode.ID,
		ClientID:  oidcClient.ClientID,
		IssueAt:   time.Now(),
	}

	if res := app.Db.Save(idToken); res.Error != nil {
		c.JSON(http.StatusInternalServerError, apiModel.GetErrorResponse("failed to create token"))
		return
	}

	exp := idToken.IssueAt.Add(app.Config.IdTokenExpireTime).Unix()

	account := db.FindAccountById(qrCode.AccountID)
	claim := TokenClaim{
		jwt.StandardClaims{
			ExpiresAt: exp,
			IssuedAt:  idToken.IssueAt.Unix(),
			Issuer:    app.Config.ServiceName,
		},
		idToken.ID,
		account.Identity,
		qrCode.Transaction,
		oidcClient.ClientID,
	}

	j := jwt.NewWithClaims(jwt.SigningMethodES256, claim)
	t, _ := j.SignedString(app.Config.JwtSignKey)

	c.JSON(http.StatusOK, TokenResponse{
		TokenType:   "access_token",
		ExpiresIn:   exp,
		Scope:       "openid",
		IdToken:     t,
		AccessToken: t,
	})

}

func getUserInfo(c *gin.Context) {
	auth := strings.ReplaceAll(c.Request.Header.Get("Authorization"), "Bearer ", "")
	claim, err := utils.ValidateJwtToken(auth, &TokenClaim{})
	if err != nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse(err.Error()))
		return
	}

	id := claim.Claims.(*TokenClaim).Id
	token := db.FindTokenById(id)
	if token == nil {
		c.JSON(http.StatusForbidden, apiModel.GetErrorResponse("invalid token"))
		return
	}

	account := db.FindAccountById(token.AccountID)
	session := db.FindSessionById(*token.SessionID)

	c.JSON(http.StatusOK, apiModel.GetSuccessResponse(UserInfoResponse{
		Identity:        account.Identity,
		Username:        account.Name,
		Transaction:     session.Transaction,
		AuthenticatorId: *session.AuthenticatorID,
		ClientId:        token.ClientID,
	}))

}

func getOAuthMetadata(c *gin.Context) {

}

func getOidcMetadata(c *gin.Context) {

}

func checkAuthorizeRequest(clientId string, redirectUri string) (*db.OidcClient, error) {
	oidcClient := db.FindOidcClient(clientId)
	if oidcClient == nil {
		return nil, errors.New("invalid client_id")
	}
	if !db.CheckRedirectUri(*oidcClient, redirectUri) {
		return nil, errors.New("invalid redirect_uri")
	}
	return oidcClient, nil
}

func checkOidcClient(id string, secret string) bool {
	if _, err := uuid.Parse(id); err != nil {
		return false
	}
	if _, err := uuid.Parse(secret); err != nil {
		return false
	}
	oidcClient := db.FindOidcClient(id)
	if oidcClient == nil {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(oidcClient.ClientSecretHash), []byte(fmt.Sprintf("%s:%s", id, secret)))
	if err != nil {
		return false
	}
	return true
}
