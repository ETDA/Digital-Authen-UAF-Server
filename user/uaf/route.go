package uaf

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	fidoModel "github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/op"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
)

type CreateUser struct {
	Identity string `json:"identity" binding:"required"`
	Name     string `json:"name" binding:"required"`
}

type GetCredentials struct {
	ClientId    string
	Secret      string
	Transaction string
}

func loginRequired(c *gin.Context) {
	session := utils.GetSession(c)
	if session.Get("account") == nil {
		//c.Redirect(http.StatusFound, "/oidc/login")
		//c.Abort()
		return
	}
}

func InitRoute(e *gin.RouterGroup) {
	e.POST("/register", loginRequired, PostUAFRegister)
}

func PostUAFRegister(c *gin.Context) {

	c.Header("Access-Control-Allow-Origin", "*")

	fmt.Println("[info] ---------- Start Create QrCode /register Session() ----------")

	var crede GetCredentials

	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		fmt.Println("[error] Basic Authen Failed")
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "Basic Authen Failed"})
		return
	}

	crede.ClientId = id
	crede.Secret = secret

	oidcClient, err := checkAuthorize(crede.ClientId, crede.Secret)
	if err != nil {
		fmt.Println("[info] ClientId: " + crede.ClientId)
		fmt.Println("[info] Secret: " + crede.Secret)
		fmt.Println("[error] " + err.Error())

		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": err.Error()})
		return
	}

	if oidcClient == nil {

		fmt.Println("[info] ClientId: " + crede.ClientId)
		fmt.Println("[info] Secret: " + crede.Secret)
		fmt.Println("[error] invalid client_id or client_secret")

		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "invalid client_id or client_secret"})
		return
	}

	var input CreateUser

	if err := c.ShouldBindJSON(&input); err != nil {
		fmt.Println("[error] " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "description": err.Error()})
		return
	}

	identity := input.Identity

	account := db.FindAccountByIdentity(identity)

	req := fidoModel.RegistrationContext{UserName: account.Identity}

	// kill old qr codes
	oldQrCodes := db.FindNewQrCodesByAccount(account.ID)
	if len(oldQrCodes) > 0 {
		for i := 0; i < len(oldQrCodes); i++ {
			oldQrCodes[i].Status = db.QR_CODE_STATUS_EXPIRED
		}
		app.Db.Save(oldQrCodes)
	}

	json, qrToken, qrCode, err := op.GetFidoRequest(account, req, fidoModel.OperationReg)

	if err != nil {
		fmt.Println("[error] failed to generate qr code")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "description": "failed to generate qr code"})
		return
	}

	qrCode.Transaction = "register"

	if res := app.Db.Create(*qrCode); res.Error != nil {
		fmt.Println("[error] failed to update qr code")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "description": "failed to update qr code"})
		return

	} else {

		fmt.Println("[info] Create QrCode /register OK")

		png, _ := qrcode.Encode(*json, qrcode.Low, 256)

		c.JSON(http.StatusOK, gin.H{
			"qrcode":  template.URL(fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(png))),
			"qrToken": *qrToken,
		})
		return
	}
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
