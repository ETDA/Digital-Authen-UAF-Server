package user

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

func GetRegister(c *gin.Context) {
	session := utils.GetSession(c)
	identity := session.Get("identity")
	name := session.Get("name")
	if identity == nil || name == nil || identity == "" || name == "" {
		c.Redirect(http.StatusFound, "/oidc/login")
		return
	}

	if db.FindAccountByIdentity(identity.(string)) != nil {
		c.Redirect(http.StatusFound, "/user/dashboard")
		return
	}

	c.HTML(http.StatusOK, "register.html", gin.H{
		"name":     name.(string),
		"identity": identity.(string),
	})
}

func PostRegister(c *gin.Context) {

	c.Header("Access-Control-Allow-Origin", "*")

	fmt.Println("[info] ---------- Start Create Account Session() ----------")

	var req GetCredentials

	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		fmt.Println("[error] Basic Authen Failed")
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "description": "Basic Authen Failed"})
		return
	}

	req.ClientId = id
	req.Secret = secret

	oidcClient, err := checkAuthorize(req.ClientId, req.Secret)
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

	fmt.Println("[info] Authorization OK")

	var input CreateUser

	if err := c.ShouldBindJSON(&input); err != nil {
		fmt.Println("[error] " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	identity := input.Identity
	name := input.Name

	fmt.Println("[info] Username: " + identity)

	account := db.FindAccountByIdentity(identity)

	if account == nil {

		account := db.Account{
			ID:               uuid.NewString(),
			Identity:         identity,
			Name:             name,
			Allow_basic_auth: "N",
		}

		if res := app.Db.Create(account); res.Error != nil {
			fmt.Println("[error] failed to create new user")
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "description": "failed to create new user"})
			return
		}
		fmt.Println("[info] Add " + identity + " to Accounts success")
		c.JSON(http.StatusOK, gin.H{"status": "success", "description": "Add " + identity + " to Accounts success"})
		return

	} else {
		fmt.Println("[info] " + identity + " Already in Accounts")
		c.JSON(http.StatusOK, gin.H{"status": "success", "description": identity + " Already in Accounts"})
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
