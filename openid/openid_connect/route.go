package openid_connect

import (
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func InitRoute(e *gin.RouterGroup) {
	e.GET("/login", GetLogin)
	e.GET("/callback", GetCallback)
}

func GetLogin(c *gin.Context) {
	url, state := GetLoginUrl()
	session := utils.GetSession(c)
	session.Set("oidc_state", state)
	_ = session.Save()
	c.Redirect(http.StatusFound, url)
}

func GetCallback(c *gin.Context) {
	session := utils.GetSession(c)
	sessState := session.Get("oidc_state")
	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" || sessState == nil || sessState == "" {
		c.String(http.StatusBadRequest, "invalid request")
		return
	}

	if sessState != state {
		c.String(http.StatusForbidden, "invalid state")
		return
	}

	session.Delete("state")

	token, _, err := Exchange(code)
	if err != nil {
		c.String(http.StatusForbidden, "failed to get token from provider: "+err.Error())
		return
	}

	i, n, err := GetUserInfo(*token)
	if err != nil {
		c.String(http.StatusForbidden, "failed to get token from provider: "+err.Error())
		return
	}
	session.Set("identity", *i)
	session.Set("name", *n)

	account := db.FindAccountByIdentity(*i)

	if account == nil {
		session.Delete("redirect")
		_ = session.Save()
		c.Redirect(http.StatusFound, "/user/register")
		return
	}

	session.Set("account", *account)
	redirect := session.Get("redirect")

	if redirect == nil {
		_ = session.Save()
		c.Redirect(http.StatusFound, "/user/dashboard")
		return
	}
	session.Delete("redirect")
	_ = session.Save()
	c.Redirect(http.StatusFound, redirect.(string))
}
