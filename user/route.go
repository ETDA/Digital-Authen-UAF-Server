package user

import (
	"net/http"

	"github.com/etda-uaf/uaf-server/user/uaf"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func loginRequired(c *gin.Context) {
	session := utils.GetSession(c)
	if session.Get("account") == nil {
		session.Set("redirect", c.Request.RequestURI)
		_ = session.Save()
		c.Redirect(http.StatusFound, "/oidc/login")
		c.Abort()
		return
	}
}

func InitRoute(e *gin.RouterGroup) {
	e.GET("/dashboard", loginRequired, GetDashboard)
	e.GET("/register", GetRegister)
	e.GET("/logout", GetLogout)
	e.POST("/register", PostRegister)
	uaf.InitRoute(e.Group("/uaf"))
}

func GetDashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{})
}
func GetLogout(c *gin.Context) {
	session := utils.GetSession(c)
	session.Set("account", "")
	session.Set("name", "")
	session.Set("identity", "")
	session.Clear()
	session.Options(sessions.Options{Path: "/uafserver", MaxAge: -1})
	_ = session.Save()
	c.HTML(http.StatusOK, "redirect.html", gin.H{"redirect": "/uafserver"})
}
