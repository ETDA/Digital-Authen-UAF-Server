package main

import (
	"encoding/gob"
	"math/rand"
	"net/http"
	"time"

	"github.com/etda-uaf/uaf-server/api"
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido"
	"github.com/etda-uaf/uaf-server/openid/openid_connect"
	"github.com/etda-uaf/uaf-server/openid/openid_provider"
	"github.com/etda-uaf/uaf-server/user"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func SetFidoRedirectHeader(c *gin.Context) {
	c.Header("FIDO-AppID-Redirect-Authorized", "true")
	c.Redirect(http.StatusMovedPermanently, "/uafserver/uaf/")
}

func main() {

	rand.Seed(time.Now().Unix())

	// session deserialize
	gob.Register(db.Account{})
	gob.Register(db.QrCode{})

	app.ParseConfig()
	engine := gin.New()
	engine.Use(sessions.Sessions("session", app.Config.SessionStore))

	fido.InitRoute(engine.Group("/uafserver/uaf"))
	openid_connect.Init()
	openid_connect.InitRoute(engine.Group("/uafserver/oidc"))
	openid_provider.InitRoute(engine.Group("/uafserver/oidp"))
	api.InitRoute(engine.Group("/uafserver/api"))
	user.InitRoute(engine.Group("/uafserver/user"))

	engine.Static("/uafserver/static", "static")
	engine.LoadHTMLGlob("templates/*.html")

	engine.GET("/uafserver/uaf", SetFidoRedirectHeader)
	engine.GET("/uafserver/", GetIndex)
	_ = engine.Run(":8080")
	//_ = engine.RunTLS(":443", "./cert/ServerCertificate.crt", "./cert/odb.teda.th.key")

}

func GetIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{})
}
