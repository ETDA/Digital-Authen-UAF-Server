package hello

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func InitRoute(rg *gin.RouterGroup) {
	rg.GET("/", Hello)
}

func Hello(c *gin.Context) {
	name := c.DefaultQuery("name", "Guest")
	c.String(http.StatusOK, "Hello %s", name)
}
