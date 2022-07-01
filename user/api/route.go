package api

import (
	v1 "github.com/etda-uaf/uaf-server/api/v1"
	"github.com/gin-gonic/gin"
)

func InitRoute(e *gin.RouterGroup) {
	v1.InitRoute(e.Group("/v1"))
}
