package httpx

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func APIHAndler(apiPath string) http.Handler {
	r := gin.New()

	g := r.Group(apiPath)
	lg().Debug("setting up api handler", "apiPath", apiPath)

	g.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	return r.Handler()
}
