package httpx

import (
	"fmt"
	"net/http"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/gin-gonic/gin"
)

func APIHAndler(apiPath, apiToken string) http.Handler {
	r := gin.New()

	g := r.Group(apiPath)
	lg().Debug("setting up api handler", "apiPath", apiPath)

	g.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	authRequired := g.Group("/private", AuthRequired(apiToken))
	//authRequired := g.Group("/private")

	authRequired.GET("/interactions", func(c *gin.Context) {

		interactions := model.SortedInteractions(-1)

		c.JSON(http.StatusOK, interactions)
	})

	authRequired.GET("/bots", func(c *gin.Context) {

		bots := model.Bots()

		c.JSON(http.StatusOK, bots)
	})

	return r.Handler()
}

func AuthRequired(apiToken string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if apiToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
		}

		if c.Request.Header.Get("Authorization") != fmt.Sprintf("Token %s", apiToken) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
		}
	}
}
