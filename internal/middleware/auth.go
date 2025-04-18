package middleware

import (
	"auth-service/internal/token"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthentificateMiddleware(c *gin.Context) {
	tokenStr := c.Request.Header.Get("access_token")
	_, err := token.VerifyToken(tokenStr, "aboba")
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}

	c.Next()
}
