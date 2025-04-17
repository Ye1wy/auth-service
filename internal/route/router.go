package route

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type router struct {
	router *gin.Engine
}

func NewRouter() *router {
	r := router{
		router: gin.Default(),
	}

	authGroup := r.router.Group("/api/v1")
	{
		authGroup.POST("/register", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"mass": "aboba is registered"}) })
	}

	return &r
}

func (r *router) Run(addr ...string) error {
	return r.router.Run(addr...)
}
