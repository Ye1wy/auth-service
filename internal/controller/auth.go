package controller

import (
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Auth interface {
	Register(c *gin.Context)
}

type auth struct {
	*BaseController
}

func NewAuth(logger *logger.Logger) *auth {
	ctrl := NewBaseController(logger)
	return &auth{
		ctrl,
	}
}

func (a *auth) Register(c *gin.Context) {
	op := "controller.auth.Register"

	var input domain.Register

	if err := a.mapping(c, &input); err != nil {
		a.logger.Debug("Failed bind data", logger.Err(err), "op", op)
		a.responce(c, http.StatusBadRequest, gin.H{"err": "aboba"})
		return
	}

	a.responce(c, http.StatusOK, gin.H{"msg": "aboba"})
}
