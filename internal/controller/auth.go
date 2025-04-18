package controller

import (
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
	"auth-service/pkg/logger"
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthService interface {
	SignUp(ctx context.Context, user domain.User) error
	Login(ctx context.Context, user domain.User) error
	Logout(ctx context.Context) error
	Refresh(ctx context.Context) error
}

type AuthController struct {
	*BaseController
	service AuthService
}

func NewAuth(service AuthService, logger *logger.Logger) *AuthController {
	ctrl := NewBaseController(logger)
	return &AuthController{
		ctrl,
		service,
	}
}

func (ctrl *AuthController) SignUp(c *gin.Context) {
	op := "controller.auth.Register"
	var user domain.User

	if err := c.ShouldBind(&user); err != nil {
		ctrl.logger.Error("Failed bind data", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"err": "aboba"})
		return
	}

	if err := ctrl.service.SignUp(c.Request.Context(), user); err != nil {
		ctrl.logger.Error("Failed in sign up", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctrl.responce(c, http.StatusCreated, user)
}

func (ctrl *AuthController) Login(c *gin.Context) {
	op := "controller.auth.Login"
	var data dto.LoginRequest

	if err := c.ShouldBind(&data); err != nil {
		ctrl.logger.Error("Failed bind data", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"msg": "Invalid payload"})
		return
	}

	if err := ctrl.service.Login(c.Request.Context(), domain.User{}); err != nil {
		return
	}

	ctrl.responce(c, http.StatusOK, gin.H{"msg": "in system"})
}

func (ctrl *AuthController) Logout(c *gin.Context) {
	// op := "controller.auth.Logout"

	ctrl.responce(c, http.StatusResetContent, gin.H{})
}

func (ctrl *AuthController) Refresh(c *gin.Context) {
	op := "controller.auth.Refresh"
	refresh := c.GetHeader("refresh_token")
	if refresh == "" {
		ctrl.logger.Warn("No refresh token", "op", op)
		ctrl.responce(c, http.StatusUnauthorized, gin.H{"error": "no needed cookie"})
		return
	}

	ctrl.responce(c, http.StatusOK, "aboba")
}
