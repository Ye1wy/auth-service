package controller

import (
	"auth-service/internal/mapper"
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
	"auth-service/internal/service"
	"auth-service/pkg/logger"
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthService interface {
	SignUp(ctx context.Context, user domain.User) error
	Login(ctx context.Context, user domain.User) (*domain.Token, error)
	Logout(ctx context.Context) error
	Refresh(ctx context.Context) error
}

type AuthController struct {
	*BaseController
	service   AuthService
	secretKey string
}

func NewAuth(service AuthService, secretKey string, logger *logger.Logger) *AuthController {
	ctrl := NewBaseController(logger)
	return &AuthController{
		ctrl,
		service,
		secretKey,
	}
}

func (ctrl *AuthController) SignUp(c *gin.Context) {
	op := "controller.auth.Register"
	var inputUser dto.Register

	if err := c.ShouldBind(&inputUser); err != nil {
		ctrl.logger.Error("Failed bind data", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"err": "aboba"})
		return
	}

	user := mapper.RegisterToDomain(inputUser)

	err := ctrl.service.SignUp(c.Request.Context(), user)
	if errors.Is(err, service.ErrNoContent) {
		ctrl.logger.Error("No content in all or one+ field input data", "data", user, "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"error": user})
		return
	}
	if err != nil {
		ctrl.logger.Error("Failed in sign up", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusCreated)
	c.Redirect(http.StatusMovedPermanently, "/login")
}

func (ctrl *AuthController) Login(c *gin.Context) {
	op := "controller.auth.Login"
	var inputData dto.LoginRequest

	if err := c.ShouldBind(&inputData); err != nil {
		ctrl.logger.Error("Failed bind data", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"msg": "Invalid payload"})
		return
	}

	mappedData := mapper.LoginToDomain(inputData)

	tokens, err := ctrl.service.Login(c.Request.Context(), mappedData)
	if errors.Is(err, service.ErrIncorrectUsernameOrPassword) {
		ctrl.responce(c, http.StatusUnauthorized, gin.H{"massage": "incorrect payload"})
		return
	}

	if err != nil {
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "server error"})
		return
	}

	ctrl.responce(c, http.StatusOK, tokens)
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

func (ctrl *AuthController) AuthentificateMiddleware(c *gin.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.Request.Header.Get("access_token")
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return ctrl.secretKey, nil
		})

		if err != nil || !token.Valid {
			ctrl.responce(c, http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Next()
	}
}
