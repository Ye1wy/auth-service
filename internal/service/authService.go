package service

import (
	mailer "auth-service/internal/mail"
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenWrite interface {
	PinRefreshToken(ctx context.Context, token domain.RefreshToken) error
	Delete(ctx context.Context, token domain.RefreshToken) error
}

type TokenRead interface {
	GetByUsername(ctx context.Context, username string) ([]domain.RefreshToken, error)
}

type UserRead interface {
	GetByUsername(ctx context.Context, username string) (*domain.User, error)
	GetById(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

type UserWrite interface {
	Create(ctx context.Context, user domain.User) error
}

type authService struct {
	tokenWriter TokenWrite
	tokenReader TokenRead
	userWriter  UserWrite
	userReader  UserRead
	diller      mailer.Mailer
	logger      *logger.Logger
	secretKey   string
}

func NewAuthService(tokenW TokenWrite, tokenR TokenRead, userR UserRead, userW UserWrite, mailer mailer.Mailer, logger *logger.Logger, secretKey string) *authService {
	return &authService{
		tokenWriter: tokenW,
		tokenReader: tokenR,
		userWriter:  userW,
		userReader:  userR,
		diller:      mailer,
		logger:      logger,
		secretKey:   secretKey,
	}
}

func (s *authService) SignUp(ctx context.Context, user domain.User) error {
	op := "service.authService.SignUp"

	if user.Username == "" || user.Password == "" || user.Email == "" {
		s.logger.Debug("domain user is empty", "op", op)
		return ErrNoContent
	}

	cryptPassword, err := s.hashPassword(user.Password)
	if err != nil {
		return err
	}

	user.Password = cryptPassword

	if err := s.userWriter.Create(ctx, user); err != nil {
		s.logger.Debug("Creating error", logger.Err(err), "op", op)
		return err
	}

	return nil
}

func (s *authService) Login(ctx context.Context, user domain.User) (*domain.Token, error) {
	op := "service.authService.Login"

	check, err := s.userReader.GetByUsername(ctx, user.Username)
	if err != nil {
		return nil, fmt.Errorf("Auth Service: Error to get check data %v", err)
	}

	s.logger.Debug("data from user repo", "username", check.Username, "password", check.Password, "op", op)

	if user.Username != check.Username {
		return nil, ErrIncorrectUsernameOrPassword
	}

	err = bcrypt.CompareHashAndPassword([]byte(check.Password), []byte(user.Password))
	if err != nil {
		return nil, ErrIncorrectUsernameOrPassword
	}

	access, err := s.genereateAccessToken(user.Username, user.Ip)
	if err != nil {
		s.logger.Debug("access token not signed", logger.Err(err), "op", op)
		return nil, err
	}

	refresh, err := s.generateRefreshToken(check.Id)
	if err != nil {
		s.logger.Debug("Error on generate refresh token", logger.Err(err), "op", op)
		return nil, err
	}

	tokens := domain.Token{
		Access:  access,
		Refresh: refresh.Refresh,
	}

	s.logger.Debug("params", "check user", check.Username, "username", user.Username, "a", access, "r", refresh)

	if err := s.tokenWriter.PinRefreshToken(ctx, *refresh); err != nil {
		s.logger.Debug("Repository error", logger.Err(err), "op", op)
		return nil, err
	}

	return &tokens, nil
}

func (s *authService) Logout(ctx context.Context, token domain.Token) error {
	op := "service.authService.Logout"
	jwtMap, ok := s.getFromToken(token.Access)
	if !ok {
		return ErrInvalidToken
	}

	username := jwtMap["username"].(string)

	dbToken, err := s.tokenReader.GetByUsername(ctx, username)
	if err != nil {
		s.logger.Debug("Failed to get refresh token from database", logger.Err(err), "op", op)
		return err
	}

	var target domain.RefreshToken
	found := false

	for _, item := range dbToken {
		err := bcrypt.CompareHashAndPassword([]byte(item.Hash), []byte(token.Refresh))
		if err == nil {
			found = true
			target = item
		}
	}

	if !found {
		s.logger.Debug("hash not found", "op", op)
		return ErrNoContent
	}

	if err := s.tokenWriter.Delete(ctx, target); err != nil {
		s.logger.Debug("Failed delete refresh token from database", logger.Err(err), "op", op)
		return err
	}

	return nil
}

func (s *authService) Refresh(ctx context.Context, token domain.Token) (*domain.Token, error) {
	op := "service.authService.Refresh"
	jwtMap, ok := s.getFromToken(token.Access)
	if !ok {
		s.logger.Debug("Failed to get target username from JWT token payload", "op", op)
		return nil, ErrInvalidToken
	}

	username := jwtMap["username"].(string)
	s.logger.Debug("Check username", "username", username, "op", op)

	dbToken, err := s.tokenReader.GetByUsername(ctx, username)
	if err != nil {
		s.logger.Debug("Failed to get refresh token from database", logger.Err(err), "op", op)
		return nil, err
	}

	var target domain.RefreshToken
	found := false

	for _, item := range dbToken {
		err := bcrypt.CompareHashAndPassword([]byte(item.Refresh), []byte(token.Refresh))
		if err == nil {
			found = true
			target = item
		}
	}

	if !found {
		s.logger.Debug("hash not found", "op", op)
		return nil, ErrNoContent
	}

	diff := time.Now().Compare(target.ExpiresAt)
	if diff > 0 {
		return nil, ErrRefreshIsExpired
	}

	ip := jwtMap["ip"].(string)
	s.logger.Debug("Check ip", "ip", ip, "op", op)

	if ip != token.Ip {
		if err := s.tokenWriter.Delete(ctx, target); err != nil {
			return nil, err
		}

		user, err := s.userReader.GetById(ctx, target.UserId)
		if err != nil {
			return nil, err
		}

		if err := s.diller.SandText(user.Email, "Warning", "Your ip is change"); err != nil {
			return nil, err
		}

		return nil, ErrNewIp
	}

	access, err := s.genereateAccessToken(username, token.Ip)
	if err != nil {
		return nil, err
	}

	res := domain.Token{
		Ip:      token.Ip,
		Access:  access,
		Refresh: token.Refresh,
	}

	return &res, nil
}

func (s *authService) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func (s *authService) genereateAccessToken(username, ip string) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"ip":       ip,
		"exp":      time.Now().Add(time.Minute * 15).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(s.secretKey))
	if err != nil {
		return "", err
	}

	return accessTokenString, nil
}

func (s *authService) generateRefreshToken(userId uuid.UUID) (*domain.RefreshToken, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}

	refresh := base64.URLEncoding.EncodeToString(token)

	hash, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	res := domain.RefreshToken{
		UserId:    userId,
		Refresh:   refresh,
		Hash:      string(hash),
		ExpiresAt: time.Now().Add(time.Hour * 7),
		CreatedAt: time.Now(),
	}

	return &res, nil
}

func (s *authService) getFromToken(tokenStr string) (jwt.MapClaims, bool) {
	secret := []byte(s.secretKey)
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, http.ErrAbortHandler
		}
		return secret, nil
	})

	if err != nil {
		s.logger.Debug("error in get from token", logger.Err(err))
		return nil, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	}

	s.logger.Debug("Invalid JWT token")
	return nil, false
}
