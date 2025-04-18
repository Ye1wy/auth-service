package service

import (
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"context"

	"github.com/google/uuid"
)

type TokenWrite interface {
	AddInBanList(c context.Context, refreshToken domain.Token) error
	Update(c context.Context) error
}

type TokenRead interface {
	GetRefresh(c context.Context, token string) (bool, error)
}

type UserRead interface {
	GetById(c context.Context, id uuid.UUID) (*domain.User, error)
}

type UserWrite interface {
	Create(c context.Context, user domain.User) error
}

type authService struct {
	tokenWriter TokenWrite
	tokenReader TokenRead
	userWriter  UserWrite
	userReader  UserRead
	logger      *logger.Logger
}

func NewAuthService(tokenW TokenWrite, tokenR TokenRead, userR UserRead, userW UserWrite, logger *logger.Logger) *authService {
	return &authService{
		tokenWriter: tokenW,
		tokenReader: tokenR,
		userWriter:  userW,
		userReader:  userR,
		logger:      logger,
	}
}

func (s *authService) SignUp(ctx context.Context, user domain.User) error {
	return nil
}

func (s *authService) Login(ctx context.Context, user domain.User) error {
	return nil
}

func (s *authService) Logout(ctx context.Context) error {
	return nil
}

func (s *authService) Refresh(ctx context.Context) error {
	return nil
}
