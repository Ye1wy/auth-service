package repository

import (
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type tokenRepo struct {
	*baseRepo
}

func NewTokenRepo(db *pgxpool.Pool, logger *logger.Logger) *tokenRepo {
	baseRepo := NewBaseRepo(db, logger)
	return &tokenRepo{
		baseRepo: baseRepo,
	}
}

func (r *tokenRepo) AddInBanList(ctx context.Context, token domain.Token) error {
	op := "repository.token.Create"
	query := "INSERT INTO token_ban VALUES (@token)"
	arg := pgx.NamedArgs{"token": token.Refresh}

	_, err := r.db.Exec(ctx, query, arg)
	if err != nil {
		r.logger.Debug("can't add refresh token in to ban list", logger.Err(err), "op", op)
		return fmt.Errorf("Token Repo: %v", err)
	}

	return nil
}
