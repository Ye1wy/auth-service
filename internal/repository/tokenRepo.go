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

func (r *tokenRepo) GetByUsername(ctx context.Context, username string) ([]domain.RefreshToken, error) {
	op := "repository.token.GetByUsername"
	query := "SELECT rt.* FROM refresh_tokens rt JOIN users u ON rt.user_id=u.id WHERE u.username=@username"
	args := pgx.NamedArgs{"username": username}

	r.logger.Debug("Check", "username", username, "op", op)

	var datas []domain.RefreshToken

	rows, err := r.db.Query(ctx, query, args)
	if err != nil {
		r.logger.Debug("Query error", logger.Err(err), "op", op)
		return nil, fmt.Errorf("token repo: failed exec query %v", err)
	}

	for rows.Next() {
		var data domain.RefreshToken

		err := rows.Scan(&data.Id, &data.UserId, &data.Hash, &data.ExpiresAt, &data.CreatedAt)
		if err != nil {
			r.logger.Debug("Failed binding data", logger.Err(err), "op", op)
			continue
		}

		datas = append(datas, data)
	}

	if len(datas) == 0 {
		r.logger.Debug("failed in scan data from repo", logger.Err(err), "username", username, "op", op)
		return nil, ErrRefreshNotFound
	}

	return datas, nil
}

func (r *tokenRepo) PinRefreshToken(ctx context.Context, token domain.RefreshToken) error {
	op := "repository.token.PinRefreshToken"
	query := "INSERT INTO refresh_tokens(user_id, token_hash, expire_at, created_at) VALUES (@userId, @refreshTokenHash, @expireAt, @createdAt)"
	args := pgx.NamedArgs{
		"userId":           token.UserId,
		"refreshTokenHash": token.Hash,
		"expireAt":         token.ExpiresAt,
		"createdAt":        token.CreatedAt,
	}

	_, err := r.db.Exec(ctx, query, args)
	if err != nil {
		r.logger.Debug("can't add refresh token in to ban list", logger.Err(err), "op", op)
		return fmt.Errorf("Token Repo: %v", err)
	}

	return nil
}

func (r *tokenRepo) Delete(ctx context.Context, token domain.RefreshToken) error {
	op := "repository.token.Delete"
	query := "DELETE FROM refresh_tokens WHERE id=@id AND token_hash=@hash"
	args := pgx.NamedArgs{
		"id":   token.Id,
		"hash": token.Hash,
	}

	_, err := r.db.Exec(ctx, query, args)
	if err != nil {
		r.logger.Debug("Somthing wrong", logger.Err(err), "op", op)
		return err
	}

	return nil
}
