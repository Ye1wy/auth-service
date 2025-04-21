package repository

import (
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"context"
	"errors"
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

func (r *tokenRepo) GetByUsername(ctx context.Context, username string) (*domain.RefreshToken, error) {
	op := "repository.token.GetByHash"
	query := "SELECT rt.* FROM refresh_tokens rt JOIN users u ON rt.user_id=u.id WHERE u.username=@username"
	args := pgx.NamedArgs{"username": username}

	r.logger.Debug("Check", "username", username)

	var data domain.RefreshToken

	row := r.db.QueryRow(ctx, query, args)
	err := row.Scan(&data.Id, &data.UserId, &data.Hash, &data.ExpiresAt, &data.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		r.logger.Debug("Hash not found", "op", op)
		return nil, ErrRefreshNotFound
	}

	if err != nil {
		r.logger.Debug("failed in scan data from repo", logger.Err(err), "username", username, "op", op)
		return nil, err
	}

	return &data, nil
}

func (r *tokenRepo) GetByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	op := "repository.token.GetByHash"
	query := "SELECT * FROM refresh_tokens WHERE token_hash=@hash"
	args := pgx.NamedArgs{"token_hash": hash}

	r.logger.Debug("Check", "hash", hash)

	var data domain.RefreshToken

	row := r.db.QueryRow(ctx, query, args)
	err := row.Scan(&data.Id, &data.UserId, &data.Hash, &data.ExpiresAt, &data.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		r.logger.Debug("Hash not found", "op", op)
		return nil, ErrRefreshNotFound
	}

	if err != nil {
		r.logger.Debug("failed in scan data from repo", logger.Err(err), "hash", hash, "op", op)
		return nil, err
	}

	return &data, nil
}

func (r *tokenRepo) PinRefreshToken(ctx context.Context, token domain.RefreshToken) error {
	op := "repository.token.Create"
	query := "INSERT INTO refresh_tokens(user_id, token_hash, expire_at, created_at) VALUES (@userId @refreshTokenHash, @expireAt, @createdAt)"
	arg := pgx.NamedArgs{
		"username":         token.UserId,
		"refreshTokenHash": token.Hash,
		"expireAt":         token.ExpiresAt,
		"createdAt":        token.CreatedAt,
	}

	_, err := r.db.Exec(ctx, query, arg)
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
