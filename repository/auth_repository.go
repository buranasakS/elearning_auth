package repository

import (
	"context"
	db "elearning/db/sqlc"

	"github.com/redis/go-redis/v9"
	"github.com/jackc/pgx/v5/pgtype"
)

type AuthRepository struct {
	db db.Querier
	redisClient *redis.Client
}

func NewAuthRepository(db db.Querier, redisClient *redis.Client) *AuthRepository {
	return &AuthRepository{db: db, redisClient: redisClient}
}

func (r *AuthRepository) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	return r.db.CreateUser(ctx, arg)
}

func (r *AuthRepository) CheckEmailExists(ctx context.Context, email string) (db.CheckEmailExistsRow, error) {
	return r.db.CheckEmailExists(ctx, email)
}

func (r *AuthRepository) GetUserByID(ctx context.Context, id pgtype.UUID) (db.GetUserDetailRow, error) {
	return r.db.GetUserDetail(ctx, id)
}

func (r *AuthRepository) GetUserForLogin(ctx context.Context, email string) (db.GetUserForLoginRow, error) {
	return r.db.GetUserForLogin(ctx, email)
}
