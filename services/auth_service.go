package services

import (
	"context"
	db "elearning/db/sqlc"
	"elearning/repository"
	"elearning/utils"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var (
	ErrInvalidCredentials  = errors.New("invalid email or password")
	ErrUserNotFound        = errors.New("user not found")
	ErrEmailAlreadyExists  = errors.New("email already exists")
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenInvalid        = errors.New("token is invalid")
	ErrInternalError       = errors.New("internal server error")
	ErrPasswordHash        = errors.New("failed to hash password")
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid or revoked")
)

type TokenType string

const (
	AccessToken  TokenType = "access_token"
	RefreshToken TokenType = "refresh_token"
)

type AuthConfig struct {
	ACCESS_SECRET            string
	REFRESH_SECRET           string
	AccessTokenDuration      time.Duration
	RefreshTokenDuration     time.Duration
	InvalidatePreviousTokens bool
}

type TokenClaims struct {
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	TokenType TokenType `json:"token_type"`
	UserID    string    `json:"user_id"`
	jwt.StandardClaims
}

func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		AccessTokenDuration:      10 * time.Minute,
		RefreshTokenDuration:     30 * time.Minute,
		InvalidatePreviousTokens: true,
	}
}

func NewAuthService(repo *repository.AuthRepository, accessSecret, refreshSecret string, redisClient *redis.Client) *AuthService {
	config := DefaultAuthConfig()
	config.ACCESS_SECRET = accessSecret
	config.REFRESH_SECRET = refreshSecret

	return &AuthService{
		repo:        repo,
		config:      config,
		redisClient: redisClient,
	}
}

type AuthService struct {
	repo        *repository.AuthRepository
	config      AuthConfig
	redisClient *redis.Client
}

func (s *AuthService) RegisterUser(ctx context.Context, req *db.CreateUserParams) (*db.User, error) {
	existingUser, err := s.repo.CheckEmailExists(ctx, req.Email)
	if err == nil && existingUser.ID.Valid {
		return nil, ErrEmailAlreadyExists
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, ErrPasswordHash
	}

	user, err := s.repo.CreateUser(ctx, db.CreateUserParams{
		Fullname: req.Fullname,
		Email:    req.Email,
		Password: hashedPassword,
		Role:     req.Role,
	})

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *AuthService) LoginUser(ctx context.Context, email, password string) (string, string, error) {
	user, err := s.repo.GetUserForLogin(ctx, email)
	if err != nil {
		return "", "", ErrUserNotFound
	}

	err = utils.ComparePassword(user.Password, password)
	if err != nil {
		return "", "", ErrInvalidCredentials
	}

	accessToken, err := s.generateAccessToken(user, AccessToken, s.config.AccessTokenDuration)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshTokenID := uuid.New().String()
	refreshToken, err := s.generateRefreshToken(user, refreshTokenID, s.config.RefreshTokenDuration)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate JWT token: %w", err)
	}

	err = s.redisClient.Set(ctx, "refreshToken:"+user.ID.String(), refreshToken, s.config.RefreshTokenDuration).Err()
	if err != nil {
		return "", "", fmt.Errorf("failed to store refresh token in Redis: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", err
	}

	email, ok := (*claims)["email"].(string)
	if !ok {
		return "", ErrTokenInvalid
	}

	user, err := s.repo.GetUserForLogin(ctx, email)
	if err != nil {
		return "", err
	}

	storedToken, err := s.redisClient.Get(ctx, "refreshToken:"+user.ID.String()).Result()
	if err != nil {
		return "", ErrRefreshTokenInvalid
	}

	if storedToken != refreshToken {
		return "", ErrRefreshTokenInvalid
	}

	newAccessToken, err := s.generateAccessToken(user, AccessToken, s.config.AccessTokenDuration)
	if err != nil {
		return "", err
	}

	return newAccessToken, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return err
	}

	userID, ok := (*claims)["user_id"].(string)
	if !ok {
		return ErrTokenInvalid
	}

	err = s.redisClient.Del(ctx, "refreshToken:"+userID).Err()
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

func (s *AuthService) generateAccessToken(user db.GetUserForLoginRow, tokenType TokenType, duration time.Duration) (string, error) {
	now := time.Now()
	expiry := now.Add(duration)
	userID := user.ID.String()

	claims := &TokenClaims{
		Email:     user.Email,
		Role:      user.Role,
		TokenType: tokenType,
		UserID:    userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiry.Unix(),
			IssuedAt:  now.Unix(),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.ACCESS_SECRET))
}

func (s *AuthService) generateRefreshToken(user db.GetUserForLoginRow, tokenID string, duration time.Duration) (string, error) {
	now := time.Now()
	expiry := now.Add(duration)
	userID := user.ID.String()

	claims := &TokenClaims{
		Email:     user.Email,
		Role:      user.Role,
		TokenType: RefreshToken,
		UserID:    userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiry.Unix(),
			IssuedAt:  now.Unix(),
			Subject:   userID,
			Id:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.REFRESH_SECRET))
}

func (s *AuthService) ValidateToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}
		return []byte(s.config.ACCESS_SECRET), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, ErrTokenInvalid
		}
		return nil, ErrTokenExpired
	}

	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, ErrTokenInvalid
	}

	if time.Now().Unix() > int64(exp) {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

func (s *AuthService) ValidateRefreshToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}
		return []byte(s.config.REFRESH_SECRET), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, ErrTokenInvalid
		}
		return nil, ErrTokenExpired
	}

	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid
	}

	tokenType, ok := claims["token_type"].(string)
	if !ok || tokenType != string(RefreshToken) {
		return nil, ErrTokenInvalid
	}

	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}
