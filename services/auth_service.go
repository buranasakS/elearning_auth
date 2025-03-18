package services

import (
	"context"
	"elearning/config"
	db "elearning/db/sqlc"
	"elearning/repository"
	"elearning/utils"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gopkg.in/gomail.v2"
)

var (
	ErrInvalidCredentials  = errors.New("invalid email or password")
	ErrUserNotFound        = errors.New("user not found")
	ErrEmailAlreadyExists  = errors.New("email already exists")
	ErrTokenNotFound       = errors.New("token not found in redis")
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenInvalid        = errors.New("token is invalid")
	ErrTokenClaimsInvalid  = errors.New("token claims are invalid")
	ErrPasswordHash        = errors.New("failed to hash password")
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid or revoked")
	ErrDatabaseOperation   = errors.New("database operation failed")
	ErrRegisterUser        = errors.New("failed to register user")
	ErrRedisOperation      = errors.New("redis operation failed")
	ErrEmailSending        = errors.New("email sending failed")
	ErrTokenGeneration     = errors.New("failed to generate JWT token")
)

type TokenType string

const (
	AccessToken    TokenType = "access_token"
	RefreshToken   TokenType = "refresh_token"
	CookieName               = "refresh_token"
	CookiePath               = "/"
	CookieDomain             = "localhost"
	CookieSecure             = true
	CookieHTTPOnly           = true

	DefaultAccessTokenDuration  = 5 * time.Minute
	DefaultRefreshTokenDuration = 15 * time.Minute
	EmailVerificationDuration   = 10 * time.Minute

	RefreshTokenPrefix      = "refreshToken:"
	EmailVerificationPrefix = "email_verification:"

	VerificationURLBase = "http://localhost:8080/verify-email?token="
)

type TokenClaims struct {
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	TokenType TokenType `json:"token_type"`
	UserID    string    `json:"user_id"`
	jwt.StandardClaims
}

type AuthConfig struct {
	ACCESS_SECRET        string
	REFRESH_SECRET       string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	SMTP                 SMTPConfig
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type AuthService struct {
	repo        *repository.AuthRepository
	config      AuthConfig
	redisClient *redis.Client
}

func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		AccessTokenDuration:  DefaultAccessTokenDuration,
		RefreshTokenDuration: DefaultRefreshTokenDuration,
	}
}

func NewAuthService(repo *repository.AuthRepository, cfg *config.Config, redisClient *redis.Client) *AuthService {
	config := DefaultAuthConfig()
	config.ACCESS_SECRET = cfg.ACCESS_SECRET
	config.REFRESH_SECRET = cfg.REFRESH_SECRET
	config.SMTP.Host = cfg.MAILER_SMTP_HOST
	config.SMTP.Port = cfg.MAILER_SMTP_PORT
	config.SMTP.Username = cfg.MAILER_SMTP_USERNAME
	config.SMTP.Password = cfg.MAILER_SMTP_PASSWORD
	config.SMTP.From = cfg.MAILER_SMTP_USERNAME

	return &AuthService{
		repo:        repo,
		config:      config,
		redisClient: redisClient,
	}
}

func (s *AuthService) GetConfig() AuthConfig {
	return s.config
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
		return nil, ErrRegisterUser
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

	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return "", "", ErrTokenGeneration
	}

	refreshTokenID := uuid.New().String()
	refreshToken, err := s.generateRefreshToken(user, refreshTokenID)
	if err != nil {
		return "", "", ErrTokenGeneration
	}

	err = s.redisClient.Set(ctx, "refreshToken:"+user.ID.String(), refreshToken, s.config.RefreshTokenDuration).Err()
	if err != nil {
		return "", "", ErrRedisOperation
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", ErrTokenInvalid
	}

	email, ok := (*claims)["email"].(string)
	if !ok {
		return "", ErrTokenClaimsInvalid
	}

	user, err := s.repo.GetUserForLogin(ctx, email)
	if err != nil {
		return "", ErrUserNotFound
	}

	storedToken, err := s.redisClient.Get(ctx, "refreshToken:"+user.ID.String()).Result()
	if err != nil {
		return "", ErrTokenNotFound
	}

	if storedToken != refreshToken {
		return "", ErrRefreshTokenInvalid
	}

	newAccessToken, err := s.generateAccessToken(user)
	if err != nil {
		return "", ErrTokenGeneration
	}

	return newAccessToken, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return ErrTokenInvalid
	}

	userID, ok := (*claims)["user_id"].(string)
	if !ok {
		return ErrTokenClaimsInvalid
	}

	err = s.redisClient.Del(ctx, RefreshTokenPrefix+userID).Err()
	if err != nil {
		return ErrRedisOperation
	}

	return nil
}

func (s *AuthService) generateAccessToken(user db.GetUserForLoginRow) (string, error) {
	return s.generateToken(user, AccessToken, s.config.AccessTokenDuration, s.config.ACCESS_SECRET, "")
}

func (s *AuthService) generateRefreshToken(user db.GetUserForLoginRow, tokenID string) (string, error) {
	return s.generateToken(user, RefreshToken, s.config.RefreshTokenDuration, s.config.REFRESH_SECRET, tokenID)
}

func (s *AuthService) generateToken(user db.GetUserForLoginRow, tokenType TokenType, duration time.Duration, secret string, tokenID string) (string, error) {
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
			Id:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func (s *AuthService) ValidateAccessToken(tokenString string) (*jwt.MapClaims, error) {
	return s.validateToken(tokenString, AccessToken, s.config.ACCESS_SECRET)
}

func (s *AuthService) ValidateRefreshToken(tokenString string) (*jwt.MapClaims, error) {
	return s.validateToken(tokenString, RefreshToken, s.config.REFRESH_SECRET)
}

func (s *AuthService) validateToken(tokenString string, expectedType TokenType, secret string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}
		return []byte(secret), nil
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
		return nil, ErrTokenClaimsInvalid
	}

	if expectedType == RefreshToken {
		tokenType, ok := claims["token_type"].(string)
		if !ok || tokenType != string(RefreshToken) {
			return nil, ErrTokenInvalid
		}
	}

	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

func (s *AuthService) SendEmail(ctx context.Context, email string) error {
	user, err := s.repo.CheckEmailExists(ctx, email)
	if err != nil {
		return ErrDatabaseOperation
	}

	if !user.ID.Valid {
		return ErrUserNotFound
	}

	token := uuid.New().String()
	err = s.redisClient.Set(ctx, EmailVerificationPrefix+token, user.Email, EmailVerificationDuration).Err()
	if err != nil {
		return ErrRedisOperation
	}

	verificationLink := VerificationURLBase + token

	mailer := gomail.NewDialer(
		s.config.SMTP.Host,
		s.config.SMTP.Port,
		s.config.SMTP.Username,
		s.config.SMTP.Password,
	)

	m := gomail.NewMessage()
	m.SetHeader("From", s.config.SMTP.Username)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Email Verification")
	m.SetBody("text/html", fmt.Sprintf("Click <a href=\"%s\">here</a> to verify your email", verificationLink))

	if err := mailer.DialAndSend(m); err != nil {
		return ErrEmailSending
	}

	return nil
}

func (s *AuthService) ChangePassword(ctx context.Context, token, password string) (string, error) {
	email, err := s.redisClient.Get(ctx, EmailVerificationPrefix+token).Result()
	if err != nil {
		return "", ErrTokenNotFound
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return "", ErrPasswordHash
	}

	err = s.repo.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{
		Email:    email,
		Password: hashedPassword,
	})

	if err != nil {
		return "", ErrDatabaseOperation
	}

	err = s.redisClient.Del(ctx, EmailVerificationPrefix+token).Err()
	if err != nil {
		return "", ErrRedisOperation
	}

	return email, nil
}