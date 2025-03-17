package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"gopkg.in/gomail.v2"
)

type Config struct {
	DB_URL               string 
	ACCESS_SECRET        string 
	REFRESH_SECRET       string 
	MAILER_SMTP_HOST     string 
	MAILER_SMTP_PORT     int    
	MAILER_SMTP_PASSWORD string 
	MAILER_SMTP_USERNAME string 
	PORT                 string 
	REDIS_HOST           string 
	REDIS_PORT           string 
	REDIS_PASSWORD       string 
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(".env"); err != nil && !os.IsNotExist(err) {
		return nil, errors.New("error loading .env file")
	}

	requiredEnvVars := []struct {
		key    string
		envVar string
	}{
		{"DATABASE_URL", "DB_URL"},
		{"ACCESS_SECRET", "ACCESS_SECRET"},
		{"REFRESH_SECRET", "REFRESH_SECRET"},
		{"PORT", "PORT"},
		{"REDIS_HOST", "REDIS_HOST"},
		{"REDIS_PORT", "REDIS_PORT"},
		{"REDIS_PASSWORD", "REDIS_PASSWORD"},
		{"MAILER_SMTP_HOST", "MAILER_SMTP_HOST"},
		{"MAILER_SMTP_PORT", "MAILER_SMTP_PORT"},
		{"MAILER_SMTP_PASSWORD", "MAILER_SMTP_PASSWORD"},
		{"MAILER_SMTP_USERNAME", "MAILER_SMTP_USERNAME"},
	}

	for _, e := range requiredEnvVars {
		if value := os.Getenv(e.key); value == "" {
			return nil, errors.New(e.envVar + " is required")
		}
	}

	smtpPort, err := strconv.Atoi(os.Getenv("MAILER_SMTP_PORT"))
	if err != nil {
		return nil, fmt.Errorf("failed to convert MAILER_SMTP_PORT to int: %w", err)
	}

	return &Config{
		DB_URL:               os.Getenv("DATABASE_URL"),
		ACCESS_SECRET:        os.Getenv("ACCESS_SECRET"),
		REFRESH_SECRET:       os.Getenv("REFRESH_SECRET"),
		PORT:                 os.Getenv("PORT"),
		REDIS_HOST:           os.Getenv("REDIS_HOST"),
		REDIS_PORT:           os.Getenv("REDIS_PORT"),
		REDIS_PASSWORD:       os.Getenv("REDIS_PASSWORD"),
		MAILER_SMTP_HOST:     os.Getenv("MAILER_SMTP_HOST"),
		MAILER_SMTP_PORT:     smtpPort,
		MAILER_SMTP_PASSWORD: os.Getenv("MAILER_SMTP_PASSWORD"),
		MAILER_SMTP_USERNAME: os.Getenv("MAILER_SMTP_USERNAME"),
	}, nil
}

func InitDB(cfg *Config) (*pgx.Conn, error) {
	db, err := pgx.Connect(context.Background(), cfg.DB_URL)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(context.Background()); err != nil {
		return nil, err
	}

	return db, nil
}

func Port(cfg *Config) string {
	return ":" + cfg.PORT
}

func InitRedis(cfg *Config) (*redis.Client, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.REDIS_HOST + ":" + cfg.REDIS_PORT,
		Password: cfg.REDIS_PASSWORD,
		DB:       0,
	})

	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return redisClient, nil
}

func InitMailer(cfg *Config) (*gomail.Dialer, error) {
	mailer := gomail.NewDialer(cfg.MAILER_SMTP_HOST, cfg.MAILER_SMTP_PORT, cfg.MAILER_SMTP_USERNAME, cfg.MAILER_SMTP_PASSWORD)

	if _, err := mailer.Dial(); err != nil {
		return nil, fmt.Errorf("failed to connect to SMTP server: %w", err)
	}

	return mailer, nil
}
