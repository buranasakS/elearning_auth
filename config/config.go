package config

import (
	"context"
	"errors"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	DATABASE_URL   string
	ACCESS_SECRET  string
	REFRESH_SECRET string
	PORT           string
	REDIS_HOST     string
	REDIS_PORT     string
	REDIS_PASSWORD string
}

func LoadConfig() (*Config, error) {

	err := godotenv.Load(".env")
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("error loading .env file")
	}

	dbSource := os.Getenv("DATABASE_URL")
	accessSecret := os.Getenv("ACCESS_SECRET")
	refreshSecret := os.Getenv("REFRESH_SECRET")
	port := os.Getenv("PORT")
	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")
	redisPassword := os.Getenv("REDIS_PASSWORD")

	if dbSource == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	if accessSecret == "" {
		return nil, errors.New("ACCESS_SECRET is required")
	}
	if refreshSecret == "" {
		return nil, errors.New("REFRESH_SECRET is required")
	}
	if port == "" {
		return nil, errors.New("PORT is required")
	}
	if redisHost == "" {
		return nil, errors.New("REDIS_HOST is required")
	}
	if redisPort == "" {
		return nil, errors.New("REDIS_PORT is required")
	}
	if redisPassword == "" {
		return nil, errors.New("REDIS_PASSWORD is required")
	}

	return &Config{
		DATABASE_URL:   dbSource,
		ACCESS_SECRET:  accessSecret,
		REFRESH_SECRET: refreshSecret,
		PORT:           port,
		REDIS_HOST:     redisHost,
		REDIS_PORT:     redisPort,
		REDIS_PASSWORD: redisPassword,
	}, nil
}

func InitDB(cfg *Config) (*pgx.Conn, error) {
	db, err := pgx.Connect(context.Background(), cfg.DATABASE_URL)
	if err != nil {
		return nil, err
	}
	
	err = db.Ping(context.Background())
	if err != nil {
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

	err := redisClient.Ping(context.Background()).Err()
	if err != nil {
		return nil, err
	}

	return redisClient, nil
}
