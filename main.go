package main

import (
	"context"
	"elearning/config"
	db "elearning/db/sqlc"
	_ "elearning/docs" // swagger docs
	"elearning/handlers"
	"elearning/repository"
	"elearning/routes"
	"elearning/services"
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// @title           Authentication API
// @version         1.0
// @description     Authentication API

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	redisClient, err := config.InitRedis(cfg)
	if err != nil {
		log.Fatal("Failed to connect to Redis: ", err)
	}
	defer redisClient.Close()

	conn, err := config.InitDB(cfg)
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}
	defer conn.Close(context.Background())

	queries := db.New(conn)
	authRepository := repository.NewAuthRepository(queries, redisClient)
	authService := services.NewAuthService(authRepository, cfg, redisClient)
	authHandler := handlers.NewAuthHandler(authService)

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	route := &routes.Route{
		AuthHandler: authHandler,
	}

	routes.SetupRouter(r, route)
	r.Run(":8080")
}
