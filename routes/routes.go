package routes

import (
	"elearning/handlers"
	"elearning/middleware"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type Route struct {
	AuthHandler *handlers.AuthHandler
}

func SetupRouter(r *gin.Engine, route *Route) {
	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/register", route.AuthHandler.RegisterUser)
			auth.POST("/login", route.AuthHandler.LoginUser)
			auth.POST("/refresh", route.AuthHandler.RefreshToken)
			// auth.POST("/forget/password", route.AuthHandler.SendEmailForResetPassword)	
			// auth.POST("/reset/password", route.AuthHandler.ResetPassword)
		}

		protected := v1.Group("/auth")
		protected.Use(middleware.AuthMiddleware(route.AuthHandler.GetAuthService()))
		{
			protected.POST("/logout", route.AuthHandler.Logout)
		}

		protectedRoutes := v1.Group("/protected")
		protectedRoutes.Use(middleware.AuthMiddleware(route.AuthHandler.GetAuthService()))
		{
			protectedRoutes.GET("", route.AuthHandler.ProtectedRoute)
		}
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}
