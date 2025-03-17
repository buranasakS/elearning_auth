package handlers

import (
	db "elearning/db/sqlc"
	"elearning/services"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type RegisterRequest struct {
	Fullname        string `json:"fullname" binding:"required"`
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type AuthErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

type LoginResponse struct {
	Message      string `json:"message"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type SuccessResponse struct {
	Message string `json:"message"`
}

type TokenPayload struct {
	Email     string      `json:"email"`
	Role      string      `json:"role"`
	UserID    string      `json:"user_id"`
	TokenType interface{} `json:"token_type"`
	ExpiresAt int64       `json:"exp"`
	IssuedAt  int64       `json:"iat"`
	Subject   string      `json:"sub"`
}

func (h *AuthHandler) GetAuthService() *services.AuthService {
	return h.authService
}

// @Summary Register new user
// @Description Register a new user with the provided details
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "User registration details"
// @Success 201 {object} SuccessResponse
// @Failure 400 {object} AuthErrorResponse
// @Router /api/v1/auth/register [post]
func (h *AuthHandler) RegisterUser(c *gin.Context) {
	var reqBody RegisterRequest
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, AuthErrorResponse{
			Error:   "Invalid request",
			Details: err.Error(),
		})
		return
	}

	_, err := h.authService.RegisterUser(c.Request.Context(), &db.CreateUserParams{
		Fullname: reqBody.Fullname,
		Email:    reqBody.Email,
		Password: reqBody.Password,
		Role:     "user",
	})
	if err != nil {
		log.Printf("register user error %v", err)

		if errors.Is(err, services.ErrEmailAlreadyExists) {
			c.JSON(http.StatusBadRequest, AuthErrorResponse{Error: "Email already exists"})
			return
		}

		c.JSON(http.StatusBadRequest, AuthErrorResponse{Error: "Failed to register user"})
		return
	}

	c.JSON(http.StatusCreated, SuccessResponse{Message: "User registered successfully"})
}

// @Summary User login
// @Description Authenticate a user and return access & refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "User login credentials"
// @Success 200 {object} LoginResponse
// @Failure 400,401 {object} AuthErrorResponse
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) LoginUser(c *gin.Context) {
	var reqBody LoginRequest
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, AuthErrorResponse{
			Error:   "Invalid request",
			Details: err.Error(),
		})
		return
	}

	accessToken, refreshToken, err := h.authService.LoginUser(c.Request.Context(), reqBody.Email, reqBody.Password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) || errors.Is(err, services.ErrUserNotFound) {
			c.JSON(http.StatusUnauthorized, AuthErrorResponse{Error: "Invalid Invalid email or password"})
			return
		}

		log.Printf("login user error %v", err)

		c.JSON(http.StatusBadRequest, AuthErrorResponse{Error: "Unable to login. Please try again later"})
		return
	}

	c.SetCookie(
		services.CookieName,
		refreshToken,
		int(h.authService.GetConfig().RefreshTokenDuration.Seconds()),
		services.CookiePath,
		services.CookieDomain,
		services.CookieSecure,
		services.CookieHTTPOnly,
	)

	c.JSON(http.StatusOK, LoginResponse{
		Message:     "Login successful",
		AccessToken: accessToken,
	})
}

// @Summary Protected route
// @Description Example of a protected route that requires authentication
// @Tags protected
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} TokenPayload
// @Failure 401 {object} AuthErrorResponse
// @Router /api/v1/protected [get]
func (h *AuthHandler) ProtectedRoute(c *gin.Context) {
	claims, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, AuthErrorResponse{Error: "User claims not found in context"})
		return
	}

	c.JSON(http.StatusOK, claims)
}

// @Summary Refresh access token
// @Description Get a new access token using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} LoginResponse
// @Failure 400,401 {object} AuthErrorResponse
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, AuthErrorResponse{Error: "request does not contain a refresh token"})
		return
	}

	accessToken, err := h.authService.RefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, AuthErrorResponse{Error: "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		Message:     "Token refreshed successfully",
		AccessToken: accessToken,
	})
}

// @Summary User logout
// @Description Logout user and invalidate refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} SuccessResponse
// @Failure 400,401 {object} AuthErrorResponse
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, AuthErrorResponse{Error: "request does not contain a refresh token"})
		return
	}

	h.authService.Logout(c.Request.Context(), refreshToken)

	c.SetCookie("refresh_token", "", -1, "/", "localhost", true, true)
	c.JSON(http.StatusOK, SuccessResponse{Message: "Logout successful"})
}

// @Summary Send email
// @Description Send email to user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body SendEmailRequest true "Send email request"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} AuthErrorResponse
// @Router /api/v1/auth/forget/password [post]
func (h *AuthHandler) SendEmail(c *gin.Context) {
	var reqBody struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, AuthErrorResponse{Error: "Invalid request"})
		return
	}

	err := h.authService.SendEmail(c.Request.Context(), reqBody.Email)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, AuthErrorResponse{Error: "User not found"})
		} else if errors.Is(err, services.ErrInternalError) {
			c.JSON(http.StatusInternalServerError, AuthErrorResponse{Error: "Internal server error"})
		} else {
			c.JSON(http.StatusInternalServerError, AuthErrorResponse{
				Error:   "Failed to send email",
				Details: err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Email sent successfully"})
}

// @Summary Change password
// @Description Change password for user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ChangePasswordRequest true "Change password request"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} AuthErrorResponse
// @Router /api/v1/auth/change/password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var reqBody struct {
		Token    string `json:"token" binding:"required"`
		Password string `json:"password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, AuthErrorResponse{Error: "Invalid request"})
		return
	}

	_, err := h.authService.ChangePassword(c.Request.Context(), reqBody.Token, reqBody.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, AuthErrorResponse{Error: "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Password changed successfully"})
}
