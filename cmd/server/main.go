package main

// @title Sijunjung Go API
// @version 1.0
// @description API for Sijunjung Go application with authentication support
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Enter your bearer token in the format: Bearer {token}

//go:generate swag init -g cmd/server/main.go -o internal/docs

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/example/sijunjung-go/internal/config"
	"github.com/example/sijunjung-go/internal/database"
	delivery "github.com/example/sijunjung-go/internal/delivery/http"
	"github.com/example/sijunjung-go/internal/infra/email"
	"github.com/example/sijunjung-go/internal/infra/logging"
	mongorepo "github.com/example/sijunjung-go/internal/infra/mongo"
	"github.com/example/sijunjung-go/internal/usecase/auth"

	_ "github.com/example/sijunjung-go/internal/docs"
)

func main() {
	if err := godotenv.Load(); err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("failed to load environment: %v", err)
		}
	}

	cfg := config.Load()

	client, err := database.Connect(cfg.MongoURI)
	if err != nil {
		log.Fatalf("unable to connect to mongo: %v", err)
	}
	defer func() {
		if err := client.Disconnect(context.Background()); err != nil {
			log.Printf("error disconnecting mongo: %v", err)
		}
	}()
	db := client.Database(cfg.Database)

	appLogger := logging.New(db)
	userRepo := mongorepo.NewUserRepository(db)
	tokenRepo := mongorepo.NewTokenRepository(db)
	otpRepo := mongorepo.NewOTPRepository(db)
	emailService := email.NewSMTPService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom)

	authService := auth.NewService(userRepo, tokenRepo, otpRepo, emailService, cfg.AuthSecret, cfg.GoogleClientID, cfg.FacebookAppID, cfg.FacebookAppSecret, appLogger)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	authHandler := delivery.NewAuthHandler(authService)
	authMiddleware := delivery.NewAuthMiddleware(authService)

	router.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("/swagger/doc.json")))

	router.Route("/api", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/verify-otp", authHandler.VerifyOTP)
		r.Post("/resend-otp", authHandler.ResendOTP)
		r.Post("/reset-password", authHandler.ResetPassword)
		r.Post("/login", authHandler.Login)
		r.Post("/auth/google", authHandler.GoogleAuth)
		r.Post("/auth/facebook", authHandler.FacebookAuth)

		r.Group(func(private chi.Router) {
			private.Use(authMiddleware.Handler)
			private.Post("/logout", authHandler.Logout)
			private.Get("/me", authHandler.CurrentUser)
			private.Get("/sijunjung", delivery.SijunjungHandler)
		})
	})

	appLogger.Info(context.Background(), "server starting on "+cfg.HTTPPort)
	srv := &http.Server{Addr: ":" + cfg.HTTPPort, Handler: router}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
