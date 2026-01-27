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
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/example/sijunjung-go/internal/config"
	"github.com/example/sijunjung-go/internal/database"
	delivery "github.com/example/sijunjung-go/internal/delivery/http"
	"github.com/example/sijunjung-go/internal/infra/email"
	"github.com/example/sijunjung-go/internal/infra/logging"
	mongorepo "github.com/example/sijunjung-go/internal/infra/mongo"
	"github.com/example/sijunjung-go/internal/infra/whatsapp"
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
	emailService := email.NewMailjetService(cfg.MailjetAPIKey, cfg.MailjetSecretKey, cfg.MailjetFromName, cfg.MailjetFromEmail)
	whatsappService := whatsapp.NewFonnteService(cfg.FonnteToken)

	authService := auth.NewService(userRepo, tokenRepo, otpRepo, emailService, whatsappService, cfg.AuthSecret, cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL, cfg.FacebookAppID, cfg.FacebookAppSecret, appLogger)

	router := chi.NewRouter()
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Access-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
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
		r.Get("/auth/google", authHandler.GoogleAuthRedirect)
		r.Get("/auth/google/callback", authHandler.GoogleAuthCallback)
		r.Post("/auth/facebook", authHandler.FacebookAuth)

		// WhatsApp OTP routes
		r.Post("/whatsapp/send-otp", authHandler.SendWhatsAppOTP)
		r.Post("/whatsapp/verify-otp", authHandler.VerifyWhatsAppOTP)

		r.Group(func(private chi.Router) {
			private.Use(authMiddleware.Handler)
			private.Post("/logout", authHandler.Logout)
			private.Get("/me", authHandler.CurrentUser)
			private.Delete("/account", authHandler.DeleteAccount)
			private.Get("/sijunjung", delivery.SijunjungHandler)
		})
	})

	appLogger.Info(context.Background(), "server starting on "+cfg.HTTPPort)
	srv := &http.Server{Addr: ":" + cfg.HTTPPort, Handler: router}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
