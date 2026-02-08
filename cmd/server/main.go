package main

// @title Sijunjung Go API
// @version 2.0
// @description API for Sijunjung Go application with multi-role authentication support
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
	"github.com/example/sijunjung-go/internal/model"
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
	appLogger.StartCleanup(cfg.LogCleanupInterval, cfg.LogRetentionDays)

	userRepo := mongorepo.NewUserRepository(db)
	tokenRepo := mongorepo.NewTokenRepository(db)
	otpRepo := mongorepo.NewOTPRepository(db)
	emailService := email.NewMailjetService(cfg.MailjetAPIKey, cfg.MailjetSecretKey, cfg.MailjetFromName, cfg.MailjetFromEmail)
	whatsappService := whatsapp.NewFonnteService(cfg.FonnteToken)

	authService := auth.NewService(userRepo, tokenRepo, otpRepo, emailService, whatsappService, cfg.AuthSecret, cfg.AccessTokenExpiry, cfg.RefreshTokenExpiry, cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL, cfg.FacebookAppID, cfg.FacebookAppSecret, appLogger)

	// Seed super admin account
	if err := authService.SeedSuperAdmin(context.Background(), cfg.SuperAdminEmail, cfg.SuperAdminPassword); err != nil {
		log.Fatalf("failed to seed super admin: %v", err)
	}

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
	cmsHandler := delivery.NewCMSHandler(authService)
	merchantHandler := delivery.NewMerchantHandler(authService)
	mitraHandler := delivery.NewMitraHandler(authService)

	router.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("/swagger/doc.json")))

	router.Route("/api", func(r chi.Router) {

		// ========================================
		// USER routes
		// ========================================
		r.Route("/user", func(user chi.Router) {
			// Public
			user.Post("/register", authHandler.Register)
			user.Post("/verify-otp", authHandler.VerifyOTP)
			user.Post("/resend-otp", authHandler.ResendOTP)
			user.Post("/reset-password", authHandler.ResetPassword)
			user.Post("/login", authHandler.UserLogin)
			user.Post("/refresh-token", authHandler.RefreshToken)

			// OAuth
			user.Get("/auth/google", authHandler.GoogleAuthRedirect)
			user.Get("/auth/google/callback", authHandler.GoogleAuthCallback)
			user.Post("/auth/facebook", authHandler.FacebookAuth)
			user.Post("/auth/google-mobile", authHandler.GoogleAuthMobile)

			// WhatsApp OTP
			user.Post("/whatsapp/send-otp", authHandler.SendWhatsAppOTP)
			user.Post("/whatsapp/verify-otp", authHandler.VerifyWhatsAppOTP)

			// Protected (role=user)
			user.Group(func(private chi.Router) {
				private.Use(authMiddleware.Handler)
				private.Use(delivery.RequireRole(model.RoleUser))
				private.Post("/logout", authHandler.Logout)
				private.Get("/me", authHandler.CurrentUser)
				private.Delete("/account", authHandler.DeleteAccount)
				private.Get("/sijunjung", delivery.SijunjungHandler)
			})
		})

		// ========================================
		// CMS routes (Super Admin + Admin)
		// ========================================
		r.Route("/cms", func(cms chi.Router) {
			// Public
			cms.Post("/login", cmsHandler.Login)
			cms.Post("/refresh-token", authHandler.RefreshToken)

			// Protected - Super Admin OR Admin
			cms.Group(func(private chi.Router) {
				private.Use(authMiddleware.Handler)
				private.Use(delivery.RequireRole(model.RoleSuperAdmin, model.RoleAdmin))
				private.Post("/logout", authHandler.Logout)
				private.Get("/me", authHandler.CurrentUser)
			})

			// Protected - Super Admin ONLY (account management)
			cms.Group(func(superOnly chi.Router) {
				superOnly.Use(authMiddleware.Handler)
				superOnly.Use(delivery.RequireRole(model.RoleSuperAdmin))
				superOnly.Post("/accounts", cmsHandler.CreateAccount)
				superOnly.Get("/accounts", cmsHandler.ListAccounts)
				superOnly.Get("/accounts/{id}", cmsHandler.GetAccount)
				superOnly.Put("/accounts/{id}", cmsHandler.UpdateAccount)
				superOnly.Delete("/accounts/{id}", cmsHandler.DeleteAccount)
				superOnly.Post("/accounts/{id}/reset-password", cmsHandler.ResetAccountPassword)
			})
		})

		// ========================================
		// MERCHANT routes
		// ========================================
		r.Route("/merchant", func(merchant chi.Router) {
			// Public
			merchant.Post("/login", merchantHandler.Login)
			merchant.Post("/refresh-token", authHandler.RefreshToken)

			// Protected (role=merchant)
			merchant.Group(func(private chi.Router) {
				private.Use(authMiddleware.Handler)
				private.Use(delivery.RequireRole(model.RoleMerchant))
				private.Post("/logout", authHandler.Logout)
				private.Get("/me", authHandler.CurrentUser)
				private.Get("/dashboard", merchantHandler.Dashboard)
			})
		})

		// ========================================
		// MITRA routes
		// ========================================
		r.Route("/mitra", func(mitra chi.Router) {
			// Public
			mitra.Post("/login", mitraHandler.Login)
			mitra.Post("/refresh-token", authHandler.RefreshToken)

			// Protected (role=mitra)
			mitra.Group(func(private chi.Router) {
				private.Use(authMiddleware.Handler)
				private.Use(delivery.RequireRole(model.RoleMitra))
				private.Post("/logout", authHandler.Logout)
				private.Get("/me", authHandler.CurrentUser)
				private.Get("/dashboard", mitraHandler.Dashboard)
			})
		})

		// ========================================
		// LEGACY routes (backward compatibility)
		// ========================================
		r.Post("/register", authHandler.Register)
		r.Post("/verify-otp", authHandler.VerifyOTP)
		r.Post("/resend-otp", authHandler.ResendOTP)
		r.Post("/reset-password", authHandler.ResetPassword)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh-token", authHandler.RefreshToken)
		r.Get("/auth/google", authHandler.GoogleAuthRedirect)
		r.Get("/auth/google/callback", authHandler.GoogleAuthCallback)
		r.Post("/auth/facebook", authHandler.FacebookAuth)
		r.Post("/auth/google-mobile", authHandler.GoogleAuthMobile)
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
