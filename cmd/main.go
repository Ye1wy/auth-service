package main

import (
	"auth-service/internal/controller"
	"auth-service/internal/database"
	"auth-service/internal/repository"
	"auth-service/internal/route"
	"auth-service/internal/service"
	"auth-service/pkg/config"
	"auth-service/pkg/logger"
	"os"
)

func main() {
	cfg := config.MustLoad()
	log := logger.NewLogger(cfg.Env)
	conn, err := database.NewPostgresStorage(&cfg.PostgresConfig)
	if err != nil {
		panic("can't connect to database")
	}

	tokenRepo := repository.NewTokenRepo(conn, log)
	userRepo := repository.NewUserRepo(conn, log)
	scv := service.NewAuthService(tokenRepo, tokenRepo, userRepo, userRepo, log, cfg.Secret)
	auth := controller.NewAuth(scv, log)
	router := route.NewRouter(auth)

	if err := router.Run(":8080"); err != nil {
		log.Error("Somthing went wrong with run service", logger.Err(err), "op", "main")
		os.Exit(1)
	}
}
