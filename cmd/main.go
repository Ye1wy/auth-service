package main

import (
	"auth-service/internal/controller"
	"auth-service/internal/route"
	"auth-service/pkg/logger"
	"os"
)

func main() {
	log := logger.NewLogger("local")
	auth := controller.NewAuth(log)
	router := route.NewRouter(auth)

	if err := router.Run(":8080"); err != nil {
		log.Error("Somthing went wrong with run service", logger.Err(err), "op", "main")
		os.Exit(1)
	}
}
