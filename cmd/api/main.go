package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"go_boilerplate/internal/config"
	"go_boilerplate/internal/controllers"
	"go_boilerplate/internal/database"
	"go_boilerplate/internal/middlewares"
	"go_boilerplate/internal/routes"
	"go_boilerplate/internal/services"
)

func main() {
	var err error

	err = godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	db := database.InitDB()
	defer database.CloseDB(db)

	redisClient := database.InitRedis()
	defer database.CloseRedis(redisClient)

	router := gin.Default()

	// Global middlewares
	router.Use(middlewares.MetricsMiddleware())
	router.Use(middlewares.RecoveryMiddleware())

	// Initialize services and controllers
	notificationService := services.NewNotificationService()
	otpController := controllers.NewOTPController(notificationService, redisClient)

	// Setup routes
	routes.SetupRoutes(router, db, otpController)

	port := config.GetEnv("PORT", "8080")
	err = router.Run(":" + port)
	if err != nil {
		log.Fatal(err)
	}
}