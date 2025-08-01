package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"go_boilerplate/internal/config"
	"go_boilerplate/internal/database"
	"go_boilerplate/internal/routes"
)

func main() {
	var err error

	err = godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	db := database.InitDB()
	defer database.CloseDB(db)

	router := gin.Default()

	routes.SetupRoutes(router, db)

	port := config.GetEnv("PORT", "8080")
	err = router.Run(":" + port)
	if err != nil {
		log.Fatal(err)
	}
}