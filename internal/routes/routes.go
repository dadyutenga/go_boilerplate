package routes

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"go_boilerplate/internal/controllers"
	"go_boilerplate/internal/middlewares"
)

func SetupRoutes(router *gin.Engine, db *gorm.DB) {
	api := router.Group("/api")
	{
		api.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		authController := controllers.NewAuthController(db)
		api.POST("/register", authController.Register)
		api.POST("/login", authController.Login)

		protected := api.Group("/protected")
		protected.Use(middlewares.JWTAuthMiddleware())
		{
			protected.GET("/user", func(c *gin.Context) {
				c.JSON(200, gin.H{"message": "This is a protected user endpoint"})
			})

			admin := protected.Group("/admin")
			admin.Use(middlewares.RoleMiddleware("admin", "superadmin"))
			{
				admin.GET("/dashboard", func(c *gin.Context) {
					c.JSON(200, gin.H{"message": "This is an admin dashboard"})
				})
			}
		}
	}
}