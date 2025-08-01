package routes

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"go_boilerplate/internal/controllers"
	"go_boilerplate/internal/middlewares"
)

func SetupRoutes(router *gin.Engine, db *gorm.DB, otpController *controllers.OTPController) {
	api := router.Group("/api")
	{
		api.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		api.GET("/metrics", func(c *gin.Context) {
			if metrics, exists := c.Get("metrics"); exists {
				c.JSON(200, metrics)
			} else {
				c.JSON(200, gin.H{"message": "No metrics available"})
			}
		})

		authController := controllers.NewAuthController(db)
		api.POST("/register", authController.Register)
		api.POST("/login", authController.Login)

		// OTP endpoints
		api.POST("/otp/send", otpController.SendOTP)
		api.POST("/otp/verify", otpController.VerifyOTP)

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