# Go Boilerplate

A production-ready Golang web backend project scaffold using the Gin web framework with JWT authentication, RBAC, OTP integration, and more.

## Features
- **Authentication & Authorization**: JWT-based auth with user registration, login, and role-based access control (RBAC).
- **API Health Tracking**: Middleware to track API metrics, requests per endpoint, and success/failure counts.
- **SMS & Email OTP Integration**: Send OTP codes for 2FA or password resets via email (SendGrid) or SMS (Twilio).
- **Email Notifications**: Transactional emails with templating support.
- **Middleware**: JWT verification, role-check, API usage tracking, and panic recovery.
- **Tech Stack**: Gin, GORM, PostgreSQL, Redis, Go modules, dotenv config, SMTP/Twilio integrations.

## Project Structure
```
├── cmd/                # Main applications for this project
│   └── api/            # Main API server
├── internal/           # Private application code
│   ├── config/         # Configuration utilities
│   ├── controllers/    # HTTP handlers
│   ├── database/       # Database initialization and seeding
│   ├── middlewares/    # HTTP middleware
│   ├── models/         # Database models
│   ├── routes/         # API route definitions
│   ├── services/       # Business logic services (e.g., notifications)
│   └── utils/          # Utility functions
├── pkg/                # Shared packages
│   └── logger/         # Logging utilities
└── .env                # Environment configuration
```

## Setup Instructions

### Prerequisites
- Go 1.20+
- PostgreSQL
- Redis
- SendGrid account (for email)
- Twilio account (for SMS)

### Local Development
1. Clone the repository and navigate to the project directory.
2. Copy `.env.example` to `.env` and update the environment variables.
3. Install dependencies:
   ```bash
   go mod tidy
   ```
4. Run the application:
   ```bash
   go run ./cmd/api
   ```
   The server will start on the port specified in `.env` (default: 8080).

### Using Docker
(TODO: Add Docker setup instructions)

## Environment Variables
Create a `.env` file based on `.env.example` with the following variables:
```
PORT=8080
DATABASE_URL=host=localhost user=postgres password=postgres dbname=go_boilerplate port=5432 sslmode=disable
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
JWT_SECRET=mysecretkey
SENDGRID_API_KEY=your_sendgrid_api_key
FROM_EMAIL=noreply@example.com
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
FROM_PHONE=your_twilio_phone_number
```

## API Endpoints
- **POST /api/register** - Register a new user
- **POST /api/login** - Login and get JWT token
- **POST /api/otp/send** - Send OTP to email or phone
- **POST /api/otp/verify** - Verify OTP
- **GET /api/health** - Check API health
- **GET /api/metrics** - View API usage metrics
- **GET /api/protected/user** - Protected user endpoint (requires JWT)
- **GET /api/protected/admin/dashboard** - Admin-only endpoint (requires JWT and admin role)

## Testing
Run tests with:
```bash
go test ./...
```

## License
MIT