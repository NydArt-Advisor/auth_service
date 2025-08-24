# Auth Service Environment Setup

## Required Environment Variables

Create a `.env` file in the `auth_service` directory with the following variables:

```env
# Server Configuration
PORT=5002
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-jwt-key-change-this-in-production

# Session Configuration
SESSION_SECRET=your-super-secret-session-key-change-this-in-production

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Service URLs
CLIENT_URL=http://localhost:3000
FRONTEND_URL=http://localhost:3000
AUTH_SERVICE_URL=http://localhost:5002
DB_SERVICE_URL=http://localhost:5003
PAYMENT_SERVICE_URL=http://localhost:5004
AI_SERVICE_URL=http://localhost:5005
NOTIFICATION_SERVICE_URL=http://localhost:5006
METRICS_SERVICE_URL=http://localhost:5007

# Database Configuration
DATABASE_SERVICE_URL=http://localhost:5003

# Email Configuration (for password reset)
SENDGRID_API_KEY=your-sendgrid-api-key
FROM_EMAIL=noreply@nydartadvisor.com
```

## Critical Variables for Google OAuth

The 500 error you're experiencing is likely due to missing these critical environment variables:

1. **JWT_SECRET** - Required for token generation
2. **GOOGLE_CLIENT_ID** - Your Google OAuth client ID
3. **GOOGLE_CLIENT_SECRET** - Your Google OAuth client secret
4. **CLIENT_URL** - Frontend URL for redirects
5. **DB_SERVICE_URL** - Database service URL

## How to Get Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Set up OAuth consent screen
6. Create OAuth 2.0 client ID for "Web application"
7. Add authorized redirect URIs: `http://localhost:5002/auth/google/callback`
8. Copy the Client ID and Client Secret to your `.env` file

## Quick Setup

1. Copy the example above to `auth_service/.env`
2. Replace placeholder values with your actual credentials
3. Restart the auth service
4. Test Google OAuth login

## Troubleshooting

- **500 Error**: Usually means missing JWT_SECRET or Google OAuth credentials
- **Database Connection Error**: Check DB_SERVICE_URL is correct and database service is running
- **Redirect Error**: Ensure CLIENT_URL matches your frontend URL
