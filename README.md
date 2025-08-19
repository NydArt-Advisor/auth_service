# Auth Service - Technical Documentation

## Table of Contents
1. [Service Overview](#service-overview)
2. [Technology Stack](#technology-stack)
3. [Architecture](#architecture)
4. [Installation & Setup](#installation--setup)
5. [Configuration](#configuration)
6. [API Reference](#api-reference)
7. [Deployment Guide](#deployment-guide)
8. [User Manual](#user-manual)
9. [Update Manual](#update-manual)
10. [Monitoring & Troubleshooting](#monitoring--troubleshooting)
11. [Security Considerations](#security-considerations)
12. [Testing](#testing)

## Service Overview

The Authentication Service is a microservice responsible for user authentication, authorization, and session management in the NydArt Advisor application. It provides secure user registration, login, OAuth integration, and JWT token management.

### Key Features
- User registration and login
- Google OAuth 2.0 integration
- Facebook OAuth integration
- JWT token generation and validation
- Password reset functionality
- Two-factor authentication (2FA)
- Session management
- Rate limiting
- Security headers and CORS

### Service Responsibilities
- User authentication and authorization
- Token management (JWT)
- OAuth provider integration
- Password security (bcrypt hashing)
- Session handling
- User data validation

## Technology Stack

### Core Technologies
- **Runtime**: Node.js (v18+)
- **Framework**: Express.js (v4.18.2)
- **Database**: MongoDB (via Database Service)
- **Authentication**: Passport.js, JWT, bcryptjs

### Key Dependencies
```json
{
  "express": "^4.18.2",
  "passport": "^0.6.0",
  "passport-google-oauth20": "^2.0.0",
  "passport-facebook": "^3.0.0",
  "jsonwebtoken": "^9.0.0",
  "bcryptjs": "^2.4.3",
  "mongoose": "^7.0.3",
  "express-session": "^1.17.3",
  "express-rate-limit": "^7.1.5",
  "express-validator": "^7.0.1",
  "speakeasy": "^2.0.0",
  "qrcode": "^1.5.4"
}
```

### Development Tools
- **Testing**: Mocha, Chai, Sinon, Supertest
- **Code Coverage**: NYC
- **Development Server**: Nodemon
- **Environment Management**: dotenv

## Architecture

### Service Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Auth Service  │    │ Database Service│
│   (Next.js)     │◄──►│   (Express.js)  │◄──►│   (MongoDB)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   OAuth         │
                       │   Providers     │
                       │ (Google/Facebook)│
                       └─────────────────┘
```

### Data Flow
1. **Registration/Login**: User submits credentials → Auth Service validates → Database Service stores/retrieves → JWT token generated
2. **OAuth Flow**: User clicks OAuth button → Redirect to provider → Provider callback → User data retrieved → Account created/updated → JWT token generated
3. **Token Validation**: Protected routes → JWT middleware → Token validation → User data attached to request

### Security Layers
- **Rate Limiting**: Express Rate Limit
- **Input Validation**: Express Validator
- **Password Security**: bcryptjs hashing
- **Token Security**: JWT with expiration
- **Session Security**: Express Session with secure settings
- **CORS Protection**: Configured CORS middleware

## Installation & Setup

### Prerequisites
- Node.js (v18 or higher)
- npm or yarn
- MongoDB (local or Atlas)
- Google OAuth credentials (for OAuth functionality)

### Installation Steps

1. **Clone and Navigate**
   ```bash
   cd auth_service
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start Development Server**
   ```bash
   npm run dev
   ```

5. **Run Tests**
   ```bash
   npm test
   ```

## Configuration

### Environment Variables

Create a `.env` file in the `auth_service` directory:

```env
# Server Configuration
PORT=5002
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-jwt-key-change-this-in-production
JWT_EXPIRES_IN=24h

# Session Configuration
SESSION_SECRET=your-super-secret-session-key-change-this-in-production

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Facebook OAuth Configuration (Optional)
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret

# Service URLs
CLIENT_URL=http://localhost:3000
FRONTEND_URL=http://localhost:3000
AUTH_SERVICE_URL=http://localhost:5002
DB_SERVICE_URL=http://localhost:5001
PAYMENT_SERVICE_URL=http://localhost:3004
AI_SERVICE_URL=http://localhost:5005
NOTIFICATION_SERVICE_URL=http://localhost:5006
METRICS_SERVICE_URL=http://localhost:5007

# Email Configuration (for password reset)
SENDGRID_API_KEY=your-sendgrid-api-key
FROM_EMAIL=noreply@nydartadvisor.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Security
TRUST_PROXY=1
CORS_ORIGIN=http://localhost:3000
```

### Critical Configuration Notes

#### JWT Secrets
- **JWT_SECRET**: Must be a strong, random string (32+ characters)
- **JWT_REFRESH_SECRET**: Different from JWT_SECRET for security
- **SESSION_SECRET**: Unique secret for session management

#### OAuth Setup
1. **Google OAuth**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create OAuth 2.0 Client ID
   - Add authorized redirect URI: `http://localhost:5002/auth/google/callback`
   - Copy Client ID and Secret to `.env`

2. **Facebook OAuth** (Optional):
   - Go to [Facebook Developers](https://developers.facebook.com/)
   - Create app and get App ID and Secret
   - Add to `.env` if using Facebook login

#### Service URLs
- Ensure all service URLs are correct and accessible
- For production, use HTTPS URLs
- Update CORS_ORIGIN for production domain

## API Reference

### Authentication Endpoints

#### POST /auth/register
Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "id": "user_id",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
  },
  "token": "jwt_token_here"
}
```

#### POST /auth/login
Authenticate user with email and password.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "user_id",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
  },
  "token": "jwt_token_here"
}
```

#### GET /auth/google
Initiate Google OAuth flow.

**Response:** Redirects to Google OAuth consent screen.

#### GET /auth/google/callback
Google OAuth callback endpoint.

**Response:** Redirects to frontend with success/error status.

#### POST /auth/forgot-password
Request password reset email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

#### POST /auth/reset-password
Reset password with token.

**Request Body:**
```json
{
  "token": "reset_token",
  "password": "newPassword123"
}
```

#### POST /auth/logout
Logout user and invalidate session.

**Headers:** Authorization: Bearer <token>

#### GET /auth/verify
Verify JWT token validity.

**Headers:** Authorization: Bearer <token>

#### POST /auth/refresh
Refresh JWT token.

**Headers:** Authorization: Bearer <refresh_token>

### Health Check Endpoints

#### GET /health
Service health check.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "service": "auth-service",
  "version": "1.0.0"
}
```

## Deployment Guide

### Production Deployment

#### 1. Environment Preparation
```bash
# Set production environment
NODE_ENV=production

# Update all URLs to production domains
CLIENT_URL=https://yourdomain.com
FRONTEND_URL=https://yourdomain.com
AUTH_SERVICE_URL=https://auth.yourdomain.com
DB_SERVICE_URL=https://db.yourdomain.com
```

#### 2. Security Configuration
```env
# Production JWT secrets (generate strong secrets)
JWT_SECRET=your-production-jwt-secret-32-chars-minimum
JWT_REFRESH_SECRET=your-production-refresh-secret-32-chars-minimum
SESSION_SECRET=your-production-session-secret-32-chars-minimum

# Production OAuth redirects
GOOGLE_CLIENT_ID=your-production-google-client-id
GOOGLE_CLIENT_SECRET=your-production-google-client-secret

# CORS for production
CORS_ORIGIN=https://yourdomain.com
```

#### 3. Deployment Options

**Option A: Docker Deployment**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5002
CMD ["npm", "start"]
```

**Option B: Direct Deployment**
```bash
# Install dependencies
npm ci --only=production

# Start service
npm start
```

**Option C: PM2 Deployment**
```bash
# Install PM2
npm install -g pm2

# Start with PM2
pm2 start src/server.js --name "auth-service"

# Save PM2 configuration
pm2 save
pm2 startup
```

#### 4. Reverse Proxy Configuration (Nginx)
```nginx
server {
    listen 80;
    server_name auth.yourdomain.com;
    
    location / {
        proxy_pass http://localhost:5002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

#### 5. SSL Configuration
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d auth.yourdomain.com
```

### Monitoring Setup

#### 1. Logging Configuration
```javascript
// Add to server.js
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});
```

#### 2. Health Monitoring
```bash
# Health check endpoint
curl https://auth.yourdomain.com/health

# Expected response
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## User Manual

### For Developers

#### Starting the Service
```bash
# Development mode
npm run dev

# Production mode
npm start
```

#### Testing the Service
```bash
# Run all tests
npm test

# Run specific test categories
npm run test:unit
npm run test:integration
npm run test:performance
```

#### API Testing
```bash
# Test registration
curl -X POST http://localhost:5002/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","firstName":"Test","lastName":"User"}'

# Test login
curl -X POST http://localhost:5002/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

### For System Administrators

#### Service Management
```bash
# Check service status
pm2 status

# Restart service
pm2 restart auth-service

# View logs
pm2 logs auth-service

# Monitor resources
pm2 monit
```

#### Database Connection
```bash
# Test database connectivity
curl http://localhost:5002/health

# Check database service
curl http://localhost:5001/health
```

## Update Manual

### Version Update Process

#### 1. Pre-Update Checklist
- [ ] Backup current configuration
- [ ] Review changelog and breaking changes
- [ ] Test in staging environment
- [ ] Notify stakeholders of maintenance window

#### 2. Update Steps
```bash
# 1. Stop service
pm2 stop auth-service

# 2. Backup current version
cp -r /app/auth-service /app/auth-service-backup-$(date +%Y%m%d)

# 3. Pull latest code
git pull origin main

# 4. Install dependencies
npm ci --only=production

# 5. Run migrations (if any)
npm run migrate

# 6. Start service
pm2 start auth-service

# 7. Verify health
curl http://localhost:5002/health
```

#### 3. Rollback Procedure
```bash
# If update fails, rollback
pm2 stop auth-service
rm -rf /app/auth-service
mv /app/auth-service-backup-$(date +%Y%m%d) /app/auth-service
pm2 start auth-service
```

#### 4. Post-Update Verification
- [ ] Health check passes
- [ ] Authentication flows work
- [ ] OAuth integration functional
- [ ] Database connections stable
- [ ] Logs show no errors

### Configuration Updates

#### Environment Variable Changes
```bash
# Edit environment file
nano .env

# Reload environment
pm2 reload auth-service

# Verify changes
curl http://localhost:5002/health
```

#### OAuth Configuration Updates
1. Update Google OAuth credentials in Google Cloud Console
2. Update `.env` file with new credentials
3. Restart service: `pm2 restart auth-service`
4. Test OAuth flow

## Monitoring & Troubleshooting

### Health Monitoring

#### Key Metrics to Monitor
- **Response Time**: < 200ms for authentication requests
- **Error Rate**: < 1% for all endpoints
- **Uptime**: > 99.9%
- **Memory Usage**: < 80% of allocated memory
- **CPU Usage**: < 70% average

#### Monitoring Commands
```bash
# Check service health
curl http://localhost:5002/health

# Check memory usage
pm2 monit

# View recent logs
pm2 logs auth-service --lines 100

# Check database connectivity
curl http://localhost:5001/health
```

### Common Issues & Solutions

#### 1. 500 Internal Server Error
**Symptoms**: Authentication requests return 500 error
**Causes**: Missing environment variables, database connection issues
**Solutions**:
```bash
# Check environment variables
grep -E "JWT_SECRET|GOOGLE_CLIENT_ID" .env

# Check database service
curl http://localhost:5001/health

# Check logs
pm2 logs auth-service --lines 50
```

#### 2. OAuth Callback Errors
**Symptoms**: Google OAuth redirect fails
**Causes**: Incorrect redirect URI, missing OAuth credentials
**Solutions**:
```bash
# Verify OAuth configuration
echo $GOOGLE_CLIENT_ID
echo $GOOGLE_CLIENT_SECRET

# Check redirect URI in Google Console
# Should be: https://auth.yourdomain.com/auth/google/callback
```

#### 3. JWT Token Issues
**Symptoms**: Invalid token errors, authentication failures
**Causes**: JWT secret mismatch, token expiration
**Solutions**:
```bash
# Verify JWT configuration
grep JWT_SECRET .env

# Check token expiration
# Default: 24 hours, configurable via JWT_EXPIRES_IN
```

#### 4. Rate Limiting Issues
**Symptoms**: Too many requests errors
**Causes**: High traffic, misconfigured rate limits
**Solutions**:
```bash
# Check rate limit configuration
grep RATE_LIMIT .env

# Adjust if needed
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100  # requests per window
```

### Log Analysis

#### Log Locations
```bash
# PM2 logs
pm2 logs auth-service

# Application logs (if configured)
tail -f logs/combined.log
tail -f logs/error.log
```

#### Key Log Patterns
```bash
# Authentication attempts
grep "auth.*attempt" logs/combined.log

# OAuth callbacks
grep "google.*callback" logs/combined.log

# Database errors
grep "database.*error" logs/combined.log

# Rate limiting
grep "rate.*limit" logs/combined.log
```

## Security Considerations

### Security Best Practices

#### 1. Environment Variables
- Never commit `.env` files to version control
- Use strong, unique secrets for each environment
- Rotate secrets regularly
- Use environment-specific configurations

#### 2. JWT Security
- Use strong JWT secrets (32+ characters)
- Set appropriate token expiration times
- Implement token refresh mechanism
- Validate token signature and expiration

#### 3. Password Security
- Passwords are hashed using bcryptjs
- Minimum password requirements enforced
- Password reset tokens have short expiration
- Rate limiting on authentication attempts

#### 4. OAuth Security
- Validate OAuth state parameter
- Verify OAuth provider responses
- Store OAuth tokens securely
- Implement proper error handling

#### 5. API Security
- CORS properly configured
- Rate limiting enabled
- Input validation on all endpoints
- Security headers implemented

### Security Headers
```javascript
// Implemented security headers
helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});
```

### Vulnerability Scanning
```bash
# Run security audit
npm audit

# Fix vulnerabilities
npm audit fix

# Update dependencies
npm update
```

## Testing

### Test Structure
```
src/test/
├── basic.test.js          # Unit tests
├── working.test.js        # Integration tests
├── simple-test.js         # Test runner
└── utils/
    └── testHelpers.js     # Test utilities
```

### Running Tests
```bash
# Run all tests
npm test

# Run specific test categories
npm run test:unit
npm run test:integration
npm run test:performance

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

### Test Categories

#### Unit Tests
- Password hashing and validation
- JWT token generation and validation
- Input validation
- Utility functions

#### Integration Tests
- API endpoint testing
- Database operations
- OAuth flow testing
- Error handling

#### Performance Tests
- Load testing
- Memory usage
- Response time testing
- Concurrent user testing

### Test Coverage
- **Target Coverage**: > 80%
- **Critical Paths**: 100% coverage
- **Error Handling**: 100% coverage
- **Security Functions**: 100% coverage

---

## Support & Maintenance

### Contact Information
- **Developer**: DarylNyd
- **Repository**: [Auth Service Repository]
- **Documentation**: This file

### Maintenance Schedule
- **Security Updates**: Monthly
- **Dependency Updates**: Quarterly
- **Performance Reviews**: Monthly
- **Backup Verification**: Weekly

### Emergency Procedures
1. **Service Down**: Check health endpoint and logs
2. **Security Breach**: Rotate all secrets immediately
3. **Database Issues**: Verify database service connectivity
4. **OAuth Issues**: Check provider status and credentials

---

*Last Updated: January 2024*
*Version: 1.0.0*
