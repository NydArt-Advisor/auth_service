require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const { passport } = require('./middleware/auth');
const { generalLimiter } = require('./middleware/rateLimit');
const authRoutes = require('./routes/auth');
const twoFactorRoutes = require('./routes/twoFactorRoutes');
const promClient = require('prom-client');
const register = promClient.register;
promClient.collectDefaultMetrics({ register });

const app = express();

// Trust proxy configuration for rate limiting behind load balancers/proxies
app.set('trust proxy', 1);

// Apply general rate limiting to all routes
app.use(generalLimiter);

// Enhanced CORS configuration
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            process.env.CLIENT_URL,
            process.env.FRONTEND_URL,
            process.env.AUTH_SERVICE_URL,
            process.env.DATABASE_SERVICE_URL,
            process.env.PAYMENT_SERVICE_URL,
            process.env.AI_SERVICE_URL,
            process.env.NOTIFICATION_SERVICE_URL,
            process.env.METRICS_SERVICE_URL,
            // Add both Vercel domains
            'https://nydartadvisor-p3gw0m3og-darylnyds-projects.vercel.app',
            'https://nydartadvisor.vercel.app',
            'https://nydartadvisor-git-main-darylnyds-projects.vercel.app',
            // Add any other Vercel preview domains
            /^https:\/\/nydartadvisor.*\.vercel\.app$/,
        ];
        
        // Check if origin matches any allowed origins
        const isAllowed = allowedOrigins.some(allowedOrigin => {
            if (typeof allowedOrigin === 'string') {
                return origin === allowedOrigin;
            } else if (allowedOrigin instanceof RegExp) {
                return allowedOrigin.test(origin);
            }
            return false;
        });
        
        if (isAllowed) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            // For development, allow all origins
            if (process.env.NODE_ENV === 'development') {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'X-Requested-With',
        'Accept',
        'Origin',
        'Access-Control-Request-Method',
        'Access-Control-Request-Headers'
    ],
    exposedHeaders: ['Content-Length', 'X-Requested-With'],
    preflightContinue: false,
    optionsSuccessStatus: 204
}));

// Add additional headers middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Session configuration with enhanced security
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
    name: 'nydart-session' // Change default session name for security
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.send("Authentication Service is running");
});

// Routes
app.use('/auth', authRoutes);
app.use('/two-factor', twoFactorRoutes);

// Health check route
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        service: 'Authentication Service',
        environment: process.env.NODE_ENV,
        timestamp: new Date().toISOString()
    });
});

// Metrics route
app.get('/metrics', async (req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        message: 'Route not found',
        path: req.originalUrl
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error occurred:', err);
    
    // Handle specific error types
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            message: 'Validation error',
            error: process.env.NODE_ENV === 'development' ? err.message : 'Invalid input data'
        });
    }
    
    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({
            message: 'Unauthorized',
            error: 'Invalid or missing authentication token'
        });
    }
    
    res.status(500).json({
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
});

// Unhandled rejection handler
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

const PORT = process.env.PORT || 5002;

try {
    app.listen(PORT, () => {
        console.log(`Authentication service running on port ${PORT}`);
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
} catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
} 