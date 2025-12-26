// server.js - Vercel Serverless compatible
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: ['https://3k214.dfi.fund', 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// PostgreSQL connection
let pool;
try {
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
    console.log('Database pool created');
} catch (error) {
    console.error('Database pool error:', error.message);
}

// === FIXED STATIC FILE SERVING ===
// 1. Serve public assets
app.use('/public', express.static(path.join(__dirname, 'public')));

// 2. Serve CSS, JS, images directly from root for convenience
app.use('/css', express.static(path.join(__dirname, 'public/css')));
app.use('/js', express.static(path.join(__dirname, 'public/js')));
app.use('/images', express.static(path.join(__dirname, 'public/images')));

// === SPECIFIC HTML ROUTES (MUST COME BEFORE STATIC) ===
// Serve HTML files without .html extension
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates/login.html'));
});

app.get('/dashboard', (req, res) => {
    // Check authentication here if needed
    res.sendFile(path.join(__dirname, 'templates/dashboard.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates/index.html'));
});

// === API ROUTES ===
// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access token required' 
        });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        req.user = user;
        next();
    });
};

// Health endpoint
app.get('/api/health', async (req, res) => {
    try {
        let dbStatus = 'unknown';
        if (pool) {
            await pool.query('SELECT NOW()');
            dbStatus = 'connected';
        }
        
        res.json({
            success: true,
            service: 'KokKokKok API v2.1.4',
            status: 'online',
            timestamp: new Date().toISOString(),
            database: dbStatus,
            environment: process.env.NODE_ENV || 'development'
        });
    } catch (error) {
        res.json({
            success: true,
            service: 'KokKokKok API v2.1.4',
            status: 'online',
            timestamp: new Date().toISOString(),
            database: 'disconnected',
            error: error.message
        });
    }
});

// Add this after your other API routes
app.get('/api/auth/health', async (req, res) => {
    try {
        let dbStatus = 'unknown';
        if (pool) {
            await pool.query('SELECT NOW()');
            dbStatus = 'connected';
        }
        
        res.json({
            success: true,
            service: 'KokKokKok API v2.1.4',
            status: 'online',
            timestamp: new Date().toISOString(),
            database: dbStatus,
            environment: process.env.NODE_ENV || 'development'
        });
    } catch (error) {
        res.json({
            success: true,
            service: 'KokKokKok API v2.1.4',
            status: 'online',
            timestamp: new Date().toISOString(),
            database: 'disconnected',
            error: error.message
        });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        
        if (!pool) {
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        const result = await pool.query(
            `SELECT id, user_id, email, name, password_hash
             FROM users WHERE email = $1 OR user_id = $1`,
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        const token = jwt.sign(
            {
                userId: user.id,
                user_id: user.user_id,
                email: user.email
            },
            process.env.JWT_SECRET || 'development-secret',
            { expiresIn: '7d' }
        );
        
        const { password_hash, ...userData } = user;
        
        res.json({
            success: true,
            token,
            user: userData,
            message: 'Login successful',
            // Add redirect URL in response
            redirect: '/dashboard'
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
});

// Update profile endpoint
app.put('/api/auth/update-profile', authenticateToken, async (req, res) => {
    console.log('📝 Update profile request received');
    console.log('User from token:', req.user);
    
    try {
        const { name } = req.body;
        
        // Extract userId from token - your token has "userId" field
        const userId = req.user.userId;
        
        console.log('Request data:', { 
            name, 
            userId,
            tokenContains: req.user 
        });
        
        if (!name || name.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Name is required'
            });
        }

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required. Token contains: ' + JSON.stringify(req.user)
            });
        }

        if (!pool) {
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
            });
        }

        const query = 'UPDATE users SET name = $1 WHERE id = $2 RETURNING id, name, email, created_at';
        const values = [name.trim(), userId];
        
        console.log('Executing query:', query, 'with values:', values);
        
        const result = await pool.query(query, values);
        
        if (result.rowCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found with ID: ' + userId
            });
        }

        console.log('✅ Profile updated successfully:', result.rows[0]);
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('❌ Server error updating profile:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating profile',
            error: error.message
        });
    }
});

// === STATIC FILE ROUTES (COMES AFTER SPECIFIC ROUTES) ===
// Serve .html files directly from templates
app.use(express.static(path.join(__dirname, 'templates'), {
    index: false, // Don't auto-serve index.html
    extensions: ['html'] // Only serve .html files
}));

// === CATCH-ALL ROUTES (MUST BE LAST) ===
// Catch-all for API routes - return 404
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

// Catch-all for other routes - serve index.html for SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates/index.html'));
});

// Add this debug endpoint to server.js (temporary)
app.get('/api/auth/debug-token', authenticateToken, (req, res) => {
    res.json({
        success: true,
        user: req.user,
        message: 'Token is valid'
    });
});

// Export for Vercel serverless
module.exports = app;

// For local development
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}