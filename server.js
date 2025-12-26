// server.js - Vercel Serverless compatible
const express = require('express');
const cors = require('cors');
const path = require('path');
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

// Health endpoint - ALWAYS WORK
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
            message: 'Login successful'
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
app.put('/api/auth/update-profile', async (req, res) => {
    console.log('📝 Update profile request received');
    
    try {
        const { name, userId } = req.body;
        
        console.log('Request data:', { name, userId });
        
        if (!name || name.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Name is required'
            });
        }
        
        if (name.length > 100) {
            return res.status(400).json({
                success: false,
                message: 'Name must be 100 characters or less'
            });
        }
        
        // Simple verification
        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }
        
        // Get database pool
        const dbPool = getPool();
        if (!dbPool) {
            return res.status(503).json({
                success: false,
                message: 'Database service temporarily unavailable'
            });
        }
        
        // Update in database
        const result = await dbPool.query(
            `UPDATE users 
             SET name = $1, updated_at = NOW()
             WHERE id = $2 OR user_id = $2
             RETURNING id, user_id, email, name, profile_picture, updated_at`,
            [name.trim(), userId]
        );
        
        if (result.rows.length === 0) {
            console.log('User not found:', userId);
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        console.log('✅ Name updated successfully for user:', userId);
        
        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('❌ Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error updating profile: ' + error.message
        });
    }
});

// Get profile endpoint (optional but useful)
app.get('/api/auth/profile', async (req, res) => {
    try {
        const { userId } = req.query;
        
        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }
        
        const dbPool = getPool();
        if (!dbPool) {
            return res.status(503).json({
                success: false,
                message: 'Database service temporarily unavailable'
            });
        }
        
        const result = await dbPool.query(
            `SELECT id, user_id, email, name, profile_picture, 
                    wallet_address, nft_tier, created_at, updated_at
             FROM users 
             WHERE id = $1 OR user_id = $1`,
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch profile'
        });
    }
});

// Static files - Serve from templates directory
app.use(express.static(path.join(__dirname, 'templates')));

// Serve specific HTML files
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates/login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates/dashboard.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates/index.html'));
});

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

// Export for Vercel serverless
module.exports = app;

// For local development
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}