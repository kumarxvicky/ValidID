
require('dotenv').config();

const crypto = require('node:crypto');
const path = require('node:path');

const express = require('express');
const session = require('express-session');
const sql = require('mssql/msnodesqlv8');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

// ========================================
// 1. ENVIRONMENT CONFIGURATION
// ========================================

const requiredEnvironment = [
    'DB_SERVER',
    'DB_NAME',
    'SESSION_SECRET'
];

const missingEnvironment = requiredEnvironment.filter(
    name => !process.env[name]
);

if (missingEnvironment.length > 0) {
    console.error(
        'Missing environment values:',
        missingEnvironment.join(', ')
    );
    process.exit(1);
}

if (process.env.SESSION_SECRET.length < 32) {
    console.error(
        'SESSION_SECRET must be at least 32 characters.'
    );
    process.exit(1);
}

// ========================================
// 2. EXPRESS APP
// ========================================

const app = express();

const PORT = Number(process.env.PORT || 3000);

const isProduction =
    process.env.NODE_ENV === 'production';

// ========================================
// 3. SQL SERVER CONFIGURATION
// ========================================

// Windows Authentication
// No SQL username or password required.


const serverName = process.env.DB_SERVER;

const dbConfig = {
    server: serverName,
    database: process.env.DB_NAME,

    driver: 'ODBC Driver 18 for SQL Server',

    options: {
        trustedConnection: true,
        instanceName: process.env.DB_INSTANCE,
        encrypt: process.env.DB_ENCRYPT === 'true',
        trustServerCertificate:
            process.env.DB_TRUST_SERVER_CERTIFICATE === 'true'
    },

    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000
    }
};


// ========================================
// 4. DATABASE CONNECTION POOL
// ========================================

const pool = new sql.ConnectionPool(dbConfig);

const poolConnect = pool.connect();

// ========================================
// 5. MIDDLEWARE
// ========================================

if (isProduction) {
    app.set('trust proxy', 1);
}

app.use(helmet());

app.use(express.json({
    limit: '10kb'
}));

app.use(express.urlencoded({
    extended: false,
    limit: '10kb'
}));

// ========================================
// 6. SESSION CONFIGURATION
// ========================================

// MemoryStore is suitable for local development only.
// Use a persistent SQL Server session store in production.

app.use(session({
    name: 'identify.sid',

    secret: process.env.SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// ========================================
// 7. RATE LIMITER
// ========================================

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,

    limit: 10,

    standardHeaders: 'draft-8',

    legacyHeaders: false,

    message: {
        error: 'Too many attempts. Please try again later.'
    }
});

// ========================================
// 8. CSRF TOKEN FUNCTIONS
// ========================================

function newCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

function requireCsrf(req, res, next) {

    const token = req.get('x-csrf-token');

    if (
        !token ||
        !req.session.csrfToken ||
        token !== req.session.csrfToken
    ) {
        return res.status(403).json({
            error: 'Session expired. Refresh the page and try again.'
        });
    }

    next();
}

// ========================================
// 9. SESSION ROTATION
// ========================================

function rotateSession(req, userId) {

    return new Promise((resolve, reject) => {

        req.session.regenerate(error => {

            if (error) {
                return reject(error);
            }

            req.session.userId = userId;

            req.session.csrfToken = newCsrfToken();

            req.session.save(saveError => {

                if (saveError) {
                    return reject(saveError);
                }

                resolve();
            });
        });
    });
}

// ========================================
// 10. USER RESPONSE FUNCTION
// ========================================
async function requireAdmin(req, res, next) {
    try {
        if (!req.session.userId) {
            return res.status(401).json({
                error: 'Please sign in.'
            });
        }

        await poolConnect;

        const result = await pool.request()
            .input('id', sql.BigInt, req.session.userId)
            .query(`
                SELECT role, is_active
                FROM dbo.users
                WHERE id = @id
            `);

        const user = result.recordset[0];

        if (!user || !user.is_active) {
            return res.status(403).json({
                error: 'Account is inactive.'
            });
        }

        if (user.role !== 'admin') {
            return res.status(403).json({
                error: 'Administrator access required.'
            });
        }

        next();

    } catch (error) {
        next(error);
    }
}

function safeUser(row) {
    return {
        id: row.public_id,
        name: row.full_name,
        email: row.email,
        role: row.role,
        isActive: row.is_active,
        createdAt: row.created_at
    };
}
// ========================================
// 11. AUTHENTICATION MIDDLEWARE
// ========================================

function requireUser(req, res, next) {

    if (!req.session.userId) {

        return res.status(401).json({
            error: 'Please sign in to continue.'
        });
    }

    next();
}

// ========================================
// 12. CSRF API
// ========================================

app.get('/api/csrf', (req, res) => {

    if (!req.session.csrfToken) {
        req.session.csrfToken = newCsrfToken();
    }

    res.json({
        csrfToken: req.session.csrfToken
    });
});

// ========================================
// 13. USER REGISTRATION
// ========================================

app.post(
    '/api/register',
    authLimiter,
    requireCsrf,
    async (req, res, next) => {

        try {

            const name =
                typeof req.body.name === 'string'
                    ? req.body.name.trim()
                    : '';

            const email =
                typeof req.body.email === 'string'
                    ? req.body.email.trim().toLowerCase()
                    : '';

            const password =
                typeof req.body.password === 'string'
                    ? req.body.password
                    : '';

            // Validate name

            if (name.length < 2 || name.length > 100) {

                return res.status(400).json({
                    error: 'Enter a name between 2 and 100 characters.'
                });
            }

            // Validate email

            if (
                !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
                email.length > 254
            ) {

                return res.status(400).json({
                    error: 'Enter a valid email address.'
                });
            }

            // Validate password

            if (password.length < 10 || password.length > 72) {

                return res.status(400).json({
                    error: 'Password must be between 10 and 72 characters.'
                });
            }

            await poolConnect;

            // Check existing user

            const existing = await pool.request()
                .input('email', sql.NVarChar(254), email)
                .query(`
                    SELECT TOP 1 id
                    FROM dbo.users
                    WHERE email = @email
                `);

            if (existing.recordset.length > 0) {

                return res.status(409).json({
                    error: 'This email is already registered.'
                });
            }

            // Hash password

            const passwordHash = await bcrypt.hash(password, 12);

            const publicId = crypto.randomUUID();

            // Insert user into SQL Server

            const result = await pool.request()

                .input('public_id', sql.Char(36), publicId)

                .input('full_name', sql.NVarChar(100), name)

                .input('email', sql.NVarChar(254), email)

                .input('password_hash', sql.NVarChar(255), passwordHash)

                .query(`
                    INSERT INTO dbo.users
                    (
                        public_id,
                        full_name,
                        email,
                        password_hash
                    )
                    OUTPUT
                        
                        INSERTED.id,
                        INSERTED.public_id,
                        INSERTED.full_name,
                        INSERTED.email,
                        INSERTED.role,
                        INSERTED.is_active,
                        INSERTED.created_at
                    VALUES
                    (
                        @public_id,
                        @full_name,
                        @email,
                        @password_hash
                    )
                `);

            const user = result.recordset[0];

            // Create session

            await rotateSession(req, user.id);

            res.status(201).json({
                user: safeUser(user),
                csrfToken: req.session.csrfToken
            });

        } catch (error) {

            if (
                error.number === 2627 ||
                error.number === 2601
            ) {
                return res.status(409).json({
                    error: 'This email is already registered.'
                });
            }

            next(error);
        }
    }
);

// ========================================
// 14. USER LOGIN
// ========================================

app.post(
    '/api/login',
    authLimiter,
    requireCsrf,
    async (req, res, next) => {

        try {

            const email =
                typeof req.body.email === 'string'
                    ? req.body.email.trim().toLowerCase()
                    : '';

            const password =
                typeof req.body.password === 'string'
                    ? req.body.password
                    : '';

            await poolConnect;

            // Find user

            
                
const result = await pool.request()
    .input('email', sql.NVarChar(254), email)
    .query(`
        SELECT TOP 1
            id,
            public_id,
            full_name,
            email,
            password_hash,
            role,
            is_active,
            created_at
        FROM dbo.users
        WHERE email = @email
    `);


            const user = result.recordset[0];
if (user && !user.is_active) {
    return res.status(403).json({
        error: 'Your account has been disabled.'
    });
}
            // Compare password

            const passwordMatches = user
                ? await bcrypt.compare(password, user.password_hash)
                : false;

            if (!passwordMatches) {

                return res.status(401).json({
                    error: 'The email or password is incorrect.'
                });
            }

            // Create authenticated session

            await rotateSession(req, user.id);

            res.json({
                user: safeUser(user),
                csrfToken: req.session.csrfToken
            });

        } catch (error) {

            next(error);
        }
    }
);

// ========================================
// 15. CURRENT USER API
// ========================================

app.get('/api/me', async (req, res, next) => {

    try {

        if (!req.session.userId) {

            return res.status(401).json({
                error: 'Please sign in to continue.'
            });
        }

        await poolConnect;

        const result = await pool.request()

            .input('id', sql.BigInt, req.session.userId)

            .query(`
                SELECT TOP 1
                public_id,
                full_name,
                email,
                role,
                is_active,
                created_at
                FROM dbo.users
                WHERE id = @id
            `);

        if (result.recordset.length === 0) {

            return req.session.destroy(() => {

                res.status(401).json({
                    error: 'Account could not be found.'
                });
            });
        }

        res.json({
            user: safeUser(result.recordset[0])
        });

    } catch (error) {

        next(error);
    }
});

// ========================================
// 16. USER LOGOUT
// ========================================

app.post(
    '/api/logout',
    requireCsrf,
    requireUser,
    (req, res, next) => {

        req.session.destroy(error => {

            if (error) {
                return next(error);
            }

            res.clearCookie('identify.sid', {
                httpOnly: true,
                secure: isProduction,
                sameSite: 'strict'
            });

            res.status(204).end();
        });
    }
);

// ========================================
// 17. SERVE FRONTEND FILES
// ========================================

app.use(express.static(
    path.join(__dirname, 'public'),
    {
        extensions: ['html']
    }
));

// ========================================
// 18. INVALID API ROUTES
// ========================================

app.use('/api', (req, res) => {

    res.status(404).json({
        error: 'That service was not found.'
    });
});

// ========================================
// 19. GLOBAL ERROR HANDLER
// ========================================

app.use((error, req, res, next) => {

    console.error('Server error:', error);

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        error: 'Something went wrong. Please try again.'
    });
});

// ========================================
// 20. START SERVER
// ========================================

async function start() {

    try {

        console.log('Connecting to SQL Server...');

        await poolConnect;

        await pool.request().query('SELECT 1');

        console.log('SQL Server connected successfully!');

        app.listen(PORT, () => {

            console.log(
                `Identity Portal running at http://localhost:${PORT}`
            );

        });

    } catch (error) {

        console.error('SQL Server connection failed!');

        console.error(error.message);

        await pool.close().catch(() => {});

        process.exit(1);
    }
}

// ========================================
// 21. GRACEFUL SHUTDOWN
// ========================================

async function shutdown() {

    console.log('Shutting down server...');

    await pool.close().catch(console.error);

    process.exit(0);
}

process.on('SIGINT', shutdown);

process.on('SIGTERM', shutdown);

// Start application

start();
// ========================================
// ADMIN: CHANGE USER ROLE
// ========================================

app.patch(
    '/api/admin/users/:id/role',
    requireCsrf,
    requireAdmin,
    async (req, res, next) => {
        try {
            const { role } = req.body;
            const publicId = req.params.id;

            if (!['user', 'admin'].includes(role)) {
                return res.status(400).json({
                    error: 'Invalid role.'
                });
            }

            const result = await pool.request()
                .input('publicId', sql.Char(36), publicId)
                .input('role', sql.NVarChar(20), role)
                .query(`
                    UPDATE dbo.users
                    SET role = @role
                    WHERE public_id = @publicId
                `);

            if (result.rowsAffected[0] === 0) {
                return res.status(404).json({
                    error: 'User not found.'
                });
            }

            res.json({
                message: 'User role updated successfully.'
            });

        } catch (error) {
            next(error);
        }
    }
);
// ========================================
// ADMIN: CHANGE ACCOUNT STATUS
// ========================================

app.patch(
    '/api/admin/users/:id/status',
    requireCsrf,
    requireAdmin,
    async (req, res, next) => {
        try {
            const { isActive } = req.body;

            if (typeof isActive !== 'boolean') {
                return res.status(400).json({
                    error: 'Invalid account status.'
                });
            }

            const result = await pool.request()
                .input('publicId', sql.Char(36), req.params.id)
                .input('isActive', sql.Bit, isActive)
                .query(`
                    UPDATE dbo.users
                    SET is_active = @isActive
                    WHERE public_id = @publicId
                `);

            if (result.rowsAffected[0] === 0) {
                return res.status(404).json({
                    error: 'User not found.'
                });
            }

            res.json({
                message: 'Account status updated successfully.'
            });

        } catch (error) {
            next(error);
        }
    }
);
