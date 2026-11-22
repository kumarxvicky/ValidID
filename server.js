require('dotenv').config();

const crypto = require('node:crypto');
const path = require('node:path');

const express = require('express');
const session = require('express-session');
const sql = require('mssql/msnodesqlv8');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

// 1. Environment
const requiredEnvironment = ['DB_SERVER', 'DB_NAME', 'SESSION_SECRET'];
const missingEnvironment = requiredEnvironment.filter(name => !process.env[name]);

if (missingEnvironment.length) {
    console.error('Missing environment values:', missingEnvironment.join(', '));
    process.exit(1);
}

if (process.env.SESSION_SECRET.length < 32) {
    console.error('SESSION_SECRET must be at least 32 characters.');
    process.exit(1);
}

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

// 2. SQL Server (Windows Authentication)
const dbConfig = {
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    driver: 'ODBC Driver 18 for SQL Server',
    options: {
        trustedConnection: true,
        ...(process.env.DB_INSTANCE ? { instanceName: process.env.DB_INSTANCE } : {}),
        encrypt: process.env.DB_ENCRYPT === 'true',
        trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE === 'true'
    },
    pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

const pool = new sql.ConnectionPool(dbConfig);
const poolConnect = pool.connect();

// 3. Middleware
if (isProduction) app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// MemoryStore is for local development. Use a persistent session store for production.
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

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'Too many attempts. Please try again later.' }
});

// 4. Helpers and middleware
function newCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

function requireCsrf(req, res, next) {
    const token = req.get('x-csrf-token');
    if (!token || !req.session.csrfToken || token !== req.session.csrfToken) {
        return res.status(403).json({
            error: 'Session expired. Refresh the page and try again.'
        });
    }
    next();
}

function rotateSession(req, userId) {
    return new Promise((resolve, reject) => {
        req.session.regenerate(error => {
            if (error) return reject(error);
            req.session.userId = userId;
            req.session.csrfToken = newCsrfToken();
            req.session.save(saveError => {
                if (saveError) return reject(saveError);
                resolve();
            });
        });
    });
}

function safeUser(row) {
    return {
        id: row.public_id,
        name: row.full_name,
        email: row.email,
        role: row.role,
        isActive: Boolean(row.is_active),
        createdAt: row.created_at
    };
}

function requireUser(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Please sign in to continue.' });
    }
    next();
}

async function requireAdmin(req, res, next) {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Please sign in.' });
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
            return res.status(403).json({ error: 'Account is inactive.' });
        }
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Administrator access required.' });
        }
        next();
    } catch (error) {
        next(error);
    }
}

// 5. CSRF token endpoint
app.get('/api/csrf', (req, res) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = newCsrfToken();
    }
    res.json({ csrfToken: req.session.csrfToken });
});

// 6. Registration
app.post('/api/register', authLimiter, requireCsrf, async (req, res, next) => {
    try {
        const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
        const email = typeof req.body.email === 'string'
            ? req.body.email.trim().toLowerCase()
            : '';
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        if (name.length < 2 || name.length > 100) {
            return res.status(400).json({ error: 'Enter a name between 2 and 100 characters.' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
            return res.status(400).json({ error: 'Enter a valid email address.' });
        }
        if (password.length < 10 || password.length > 72) {
            return res.status(400).json({ error: 'Password must be between 10 and 72 characters.' });
        }

        await poolConnect;

        const existing = await pool.request()
            .input('email', sql.NVarChar(254), email)
            .query('SELECT TOP 1 id FROM dbo.users WHERE email = @email');

        if (existing.recordset.length) {
            return res.status(409).json({ error: 'This email is already registered.' });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const publicId = crypto.randomUUID();

        const result = await pool.request()
            .input('public_id', sql.Char(36), publicId)
            .input('full_name', sql.NVarChar(100), name)
            .input('email', sql.NVarChar(254), email)
            .input('password_hash', sql.NVarChar(255), passwordHash)
            .query(`
                INSERT INTO dbo.users
                    (public_id, full_name, email, password_hash)
                OUTPUT
                    INSERTED.id,
                    INSERTED.public_id,
                    INSERTED.full_name,
                    INSERTED.email,
                    INSERTED.role,
                    INSERTED.is_active,
                    INSERTED.created_at
                VALUES
                    (@public_id, @full_name, @email, @password_hash)
            `);

        const user = result.recordset[0];
        await rotateSession(req, user.id);

        res.status(201).json({
            user: safeUser(user),
            csrfToken: req.session.csrfToken
        });
    } catch (error) {
        if (error.number === 2627 || error.number === 2601) {
            return res.status(409).json({ error: 'This email is already registered.' });
        }
        next(error);
    }
});

// 7. Login
app.post('/api/login', authLimiter, requireCsrf, async (req, res, next) => {
    try {
        const email = typeof req.body.email === 'string'
            ? req.body.email.trim().toLowerCase()
            : '';
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        if (!email || !password) {
            return res.status(400).json({ error: 'Enter your email and password.' });
        }

        await poolConnect;
        const result = await pool.request()
            .input('email', sql.NVarChar(254), email)
            .query(`
                SELECT TOP 1
                    id, public_id, full_name, email, password_hash,
                    role, is_active, created_at
                FROM dbo.users
                WHERE email = @email
            `);

        const user = result.recordset[0];

        if (!user) {
            return res.status(401).json({ error: 'The email or password is incorrect.' });
        }
        if (!user.is_active) {
            return res.status(403).json({ error: 'Your account has been disabled.' });
        }

        const passwordMatches = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatches) {
            return res.status(401).json({ error: 'The email or password is incorrect.' });
        }

        await rotateSession(req, user.id);
        res.json({ user: safeUser(user), csrfToken: req.session.csrfToken });
    } catch (error) {
        next(error);
    }
});

// 8. Current user
app.get('/api/me', async (req, res, next) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Please sign in to continue.' });
        }

        await poolConnect;
        const result = await pool.request()
            .input('id', sql.BigInt, req.session.userId)
            .query(`
                SELECT TOP 1
                    public_id, full_name, email, role, is_active, created_at
                FROM dbo.users
                WHERE id = @id
            `);

        const user = result.recordset[0];
        if (!user || !user.is_active) {
            return req.session.destroy(() => {
                res.clearCookie('identify.sid');
                res.status(401).json({ error: 'Your session is no longer valid. Please sign in again.' });
            });
        }

        res.json({ user: safeUser(user) });
    } catch (error) {
        next(error);
    }
});

// 9. Admin: list users (password hashes are never selected)
app.get('/api/admin/users', requireAdmin, async (req, res, next) => {
    try {
        await poolConnect;
        const result = await pool.request().query(`
            SELECT public_id, full_name, email, role, is_active, created_at
            FROM dbo.users
            ORDER BY created_at DESC
        `);
        res.json({ users: result.recordset.map(safeUser) });
    } catch (error) {
        next(error);
    }
});

// 10. Admin: update role
app.patch('/api/admin/users/:id/role', requireCsrf, requireAdmin, async (req, res, next) => {
    try {
        const { role } = req.body;
        const publicId = req.params.id;

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role.' });
        }

        await poolConnect;
        const target = await pool.request()
            .input('publicId', sql.Char(36), publicId)
            .query('SELECT id, role FROM dbo.users WHERE public_id = @publicId');

        if (!target.recordset.length) {
            return res.status(404).json({ error: 'User not found.' });
        }

        if (String(target.recordset[0].id) === String(req.session.userId) && role !== 'admin') {
            return res.status(400).json({ error: 'You cannot remove your own administrator role.' });
        }

        if (target.recordset[0].role === 'admin' && role !== 'admin') {
            const count = await pool.request().query(`
                SELECT COUNT(*) AS adminCount
                FROM dbo.users
                WHERE role = 'admin' AND is_active = 1
            `);
            if (count.recordset[0].adminCount <= 1) {
                return res.status(400).json({ error: 'You cannot demote the last active administrator.' });
            }
        }

        await pool.request()
            .input('publicId', sql.Char(36), publicId)
            .input('role', sql.NVarChar(20), role)
            .query('UPDATE dbo.users SET role = @role WHERE public_id = @publicId');

        res.json({ message: 'User role updated successfully.' });
    } catch (error) {
        next(error);
    }
});

// 11. Admin: enable/disable account
app.patch('/api/admin/users/:id/status', requireCsrf, requireAdmin, async (req, res, next) => {
    try {
        const { isActive } = req.body;
        const publicId = req.params.id;

        if (typeof isActive !== 'boolean') {
            return res.status(400).json({ error: 'Invalid account status.' });
        }

        await poolConnect;
        const target = await pool.request()
            .input('publicId', sql.Char(36), publicId)
            .query('SELECT id, role, is_active FROM dbo.users WHERE public_id = @publicId');

        if (!target.recordset.length) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const targetUser = target.recordset[0];
        if (String(targetUser.id) === String(req.session.userId) && !isActive) {
            return res.status(400).json({ error: 'You cannot disable your own account.' });
        }

        if (targetUser.role === 'admin' && targetUser.is_active && !isActive) {
            const count = await pool.request().query(`
                SELECT COUNT(*) AS adminCount
                FROM dbo.users
                WHERE role = 'admin' AND is_active = 1
            `);
            if (count.recordset[0].adminCount <= 1) {
                return res.status(400).json({ error: 'You cannot disable the last active administrator.' });
            }
        }

        await pool.request()
            .input('publicId', sql.Char(36), publicId)
            .input('isActive', sql.Bit, isActive)
            .query('UPDATE dbo.users SET is_active = @isActive WHERE public_id = @publicId');

        res.json({ message: 'Account status updated successfully.' });
    } catch (error) {
        next(error);
    }
});

// 12. Logout
app.post('/api/logout', requireCsrf, requireUser, (req, res, next) => {
    req.session.destroy(error => {
        if (error) return next(error);
        res.clearCookie('identify.sid', {
            httpOnly: true,
            secure: isProduction,
            sameSite: 'strict'
        });
        res.status(204).end();
    });
});

// 13. Static files (routes above must be registered before the API 404 handler)
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.use('/api', (req, res) => {
    res.status(404).json({ error: 'That service was not found.' });
});

// 14. Error handler (must be last)
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    if (res.headersSent) return next(error);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

// 15. Start
async function start() {
    try {
        console.log('Connecting to SQL Server...');
        await poolConnect;
        await pool.request().query('SELECT 1');
        console.log('SQL Server connected successfully!');
        app.listen(PORT, () => {
            console.log(`Identity Portal running at http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('SQL Server connection failed:', error);
        await pool.close().catch(() => {});
        process.exit(1);
    }
}

async function shutdown() {
    console.log('Shutting down server...');
    await pool.close().catch(console.error);
    process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
start();
