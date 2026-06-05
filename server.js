"use strict";

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

// ══════════════════════════════════════════════════════════════════════════════
//  ENVIRONMENT VALIDATION
//  Fail fast — never run with missing or defaulted secrets.
// ══════════════════════════════════════════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

if (!JWT_SECRET || !ADMIN_USER || !ADMIN_PASS) {
    console.error("[Startup] FATAL: JWT_SECRET, ADMIN_USER, and ADMIN_PASS must be set in environment variables.");
    process.exit(1);
}

// ── Security constants ─────────────────────────────────────────────────────────
const SALT_ROUNDS = 12;   // ~250 ms per hash — strong defence against offline brute-force
const DELIVERY_FEE = 30.00;

// ── JWT expiry constants ───────────────────────────────────────────────────────
// Access token: 7 days  — long enough for a comfortable shopping session.
// Refresh token: 30 days — lets users stay logged in across sessions.
// Both are configurable via env so staging/production can differ without code changes.
const JWT_ACCESS_EXPIRES = process.env.JWT_USER_EXPIRES_IN || "7d";
const JWT_REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES_IN || "30d";

// ── Allowed payment methods (whitelist-based — never trust free-text) ──────────
const ALLOWED_PAYMENT_METHODS = new Set(["cod", "upi", "card", "netbanking"]);

// ── Allowed order statuses (for admin PATCH) ───────────────────────────────────
const VALID_ORDER_STATUSES = ["pending", "confirmed", "shipped", "delivered", "cancelled"];

// ── Cart quantity bounds ───────────────────────────────────────────────────────
// Hard cap per line-item to prevent abuse (e.g. someone sending qty: 9999999)
const MAX_QTY_PER_ITEM = 100;

// ══════════════════════════════════════════════════════════════════════════════
//  RATE LIMITERS
// ══════════════════════════════════════════════════════════════════════════════

// Login: 5 attempts / 15 min per IP
const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.warn(`[Rate Limit] Login blocked for IP ${req.ip} at ${new Date().toISOString()}`);
        return res.status(429).json({
            status: "error",
            code: 429,
            message: "Too many login attempts. Please try again after 15 minutes.",
        });
    },
});

// Register: 10 attempts / 60 min per IP — prevents mass account creation
const registerRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.warn(`[Rate Limit] Register blocked for IP ${req.ip}`);
        return res.status(429).json({
            status: "error",
            code: 429,
            message: "Too many registration attempts. Please try again after 1 hour.",
        });
    },
});

// Token refresh: 30 calls / 15 min per IP
const refreshRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        return res.status(429).json({
            status: "error",
            code: 429,
            message: "Too many token refresh requests. Please try again shortly.",
        });
    },
});

// Cart merge: 20 calls / 5 min per IP — prevents brute-force token replay on merge
const cartMergeRateLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.warn(`[Rate Limit] Cart merge blocked for IP ${req.ip}`);
        return res.status(429).json({
            status: "error",
            code: 429,
            message: "Too many cart merge requests. Please slow down.",
        });
    },
});

// ══════════════════════════════════════════════════════════════════════════════
//  DATABASE POOL
// ══════════════════════════════════════════════════════════════════════════════
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    ssl: process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: true }   // Verifies Neon/RDS cert in production
        : false,
});

pool.on("error", (err) => { console.error("[pg Pool] Unexpected error on idle client:", err.message); });
pool.on("connect", () => { console.log("[pg Pool] New client connected to PostgreSQL."); });
pool.on("remove", () => { console.log("[pg Pool] Client removed from pool."); });

// ══════════════════════════════════════════════════════════════════════════════
//  EXPRESS APP
// ══════════════════════════════════════════════════════════════════════════════
const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());

// ── CORS ───────────────────────────────────────────────────────────────────────
// Production: restrict to the explicit FRONTEND_ORIGIN env var.
// Development: fall back to localhost on common ports so local dev still works.
// Never use "*" in production — it exposes the API to any origin.
const ALLOWED_ORIGINS = process.env.FRONTEND_ORIGIN
    ? process.env.FRONTEND_ORIGIN.split(",").map((o) => o.trim()).filter(Boolean)
    : ["http://localhost:3000", "http://localhost:5000", "http://127.0.0.1:5000"];

app.use(cors({
    origin: (origin, callback) => {
        // Allow server-to-server / curl requests (no Origin header)
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        console.warn(`[CORS] Blocked request from unlisted origin: ${origin}`);
        return callback(new Error(`CORS: origin "${origin}" is not allowed.`));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    credentials: true,
    optionsSuccessStatus: 200,
}));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH MIDDLEWARE
// ══════════════════════════════════════════════════════════════════════════════

// ── verifyAdmin ────────────────────────────────────────────────────────────────
// Hard gate for all admin-only endpoints.
// Rejects missing, malformed, expired, or non-admin tokens.
function verifyAdmin(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: missing or malformed Authorization header.",
        });
    }
    const token = authHeader.slice(7);
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        return next();
    } catch {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: invalid or expired token.",
        });
    }
}

// ── verifyUser ─────────────────────────────────────────────────────────────────
// Hard gate for user-only protected routes (order history, cart, profile).
// Rejects missing, malformed, expired tokens AND admin tokens.
// The role === "user" check prevents an admin token from being replayed here.
function verifyUser(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: missing or malformed Authorization header.",
        });
    }
    const token = authHeader.slice(7);
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded || decoded.role !== "user") {
            return res.status(403).json({
                status: "error", code: 403,
                message: "Forbidden: this endpoint requires a user token.",
            });
        }
        req.user = decoded;
        return next();
    } catch {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: invalid or expired token.",
        });
    }
}

// ── parseUserId ────────────────────────────────────────────────────────────────
// Safely extracts and validates the integer user id from a decoded JWT payload.
// Returns the integer, or NaN if the sub value is unusable.
// Defends against prototype-pollution and non-integer sub values.
function parseUserId(decoded) {
    if (!decoded || decoded.sub === undefined) return NaN;
    const id = Number.isInteger(decoded.sub)
        ? decoded.sub
        : parseInt(decoded.sub, 10);
    return (Number.isFinite(id) && id > 0) ? id : NaN;
}

// ══════════════════════════════════════════════════════════════════════════════
//  DATABASE INITIALISATION
//  All CREATE TABLE / ALTER TABLE statements are idempotent (IF NOT EXISTS /
//  IF NOT EXISTS column). Safe to re-run on every server boot.
// ══════════════════════════════════════════════════════════════════════════════
async function initializeDatabase() {
    let client;
    try {
        client = await pool.connect();
        console.log("[DB Init] Connected to PostgreSQL. Running table migrations...");

        // ── contact_submissions ────────────────────────────────────────────────
        await client.query(`
            CREATE TABLE IF NOT EXISTS contact_submissions (
                id         SERIAL       PRIMARY KEY,
                full_name  VARCHAR(255) NOT NULL,
                phone      VARCHAR(20)  NULL,
                email      VARCHAR(255) NOT NULL,
                subject    VARCHAR(100) NOT NULL,
                message    TEXT         NOT NULL,
                created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_contact_submissions_email
            ON contact_submissions (email);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_contact_submissions_created_at
            ON contact_submissions (created_at DESC);`);
        console.log("[DB Init] contact_submissions table is ready.");

        // ── products ───────────────────────────────────────────────────────────
        await client.query(`
            CREATE TABLE IF NOT EXISTS products (
                id             SERIAL        PRIMARY KEY,
                name           VARCHAR(255)  NOT NULL,
                description    TEXT,
                price          NUMERIC(10,2) NOT NULL,
                category       VARCHAR(100),
                in_stock       BOOLEAN       NOT NULL DEFAULT true,
                image_url      VARCHAR(512),
                created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
                stock_quantity INT           NOT NULL DEFAULT 50
                                             CHECK (stock_quantity >= 0)
            );
        `);
        console.log("[DB Init] products table is ready.");

        // ── users ──────────────────────────────────────────────────────────────
        // Must exist before orders (FK reference) and before carts.
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL        PRIMARY KEY,
                full_name     VARCHAR(255)  NOT NULL,
                email         VARCHAR(255)  NOT NULL UNIQUE,
                phone         VARCHAR(20)   NULL,
                password_hash VARCHAR(255)  NOT NULL,
                created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);`);

        // ── Phase 6 migration: add address columns to users ────────────────────
        // ADD COLUMN IF NOT EXISTS is idempotent — safe on every boot.
        await client.query(`
            ALTER TABLE users
                ADD COLUMN IF NOT EXISTS address  TEXT         NULL,
                ADD COLUMN IF NOT EXISTS pin_code VARCHAR(20)  NULL;
        `);
        console.log("[DB Init] users table is ready (with address + pin_code).");

        // ── orders ─────────────────────────────────────────────────────────────
        // user_id NOT NULL — Phase 6 drops guest checkout.
        // ON DELETE SET NULL: historical orders are preserved (anonymised)
        // if a user account is deleted. Correct for financial records.
        await client.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id             SERIAL        PRIMARY KEY,
                user_id        INT           NOT NULL
                                             REFERENCES users(id) ON DELETE SET NULL,
                customer_name  VARCHAR(255)  NOT NULL,
                email          VARCHAR(255)  NOT NULL,
                phone          VARCHAR(20)   NOT NULL,
                address        TEXT          NOT NULL,
                pin_code       VARCHAR(20)   NOT NULL,
                payment_method VARCHAR(50)   NOT NULL,
                total_amount   NUMERIC(10,2) NOT NULL,
                status         VARCHAR(50)   NOT NULL DEFAULT 'pending',
                created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
            );
        `);
        // Idempotent phase-5 backfill: if the table was created without the FK
        // by an earlier server version, add it now.
        await client.query(`
            ALTER TABLE orders
                ADD COLUMN IF NOT EXISTS user_id INT NULL
                    REFERENCES users(id) ON DELETE SET NULL;
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_orders_user_id
            ON orders (user_id) WHERE user_id IS NOT NULL;`);
        console.log("[DB Init] orders table is ready.");

        // ── order_items ────────────────────────────────────────────────────────
        await client.query(`
            CREATE TABLE IF NOT EXISTS order_items (
                id                SERIAL        PRIMARY KEY,
                order_id          INT           NOT NULL
                                  REFERENCES orders(id) ON DELETE CASCADE,
                product_id        INT           NOT NULL,
                name_at_purchase  VARCHAR(255)  NULL,
                quantity          INT           NOT NULL CHECK (quantity > 0),
                price_at_purchase NUMERIC(10,2) NOT NULL
            );
        `);
        // Idempotent: add name_at_purchase if created by older schema
        await client.query(`
            ALTER TABLE order_items
                ADD COLUMN IF NOT EXISTS name_at_purchase VARCHAR(255) NULL;
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_order_items_order_id
            ON order_items (order_id);`);
        console.log("[DB Init] order_items table is ready.");

        // ── cart ───────────────────────────────────────────────────────────────
        // One row per user — created lazily on first cart interaction.
        // ON DELETE CASCADE: user deleted → cart deleted automatically.
        await client.query(`
            CREATE TABLE IF NOT EXISTS cart (
                id         SERIAL      PRIMARY KEY,
                user_id    INT         NOT NULL UNIQUE
                                       REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_cart_user_id ON cart (user_id);`);

        // ── cart_items ─────────────────────────────────────────────────────────
        // The UNIQUE constraint on (cart_id, product_id) enforces one row per
        // product per cart. Upserts use this constraint via ON CONFLICT.
        await client.query(`
            CREATE TABLE IF NOT EXISTS cart_items (
                id         SERIAL        PRIMARY KEY,
                cart_id    INT           NOT NULL
                                         REFERENCES cart(id) ON DELETE CASCADE,
                product_id INT           NOT NULL,
                quantity   INT           NOT NULL CHECK (quantity > 0),
                added_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_cart_items_cart_product UNIQUE (cart_id, product_id)
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_cart_items_cart_id
            ON cart_items (cart_id);`);
        console.log("[DB Init] cart + cart_items tables are ready.");

        // ── refresh_tokens ─────────────────────────────────────────────────────
        // Stores opaque refresh tokens (hashed) for the sliding-session flow.
        // ON DELETE CASCADE: user deleted → all their refresh tokens deleted.
        await client.query(`
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id         SERIAL       PRIMARY KEY,
                user_id    INT          NOT NULL
                                         REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(64)  NOT NULL UNIQUE,
                issued_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ  NOT NULL,
                revoked    BOOLEAN      NOT NULL DEFAULT false
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id
            ON refresh_tokens (user_id);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash
            ON refresh_tokens (token_hash);`);
        console.log("[DB Init] refresh_tokens table is ready.");

    } catch (err) {
        console.error("[DB Init] FATAL: Could not initialise the database:", err.message);
        process.exit(1);
    } finally {
        if (client) client.release();
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  INPUT VALIDATORS
// ══════════════════════════════════════════════════════════════════════════════

function validateContactPayload(body) {
    const REQUIRED = ["fullName", "email", "subject", "message"];
    const errors = [];
    REQUIRED.forEach((field) => {
        const v = body[field];
        if (v === undefined || v === null) errors.push(`"${field}" is required.`);
        else if (typeof v !== "string") errors.push(`"${field}" must be a string.`);
        else if (v.trim().length === 0) errors.push(`"${field}" must not be blank.`);
    });
    return { valid: errors.length === 0, errors };
}

function validateRegisterPayload(body) {
    const errors = [];
    if (!body.full_name || typeof body.full_name !== "string" || body.full_name.trim().length < 2)
        errors.push('"full_name" is required and must be at least 2 characters.');

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!body.email || typeof body.email !== "string" || !emailRegex.test(body.email.trim()))
        errors.push('"email" must be a valid email address.');

    if (body.phone !== undefined && body.phone !== null && body.phone !== "") {
        const phoneRegex = /^[+\d][\d\s\-]{6,14}$/;
        if (typeof body.phone !== "string" || !phoneRegex.test(body.phone.trim()))
            errors.push('"phone" must be a valid phone number (7–15 digits).');
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
    if (!body.password || typeof body.password !== "string" || !passwordRegex.test(body.password))
        errors.push('"password" must be at least 8 characters and include an uppercase letter, a number, and a special character.');

    return { valid: errors.length === 0, errors };
}

// ── validateCartItems ──────────────────────────────────────────────────────────
// Validates an array of { product_id, quantity } objects sent by the client.
// Returns { valid, errors, lines } where `lines` are sanitised integer pairs.
//
// Security notes:
//   • product_id and quantity are coerced to integers — rejects floats/strings/objects.
//   • quantity is bounded above by MAX_QTY_PER_ITEM to prevent integer overflow
//     in price calculations and DB CHECK constraints.
//   • Duplicate product_ids in the array are detected and rejected — the merge
//     logic must produce a canonical list before calling this.
function validateCartItems(rawItems) {
    const errors = [];
    const lines = [];
    const seenIds = new Set();

    if (!Array.isArray(rawItems) || rawItems.length === 0) {
        return { valid: false, errors: ['"items" must be a non-empty array.'], lines: [] };
    }

    if (rawItems.length > 50) {
        return { valid: false, errors: ['"items" array must not exceed 50 entries.'], lines: [] };
    }

    for (let i = 0; i < rawItems.length; i++) {
        const item = rawItems[i];
        if (!item || typeof item !== "object" || Array.isArray(item)) {
            errors.push(`items[${i}]: must be an object.`);
            continue;
        }
        const productId = parseInt(item.product_id, 10);
        const quantity = parseInt(item.quantity, 10);

        if (!Number.isFinite(productId) || productId <= 0)
            errors.push(`items[${i}].product_id: must be a positive integer.`);
        else if (seenIds.has(productId))
            errors.push(`items[${i}].product_id: duplicate entry for product id ${productId}.`);
        else if (!Number.isFinite(quantity) || quantity <= 0)
            errors.push(`items[${i}].quantity: must be a positive integer.`);
        else if (quantity > MAX_QTY_PER_ITEM)
            errors.push(`items[${i}].quantity: must not exceed ${MAX_QTY_PER_ITEM}.`);
        else {
            seenIds.add(productId);
            lines.push({ productId, quantity });
        }
    }

    return { valid: errors.length === 0, errors, lines };
}

// ══════════════════════════════════════════════════════════════════════════════
//  CART HELPERS
// ══════════════════════════════════════════════════════════════════════════════

// ── getOrCreateCart ────────────────────────────────────────────────────────────
// Returns the cart id for a user, creating the cart row if it doesn't exist yet.
// All operations are done within the supplied `client` (for transaction safety).
async function getOrCreateCart(client, userId) {
    // Try to find an existing cart
    const existing = await client.query(
        "SELECT id FROM cart WHERE user_id = $1;",
        [userId]
    );
    if (existing.rows.length > 0) return existing.rows[0].id;

    // Create one
    const created = await client.query(
        "INSERT INTO cart (user_id) VALUES ($1) RETURNING id;",
        [userId]
    );
    return created.rows[0].id;
}

// ── touchCartTimestamp ─────────────────────────────────────────────────────────
// Updates the cart's updated_at timestamp so clients can detect staleness.
async function touchCartTimestamp(client, cartId) {
    await client.query(
        "UPDATE cart SET updated_at = NOW() WHERE id = $1;",
        [cartId]
    );
}

// ══════════════════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── GET /api/v1/health ─────────────────────────────────────────────────────────
app.get("/api/v1/health", async (req, res) => {
    let dbStatus = "ok";
    let dbLatencyMs = null;
    try {
        const start = Date.now();
        await pool.query("SELECT 1;");
        dbLatencyMs = Date.now() - start;
    } catch {
        dbStatus = "error";
    }
    const status = dbStatus === "ok" ? 200 : 503;
    res.status(status).json({
        status: dbStatus === "ok" ? "ok" : "degraded",
        message: "Manish General Store API is up and running.",
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || "development",
        uptime: `${process.uptime().toFixed(2)}s`,
        pid: process.pid,
        database: { status: dbStatus, latency_ms: dbLatencyMs },
    });
});

// ── GET /api/v1 ────────────────────────────────────────────────────────────────
app.get("/api/v1", (req, res) => {
    res.status(200).json({
        message: "Welcome to the Manish General Store API.",
        version: "2.0.0",
        docs: "/api/v1/health",
    });
});

// ── POST /api/v1/contact ───────────────────────────────────────────────────────
app.post("/api/v1/contact", async (req, res, next) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { valid, errors } = validateContactPayload(body);

    if (!valid) {
        return res.status(400).json({
            status: "error", code: 400,
            message: "Contact form validation failed. Please correct the errors below.",
            errors,
        });
    }

    const { fullName, email, subject, message, phone } = body;
    const submission = {
        fullName: fullName.trim(),
        phone: (typeof phone === "string" && phone.trim().length > 0) ? phone.trim() : null,
        email: email.trim().toLowerCase(),
        subject: subject.trim(),
        message: message.trim(),
    };

    console.log("════════════════════════════════════════════════");
    console.log("[POST /api/v1/contact] New Contact Submission");
    console.log(`  Timestamp : ${new Date().toISOString()}`);
    console.log(`  Full Name : ${submission.fullName}`);
    console.log(`  Email     : ${submission.email}`);
    console.log(`  Subject   : ${submission.subject}`);
    console.log("════════════════════════════════════════════════");

    try {
        const result = await pool.query(
            `INSERT INTO contact_submissions (full_name, phone, email, subject, message)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, created_at;`,
            [submission.fullName, submission.phone, submission.email, submission.subject, submission.message]
        );
        const { id, created_at } = result.rows[0];
        console.log(`[DB] Contact submission saved — id: ${id}`);
        return res.status(201).json({
            status: "success",
            message: "Message received successfully!",
            data: { id, created_at },
        });
    } catch (err) {
        err.message = `[DB] Failed to save contact submission: ${err.message}`;
        return next(err);
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  USER AUTHENTICATION
// ══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/users/register ────────────────────────────────────────────────
// Rate-limited: 10 attempts / 60 min per IP — prevents mass account creation.
app.post("/api/v1/users/register", registerRateLimiter, async (req, res) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { valid, errors } = validateRegisterPayload(body);

    if (!valid) {
        return res.status(400).json({
            status: "error", code: 400,
            message: "Registration validation failed.",
            errors,
        });
    }

    const fullName = body.full_name.trim();
    const email = body.email.trim().toLowerCase();
    const phone = (typeof body.phone === "string" && body.phone.trim().length > 0)
        ? body.phone.trim()
        : null;

    try {
        const passwordHash = await bcrypt.hash(body.password, SALT_ROUNDS);

        const result = await pool.query(
            `INSERT INTO users (full_name, email, phone, password_hash)
             VALUES ($1, $2, $3, $4)
             RETURNING id, full_name, email, phone, created_at;`,
            [fullName, email, phone, passwordHash]
        );

        const user = result.rows[0];
        console.log(`[Register] New user — id: ${user.id}, email: "${user.email}"`);

        return res.status(201).json({
            status: "success",
            message: "Registration successful.",
            data: {
                id: user.id,
                full_name: user.full_name,
                email: user.email,
                phone: user.phone,
                created_at: user.created_at,
            },
        });

    } catch (err) {
        if (err.code === "23505" && err.constraint === "users_email_key") {
            console.warn(`[Register] Duplicate email: "${email}"`);
            return res.status(409).json({
                status: "error", code: 409,
                message: "An account with this email already exists.",
            });
        }
        console.error(`[Register] Error for "${email}":`, err.message);
        return res.status(500).json({
            status: "error", code: 500,
            message: "Registration failed. Please try again later.",
        });
    }
});

// ── POST /api/v1/users/login ───────────────────────────────────────────────────
// Rate-limited: 5 attempts / 15 min per IP.
// Uses a constant-time path to prevent email enumeration via timing attacks.
app.post("/api/v1/users/login", loginRateLimiter, async (req, res) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { email, password } = body;

    if (
        !email || typeof email !== "string" || email.trim().length === 0 ||
        !password || typeof password !== "string" || password.trim().length === 0
    ) {
        return res.status(400).json({
            status: "error", code: 400,
            message: "Email and password are required.",
        });
    }

    const normalizedEmail = email.trim().toLowerCase();

    try {
        const result = await pool.query(
            `SELECT id, full_name, email, phone, password_hash, address, pin_code
             FROM users WHERE email = $1;`,
            [normalizedEmail]
        );

        // Constant-time path: always run bcrypt.compare even if user not found.
        // Without this, an attacker can detect valid emails by measuring the
        // ~250 ms bcrypt delay vs. an instant "not found" return.
        const DUMMY_HASH = "$2b$12$invalidhashpaddingtomakethislongenoughtoberealistic000000";
        const storedHash = result.rows.length > 0 ? result.rows[0].password_hash : DUMMY_HASH;
        const passwordMatch = await bcrypt.compare(password, storedHash);

        if (result.rows.length === 0 || !passwordMatch) {
            console.warn(`[Login] Failed attempt — email: "${normalizedEmail}" at ${new Date().toISOString()}`);
            return res.status(401).json({
                status: "error", code: 401,
                message: "Authentication failed. Invalid email or password.",
            });
        }

        const user = result.rows[0];
        const token = jwt.sign(
            { sub: user.id, email: user.email, role: "user" },
            JWT_SECRET,
            { expiresIn: JWT_ACCESS_EXPIRES, algorithm: "HS256" }
        );

        // ── Issue a refresh token ──────────────────────────────────────────────
        // The refresh token is a signed JWT stored (hashed) in the DB so it can
        // be revoked server-side (e.g. on logout or password change).
        const refreshToken = jwt.sign(
            { sub: user.id, role: "user", type: "refresh" },
            JWT_SECRET,
            { expiresIn: JWT_REFRESH_EXPIRES, algorithm: "HS256" }
        );
        // Store a SHA-256 hash — never store the raw token in the DB.
        const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
        await pool.query(
            `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (token_hash) DO NOTHING;`,
            [user.id, tokenHash, expiresAt]
        );

        console.log(`[Login] Success — user id: ${user.id}, email: "${user.email}"`);

        return res.status(200).json({
            status: "success",
            message: "Login successful.",
            data: {
                token,
                refreshToken,
                expiresIn: JWT_ACCESS_EXPIRES,
                user: {
                    id: user.id,
                    full_name: user.full_name,
                    email: user.email,
                    phone: user.phone,
                    address: user.address || null,
                    pin_code: user.pin_code || null,
                },
            },
        });

    } catch (err) {
        console.error(`[Login] Unexpected error for "${normalizedEmail}":`, err.message);
        return res.status(500).json({
            status: "error", code: 500,
            message: "Authentication failed. Please try again later.",
        });
    }
});

// ── GET /api/v1/users/me ───────────────────────────────────────────────────────
// Returns the authenticated user's profile (including saved address).
app.get("/api/v1/users/me", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: token contains an invalid user identity.",
        });
    }

    try {
        const result = await pool.query(
            `SELECT id, full_name, email, phone, address, pin_code, created_at
             FROM users WHERE id = $1;`,
            [userId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ status: "error", code: 404, message: "User not found." });
        }
        return res.status(200).json({ status: "success", data: result.rows[0] });
    } catch (err) {
        err.message = `[DB] Failed to fetch user #${userId}: ${err.message}`;
        return next(err);
    }
});

// ── PATCH /api/v1/users/me ─────────────────────────────────────────────────────
// Allows an authenticated user to update their own profile fields.
// Only whitelisted fields are accepted — never role, email-uniqueness is
// re-checked, and password changes require the current password.
app.patch("/api/v1/users/me", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: token contains an invalid user identity.",
        });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const allowedFields = ["full_name", "phone", "address", "pin_code"];
    const updates = {};
    const errors = [];

    if (body.full_name !== undefined) {
        if (typeof body.full_name !== "string" || body.full_name.trim().length < 2)
            errors.push('"full_name" must be at least 2 characters.');
        else updates.full_name = body.full_name.trim();
    }
    if (body.phone !== undefined && body.phone !== null && body.phone !== "") {
        const phoneRegex = /^[+\d][\d\s\-]{6,14}$/;
        if (typeof body.phone !== "string" || !phoneRegex.test(body.phone.trim()))
            errors.push('"phone" must be a valid phone number.');
        else updates.phone = body.phone.trim();
    }
    if (body.address !== undefined) {
        if (typeof body.address !== "string" || body.address.trim().length === 0)
            errors.push('"address" must be a non-empty string.');
        else updates.address = body.address.trim();
    }
    if (body.pin_code !== undefined) {
        if (typeof body.pin_code !== "string" || body.pin_code.trim().length === 0)
            errors.push('"pin_code" must be a non-empty string.');
        else updates.pin_code = body.pin_code.trim();
    }

    if (errors.length > 0) {
        return res.status(400).json({ status: "error", code: 400, message: "Validation failed.", errors });
    }

    if (Object.keys(updates).length === 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `No valid fields provided. Updatable fields: ${allowedFields.join(", ")}.`,
        });
    }

    // Build a dynamic SET clause — only update provided fields.
    const setClauses = Object.keys(updates).map((col, i) => `${col} = $${i + 1}`);
    const values = [...Object.values(updates), userId];

    try {
        const result = await pool.query(
            `UPDATE users SET ${setClauses.join(", ")}
             WHERE id = $${values.length}
             RETURNING id, full_name, email, phone, address, pin_code, created_at;`,
            values
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ status: "error", code: 404, message: "User not found." });
        }
        console.log(`[PATCH /api/v1/users/me] user_id ${userId} updated fields: ${Object.keys(updates).join(", ")}`);
        return res.status(200).json({ status: "success", data: result.rows[0] });
    } catch (err) {
        err.message = `[DB] Failed to update user #${userId}: ${err.message}`;
        return next(err);
    }
});

// ── POST /api/v1/users/refresh ─────────────────────────────────────────────────
// Exchanges a valid, non-revoked refresh token for a fresh access token.
// The old refresh token is rotated (revoked) and a new one is issued —
// this limits the blast radius if a refresh token is stolen.
app.post("/api/v1/users/refresh", refreshRateLimiter, async (req, res, next) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { refreshToken } = body;

    if (!refreshToken || typeof refreshToken !== "string") {
        return res.status(400).json({
            status: "error", code: 400,
            message: '"refreshToken" is required.',
        });
    }

    let decoded;
    try {
        decoded = jwt.verify(refreshToken, JWT_SECRET);
    } catch {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Refresh token is invalid or expired.",
        });
    }

    if (!decoded || decoded.type !== "refresh" || decoded.role !== "user") {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Token is not a valid refresh token.",
        });
    }

    const userId = parseUserId(decoded);
    if (isNaN(userId)) {
        return res.status(401).json({ status: "error", code: 401, message: "Invalid token identity." });
    }

    const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    try {
        // Verify the token exists in DB and hasn't been revoked
        const stored = await pool.query(
            `SELECT id, revoked, expires_at FROM refresh_tokens
             WHERE token_hash = $1 AND user_id = $2;`,
            [tokenHash, userId]
        );

        if (stored.rowCount === 0 || stored.rows[0].revoked || new Date(stored.rows[0].expires_at) < new Date()) {
            return res.status(401).json({
                status: "error", code: 401,
                message: "Refresh token has been revoked or expired. Please log in again.",
            });
        }

        // Fetch fresh user data
        const userResult = await pool.query(
            `SELECT id, full_name, email, phone, address, pin_code FROM users WHERE id = $1;`,
            [userId]
        );
        if (userResult.rowCount === 0) {
            return res.status(401).json({ status: "error", code: 401, message: "User account no longer exists." });
        }
        const user = userResult.rows[0];

        // Rotate: revoke old token, issue new pair
        await pool.query(`UPDATE refresh_tokens SET revoked = true WHERE id = $1;`, [stored.rows[0].id]);

        const newAccessToken = jwt.sign(
            { sub: user.id, email: user.email, role: "user" },
            JWT_SECRET,
            { expiresIn: JWT_ACCESS_EXPIRES, algorithm: "HS256" }
        );
        const newRefreshToken = jwt.sign(
            { sub: user.id, role: "user", type: "refresh" },
            JWT_SECRET,
            { expiresIn: JWT_REFRESH_EXPIRES, algorithm: "HS256" }
        );
        const newHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
        const newExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        await pool.query(
            `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3);`,
            [userId, newHash, newExpiry]
        );

        console.log(`[Refresh] Rotated token for user_id ${userId}`);
        return res.status(200).json({
            status: "success",
            data: {
                token: newAccessToken,
                refreshToken: newRefreshToken,
                expiresIn: JWT_ACCESS_EXPIRES,
                user: { id: user.id, full_name: user.full_name, email: user.email, phone: user.phone },
            },
        });

    } catch (err) {
        err.message = `[DB] Refresh token error: ${err.message}`;
        return next(err);
    }
});

// ── POST /api/v1/users/logout ──────────────────────────────────────────────────
// Revokes the supplied refresh token server-side.
// The access token is short-lived and expires on its own; revoking the
// refresh token prevents silent re-authentication after logout.
app.post("/api/v1/users/logout", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { refreshToken } = body;

    if (!refreshToken || typeof refreshToken !== "string") {
        // Still return 200 — the client-side token can be discarded regardless.
        return res.status(200).json({ status: "success", message: "Logged out." });
    }

    const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    try {
        await pool.query(
            `UPDATE refresh_tokens SET revoked = true
             WHERE token_hash = $1 AND user_id = $2;`,
            [tokenHash, userId]
        );
        console.log(`[Logout] user_id ${userId} — refresh token revoked.`);
        return res.status(200).json({ status: "success", message: "Logged out successfully." });
    } catch (err) {
        err.message = `[DB] Logout error: ${err.message}`;
        return next(err);
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  PRODUCTS
// ══════════════════════════════════════════════════════════════════════════════

// ── GET /api/v1/products ───────────────────────────────────────────────────────
// Supports filtering by category, search term, stock status, and pagination.
//
// Query params:
//   ?category=<string>   — exact category match (case-insensitive)
//   ?search=<string>     — partial match on name or description
//   ?in_stock=true|false — filter by stock status (default: omit = return all)
//   ?page=<int>          — page number (default: 1)
//   ?limit=<int>         — results per page (default: 20, max: 100)
//   ?sort=price_asc|price_desc|name_asc|newest — sort order (default: id ASC)
app.get("/api/v1/products", async (req, res, next) => {
    try {
        const conditions = [];
        const params = [];

        // ── ?category= ────────────────────────────────────────────────────────
        if (req.query.category && typeof req.query.category === "string" && req.query.category.trim()) {
            params.push(req.query.category.trim().toLowerCase());
            conditions.push(`LOWER(category) = $${params.length}`);
        }

        // ── ?search= ──────────────────────────────────────────────────────────
        if (req.query.search && typeof req.query.search === "string" && req.query.search.trim()) {
            const term = `%${req.query.search.trim().toLowerCase()}%`;
            params.push(term);
            const idx = params.length;
            conditions.push(`(LOWER(name) LIKE $${idx} OR LOWER(description) LIKE $${idx})`);
        }

        // ── ?in_stock= ────────────────────────────────────────────────────────
        if (req.query.in_stock === "true") {
            conditions.push(`in_stock = true`);
        } else if (req.query.in_stock === "false") {
            conditions.push(`in_stock = false`);
        }

        // ── Pagination ────────────────────────────────────────────────────────
        const rawPage = parseInt(req.query.page, 10);
        const rawLimit = parseInt(req.query.limit, 10);
        const page = Number.isFinite(rawPage) && rawPage > 0 ? rawPage : 1;
        const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 100) : 20;
        const offset = (page - 1) * limit;

        // ── Sort ──────────────────────────────────────────────────────────────
        const SORT_MAP = {
            price_asc: "price ASC",
            price_desc: "price DESC",
            name_asc: "name ASC",
            newest: "created_at DESC",
        };
        const orderBy = SORT_MAP[req.query.sort] || "id ASC";

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

        // ── Total count (for pagination metadata) ─────────────────────────────
        const countResult = await pool.query(
            `SELECT COUNT(*) FROM products ${whereClause};`,
            params
        );
        const total = parseInt(countResult.rows[0].count, 10);

        // ── Fetch page ────────────────────────────────────────────────────────
        params.push(limit, offset);
        const result = await pool.query(
            `SELECT id, name, description, price, category, in_stock, image_url,
                    stock_quantity, created_at
             FROM products
             ${whereClause}
             ORDER BY ${orderBy}
             LIMIT $${params.length - 1} OFFSET $${params.length};`,
            params
        );

        // ── Distinct categories (for frontend filter UI) ───────────────────────
        const categoriesResult = await pool.query(
            `SELECT DISTINCT category FROM products WHERE category IS NOT NULL ORDER BY category ASC;`
        );
        const categories = categoriesResult.rows.map((r) => r.category);

        return res.status(200).json({
            status: "success",
            count: result.rowCount,
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
            categories,
            data: result.rows,
        });
    } catch (err) {
        err.message = `[DB] Failed to fetch products: ${err.message}`;
        return next(err);
    }
});

// ── GET /api/v1/products/:id ───────────────────────────────────────────────────
// Returns a single product by its ID.
app.get("/api/v1/products/:id", async (req, res, next) => {
    const productId = parseInt(req.params.id, 10);
    if (!Number.isFinite(productId) || productId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid product id: "${req.params.id}". Must be a positive integer.`,
        });
    }
    try {
        const result = await pool.query(
            `SELECT id, name, description, price, category, in_stock, image_url,
                    stock_quantity, created_at
             FROM products WHERE id = $1;`,
            [productId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({
                status: "error", code: 404,
                message: `Product with id ${productId} not found.`,
            });
        }
        return res.status(200).json({ status: "success", data: result.rows[0] });
    } catch (err) {
        err.message = `[DB] Failed to fetch product #${productId}: ${err.message}`;
        return next(err);
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  ORDERS  (Phase 6 — Strict Authenticated Checkout)
//
//  Guest checkout is DROPPED.  Every order must be accompanied by a valid
//  user JWT.  This enforces:
//    • Accountability — every order is linked to a real user account.
//    • Address saving  — a "save_address" flag updates the user's profile.
//    • Cart clearing   — after successful order the backend cart is wiped.
//
//  Security guarantees carried forward from Phase 5:
//    • user_id is NEVER accepted from the request body.  It comes exclusively
//      from the verified JWT via verifyUser.
//    • Admin tokens are rejected (role check inside verifyUser).
//    • All product prices are fetched fresh from the DB inside the transaction.
//      The client cannot dictate prices.
//    • Payment method is validated against a strict allowlist.
//    • All monetary arithmetic uses server-side values only.
// ══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/orders ────────────────────────────────────────────────────────
app.post("/api/v1/orders", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: token contains an invalid user identity.",
        });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { cart, contact, address, payment } = body;

    // ── Shape validation ───────────────────────────────────────────────────────
    const shapeErrors = [];

    if (!cart || typeof cart !== "object" || Array.isArray(cart)) {
        shapeErrors.push('"cart" must be a non-null object mapping product IDs to quantities.');
    } else if (Object.keys(cart).length === 0) {
        shapeErrors.push('"cart" must not be empty.');
    } else if (Object.keys(cart).length > 50) {
        shapeErrors.push('"cart" must not exceed 50 distinct items.');
    }

    if (!contact || typeof contact !== "object") {
        shapeErrors.push('"contact" object is required.');
    } else {
        if (typeof contact.name !== "string" || contact.name.trim().length === 0)
            shapeErrors.push('"contact.name" is required.');
        if (typeof contact.email !== "string" || contact.email.trim().length === 0)
            shapeErrors.push('"contact.email" is required.');
        if (typeof contact.phone !== "string" || contact.phone.trim().length === 0)
            shapeErrors.push('"contact.phone" is required.');
    }

    if (!address || typeof address !== "object") {
        shapeErrors.push('"address" object is required.');
    } else {
        if (typeof address.street !== "string" || address.street.trim().length === 0)
            shapeErrors.push('"address.street" is required.');
        if (typeof address.pin !== "string" || address.pin.trim().length === 0)
            shapeErrors.push('"address.pin" is required.');
    }

    if (!payment || typeof payment !== "object") {
        shapeErrors.push('"payment" object is required.');
    } else {
        const method = (typeof payment.method === "string") ? payment.method.trim().toLowerCase() : "";
        if (!method) {
            shapeErrors.push('"payment.method" is required.');
        } else if (!ALLOWED_PAYMENT_METHODS.has(method)) {
            shapeErrors.push(`"payment.method" must be one of: ${[...ALLOWED_PAYMENT_METHODS].join(", ")}.`);
        }
    }

    if (shapeErrors.length > 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: "Order validation failed.", errors: shapeErrors,
        });
    }

    const orderContact = {
        name: contact.name.trim(),
        email: contact.email.trim().toLowerCase(),
        phone: contact.phone.trim(),
    };
    const orderAddress = {
        street: address.street.trim(),
        pin: address.pin.trim(),
    };
    const paymentMethod = payment.method.trim().toLowerCase();
    // save_address: true means "persist this address to the user's profile"
    const saveAddress = body.save_address === true;

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        // ── Verify the user exists (prevents orphaned orders if the account was
        //    deleted between token issuance and this request) ──────────────────
        const userCheck = await client.query(
            "SELECT id FROM users WHERE id = $1;",
            [userId]
        );
        if (userCheck.rowCount === 0) {
            await client.query("ROLLBACK");
            return res.status(401).json({
                status: "error", code: 401,
                message: "Unauthorized: the account associated with this token no longer exists.",
            });
        }

        // ── Validate cart items against live inventory ─────────────────────────
        let subtotal = 0;
        const validatedCartLines = [];
        const cartErrors = [];

        for (const [rawId, rawQty] of Object.entries(cart)) {
            const productId = parseInt(rawId, 10);
            const quantity = parseInt(rawQty, 10);

            if (!Number.isFinite(productId) || productId <= 0) {
                cartErrors.push(`Invalid product id: "${rawId}".`);
                continue;
            }
            if (!Number.isFinite(quantity) || quantity <= 0) {
                cartErrors.push(`Invalid quantity for product id ${productId}: "${rawQty}".`);
                continue;
            }
            if (quantity > MAX_QTY_PER_ITEM) {
                cartErrors.push(`Quantity for product id ${productId} must not exceed ${MAX_QTY_PER_ITEM}.`);
                continue;
            }

            // Lock the product row for update to prevent TOCTOU race conditions
            // in concurrent checkouts (e.g. two users buying the last item).
            const { rows } = await client.query(
                "SELECT id, name, price, in_stock, stock_quantity FROM products WHERE id = $1 FOR UPDATE;",
                [productId]
            );

            if (rows.length === 0) {
                cartErrors.push(`Product with id ${productId} does not exist.`);
                continue;
            }
            const product = rows[0];
            if (!product.in_stock) {
                cartErrors.push(`"${product.name}" (id: ${productId}) is currently out of stock.`);
                continue;
            }
            if (quantity > product.stock_quantity) {
                cartErrors.push(
                    `Only ${product.stock_quantity} unit${product.stock_quantity === 1 ? "" : "s"} ` +
                    `of "${product.name}" ${product.stock_quantity === 1 ? "is" : "are"} available.`
                );
                continue;
            }

            const unitPrice = parseFloat(product.price);
            subtotal += unitPrice * quantity;
            validatedCartLines.push({ productId, quantity, price: unitPrice, name: product.name });
        }

        if (cartErrors.length > 0) {
            await client.query("ROLLBACK");
            return res.status(400).json({
                status: "error", code: 400,
                message: "One or more cart items are invalid.", errors: cartErrors,
            });
        }

        const totalAmount = parseFloat((subtotal + DELIVERY_FEE).toFixed(2));

        console.log("════════════════════════════════════════════════");
        console.log("[POST /api/v1/orders] Authenticated Order");
        console.log(`  Timestamp  : ${new Date().toISOString()}`);
        console.log(`  user_id    : ${userId}`);
        console.log(`  Customer   : ${orderContact.name} <${orderContact.email}>`);
        console.log(`  Address    : ${orderAddress.street}, PIN ${orderAddress.pin}`);
        console.log(`  Payment    : ${paymentMethod}`);
        console.log(`  Lines      : ${validatedCartLines.length} item(s)`);
        console.log(`  Subtotal   : ₹${subtotal.toFixed(2)}`);
        console.log(`  Delivery   : ₹${DELIVERY_FEE.toFixed(2)}`);
        console.log(`  Total      : ₹${totalAmount.toFixed(2)}`);
        console.log(`  SaveAddr   : ${saveAddress}`);
        console.log("════════════════════════════════════════════════");

        // ── Insert order ───────────────────────────────────────────────────────
        // user_id comes from the verified JWT, never from the request body.
        const insertOrderResult = await client.query(
            `INSERT INTO orders
                (user_id, customer_name, email, phone, address, pin_code, payment_method, total_amount)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id;`,
            [
                userId,
                orderContact.name,
                orderContact.email,
                orderContact.phone,
                orderAddress.street,
                orderAddress.pin,
                paymentMethod,
                totalAmount,
            ]
        );
        const newOrderId = insertOrderResult.rows[0].id;

        // ── Insert order line items ────────────────────────────────────────────
        // name_at_purchase is snapshotted so renaming a product later doesn't
        // corrupt historical order records.
        for (const line of validatedCartLines) {
            await client.query(
                `INSERT INTO order_items
                    (order_id, product_id, name_at_purchase, quantity, price_at_purchase)
                 VALUES ($1, $2, $3, $4, $5);`,
                [newOrderId, line.productId, line.name, line.quantity, line.price]
            );
        }

        // ── Decrement stock ────────────────────────────────────────────────────
        // Uses a row-level lock acquired above (FOR UPDATE), so concurrent
        // checkouts cannot oversell.
        for (const line of validatedCartLines) {
            const { rows: updated } = await client.query(
                `UPDATE products
                 SET
                     stock_quantity = stock_quantity - $1,
                     in_stock       = CASE WHEN (stock_quantity - $1) <= 0 THEN false ELSE in_stock END
                 WHERE id = $2
                 RETURNING name, stock_quantity, in_stock;`,
                [line.quantity, line.productId]
            );
            if (updated.length > 0) {
                const { name, stock_quantity: rem, in_stock: inStock } = updated[0];
                if (!inStock) console.warn(`OUT OF STOCK: "${name}" (id: ${line.productId}) has sold out.`);
                else if (rem <= 5) console.warn(`LOW STOCK: "${name}" has only ${rem} unit(s) left.`);
            }
        }

        // ── Optionally save address to user profile ────────────────────────────
        // Only triggered when the checkout form's "Save this address" box is
        // checked.  Uses parameterised query — no string interpolation.
        if (saveAddress) {
            await client.query(
                `UPDATE users
                 SET address = $1, pin_code = $2
                 WHERE id = $3;`,
                [orderAddress.street, orderAddress.pin, userId]
            );
            console.log(`[Orders] Address saved to profile for user_id ${userId}.`);
        }

        // ── Clear the backend cart ─────────────────────────────────────────────
        // After a successful order the user's persisted cart is wiped so the
        // next session starts clean — matching Amazon / JioMart behaviour.
        // We do this inside the same transaction so a rollback on a later
        // failure also restores the cart.
        await client.query(
            `DELETE FROM cart_items
             WHERE cart_id = (SELECT id FROM cart WHERE user_id = $1);`,
            [userId]
        );
        await client.query(
            `UPDATE cart SET updated_at = NOW() WHERE user_id = $1;`,
            [userId]
        );

        await client.query("COMMIT");
        console.log(`[DB] Order #${newOrderId} committed — total ₹${totalAmount.toFixed(2)}, user_id: ${userId}`);

        return res.status(201).json({
            status: "success",
            message: "Order placed successfully.",
            data: { order_id: newOrderId, total_amount: totalAmount },
        });

    } catch (err) {
        try {
            await client.query("ROLLBACK");
            console.warn("[DB] Transaction rolled back:", err.message);
        } catch (rbErr) {
            console.error("[DB] ROLLBACK failed:", rbErr.message);
        }
        err.message = `[DB] Failed to place order: ${err.message}`;
        return next(err);
    } finally {
        client.release();
    }
});

// ── GET /api/v1/users/me/orders ───────────────────────────────────────────────
// Returns the authenticated user's order history, newest first.
// Each order includes its full enriched line items.
app.get("/api/v1/users/me/orders", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: token contains an invalid user identity.",
        });
    }

    try {
        const ordersResult = await pool.query(
            `SELECT id, customer_name, email, phone, address, pin_code,
                    payment_method, total_amount, status, created_at
             FROM orders
             WHERE user_id = $1
             ORDER BY created_at DESC;`,
            [userId]
        );

        const orders = ordersResult.rows;
        if (orders.length === 0) {
            return res.status(200).json({ status: "success", count: 0, data: [] });
        }

        // Batch-fetch all order items in a single query to avoid N+1.
        const orderIds = orders.map((o) => o.id);
        const itemsResult = await pool.query(
            `SELECT
                oi.order_id,
                oi.id,
                oi.product_id,
                COALESCE(oi.name_at_purchase, p.name, 'Product #' || oi.product_id) AS name,
                oi.quantity,
                oi.price_at_purchase AS price
             FROM order_items oi
             LEFT JOIN products p ON p.id = oi.product_id
             WHERE oi.order_id = ANY($1)
             ORDER BY oi.order_id DESC, oi.id ASC;`,
            [orderIds]
        );

        // Group items by order_id
        const itemsByOrderId = {};
        for (const item of itemsResult.rows) {
            if (!itemsByOrderId[item.order_id]) itemsByOrderId[item.order_id] = [];
            const { order_id, ...itemData } = item;
            itemsByOrderId[order_id].push(itemData);
        }

        const enrichedOrders = orders.map((order) => ({
            ...order,
            items: itemsByOrderId[order.id] || [],
        }));

        console.log(`[GET /api/v1/users/me/orders] user_id ${userId} — ${enrichedOrders.length} order(s).`);

        return res.status(200).json({
            status: "success",
            count: enrichedOrders.length,
            data: enrichedOrders,
        });

    } catch (err) {
        err.message = `[DB] Failed to fetch orders for user #${userId}: ${err.message}`;
        return next(err);
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  CART API  (Phase 6)
//
//  Architecture
//  ────────────
//  • One `cart` row per user (created lazily).
//  • One `cart_items` row per (cart, product) — enforced by UNIQUE constraint.
//  • All mutations run inside DB transactions so partial writes never persist.
//  • Quantities are always capped at MAX_QTY_PER_ITEM and bounded by live
//    stock_quantity fetched from the products table.
//
//  Endpoints
//  ─────────
//  GET    /api/v1/cart               → fetch the user's full cart with product details
//  PUT    /api/v1/cart               → replace / sync the entire cart
//  POST   /api/v1/cart/merge         → merge a guest localStorage cart into the backend cart
//  DELETE /api/v1/cart               → clear all items
//  DELETE /api/v1/cart/items/:id     → remove a single line item
// ══════════════════════════════════════════════════════════════════════════════

// ── GET /api/v1/cart ───────────────────────────────────────────────────────────
// Returns the authenticated user's cart with enriched product details and a
// computed subtotal.  Returns an empty cart if none exists yet.
app.get("/api/v1/cart", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: invalid user identity in token.",
        });
    }

    try {
        // Fetch the cart and all its items in a single JOIN.  If no cart row
        // exists yet, the outer query returns nothing — we return an empty cart.
        const result = await pool.query(
            `SELECT
                c.id              AS cart_id,
                c.updated_at,
                ci.id             AS item_id,
                ci.product_id,
                ci.quantity,
                ci.added_at,
                p.name,
                p.price,
                p.image_url,
                p.in_stock,
                p.stock_quantity
             FROM cart c
             LEFT JOIN cart_items ci ON ci.cart_id = c.id
             LEFT JOIN products    p  ON p.id = ci.product_id
             WHERE c.user_id = $1
             ORDER BY ci.added_at ASC;`,
            [userId]
        );

        if (result.rowCount === 0 || result.rows[0].item_id === null) {
            // No cart yet, or cart exists but is empty
            return res.status(200).json({
                status: "success",
                data: {
                    cart_id: result.rows[0]?.cart_id ?? null,
                    updated_at: result.rows[0]?.updated_at ?? null,
                    items: [],
                    subtotal: 0,
                    item_count: 0,
                },
            });
        }

        let subtotal = 0;
        let item_count = 0;
        const items = result.rows.map((row) => {
            const lineTotal = parseFloat(row.price) * row.quantity;
            subtotal += lineTotal;
            item_count += row.quantity;
            return {
                item_id: row.item_id,
                product_id: row.product_id,
                name: row.name,
                price: parseFloat(row.price),
                image_url: row.image_url,
                in_stock: row.in_stock,
                stock_quantity: row.stock_quantity,
                quantity: row.quantity,
                added_at: row.added_at,
                line_total: parseFloat(lineTotal.toFixed(2)),
            };
        });

        return res.status(200).json({
            status: "success",
            data: {
                cart_id: result.rows[0].cart_id,
                updated_at: result.rows[0].updated_at,
                items,
                subtotal: parseFloat(subtotal.toFixed(2)),
                item_count,
            },
        });

    } catch (err) {
        err.message = `[DB] Failed to fetch cart for user #${userId}: ${err.message}`;
        return next(err);
    }
});

// ── PUT /api/v1/cart ───────────────────────────────────────────────────────────
//
// Full cart sync / replace.  Replaces the user's entire cart with the
// provided items array.  Used by the frontend to push its in-memory state
// to the server (e.g. after adding/removing items on the product page).
//
// Request body:
//   { "items": [ { "product_id": 3, "quantity": 2 }, ... ] }
//
// Behaviour:
//   • All existing cart_items rows for the user are deleted.
//   • The new items are inserted.
//   • Quantities are validated against live stock.
//   • Sending an empty array clears the cart.
app.put("/api/v1/cart", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: invalid user identity in token.",
        });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const rawItems = body.items;

    // Allow an explicit empty array to clear the cart
    if (rawItems !== undefined && (!Array.isArray(rawItems))) {
        return res.status(400).json({
            status: "error", code: 400,
            message: '"items" must be an array.',
        });
    }

    const items = Array.isArray(rawItems) ? rawItems : [];

    // Validate if there are items to insert
    let validatedLines = [];
    if (items.length > 0) {
        const { valid, errors, lines } = validateCartItems(items);
        if (!valid) {
            return res.status(400).json({
                status: "error", code: 400,
                message: "Cart validation failed.", errors,
            });
        }
        validatedLines = lines;
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const cartId = await getOrCreateCart(client, userId);

        // Delete all existing items
        await client.query("DELETE FROM cart_items WHERE cart_id = $1;", [cartId]);

        if (validatedLines.length > 0) {
            // Validate quantities against live stock and insert
            const insertErrors = [];
            for (const line of validatedLines) {
                const { rows } = await client.query(
                    "SELECT name, in_stock, stock_quantity FROM products WHERE id = $1;",
                    [line.productId]
                );
                if (rows.length === 0) {
                    insertErrors.push(`Product id ${line.productId} does not exist.`);
                    continue;
                }
                const p = rows[0];
                if (!p.in_stock) {
                    insertErrors.push(`"${p.name}" is out of stock.`);
                    continue;
                }
                const clampedQty = Math.min(line.quantity, p.stock_quantity, MAX_QTY_PER_ITEM);
                if (clampedQty <= 0) {
                    insertErrors.push(`"${p.name}" has no stock available.`);
                    continue;
                }
                await client.query(
                    `INSERT INTO cart_items (cart_id, product_id, quantity)
                     VALUES ($1, $2, $3);`,
                    [cartId, line.productId, clampedQty]
                );
            }

            if (insertErrors.length > 0) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    status: "error", code: 400,
                    message: "Some cart items could not be synced.", errors: insertErrors,
                });
            }
        }

        await touchCartTimestamp(client, cartId);
        await client.query("COMMIT");

        console.log(`[Cart PUT] user_id ${userId} — cart synced, ${validatedLines.length} line(s).`);
        return res.status(200).json({
            status: "success",
            message: "Cart synced successfully.",
            data: { cart_id: cartId, item_count: validatedLines.length },
        });

    } catch (err) {
        try { await client.query("ROLLBACK"); } catch { }
        err.message = `[DB] Failed to sync cart for user #${userId}: ${err.message}`;
        return next(err);
    } finally {
        client.release();
    }
});

// ── POST /api/v1/cart/merge ────────────────────────────────────────────────────
//
// Cart Merge — called immediately after a user logs in to combine the items
// they added as a guest (stored in localStorage) with their persistent
// backend cart.
//
// Merge strategy: "guest wins on conflict"
//   • If a product exists in BOTH carts, the guest quantity replaces the
//     backend quantity.  This matches the user's most recent intent.
//   • Items that exist only in the backend cart are preserved.
//   • Items that exist only in the guest cart are added.
//   • All quantities are clamped to live stock_quantity.
//
// Security:
//   • Requires a valid user JWT (verifyUser).
//   • Rate-limited per IP (cartMergeRateLimiter) to prevent token replay abuse.
//   • All product_id and quantity values are strictly validated.
//   • Product existence and stock are verified against the DB — the client
//     cannot inject phantom products or arbitrary prices.
//   • All writes are wrapped in a single DB transaction.
//
// Request body:
//   { "items": [ { "product_id": 3, "quantity": 2 }, ... ] }
//   (The items from the guest's localStorage cart)
app.post("/api/v1/cart/merge", cartMergeRateLimiter, verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: invalid user identity in token.",
        });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const rawItems = body.items;

    if (!Array.isArray(rawItems)) {
        return res.status(400).json({
            status: "error", code: 400,
            message: '"items" must be an array of { product_id, quantity } objects.',
        });
    }

    // An empty guest cart is a valid (no-op) call — return early gracefully.
    if (rawItems.length === 0) {
        return res.status(200).json({
            status: "success",
            message: "Nothing to merge — guest cart was empty.",
            data: { merged_count: 0 },
        });
    }

    const { valid, errors, lines: guestLines } = validateCartItems(rawItems);
    if (!valid) {
        return res.status(400).json({
            status: "error", code: 400,
            message: "Guest cart validation failed.", errors,
        });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const cartId = await getOrCreateCart(client, userId);

        let mergedCount = 0;

        for (const guestItem of guestLines) {
            // Verify the product exists and has sufficient stock
            const { rows } = await client.query(
                "SELECT name, in_stock, stock_quantity FROM products WHERE id = $1;",
                [guestItem.productId]
            );
            if (rows.length === 0) {
                // Product no longer exists — skip silently (don't fail the whole merge)
                console.warn(`[Cart Merge] Skipped unknown product_id ${guestItem.productId} for user ${userId}.`);
                continue;
            }
            const product = rows[0];
            if (!product.in_stock || product.stock_quantity <= 0) {
                console.warn(`[Cart Merge] Skipped out-of-stock "${product.name}" for user ${userId}.`);
                continue;
            }

            // Clamp to available stock
            const effectiveQty = Math.min(guestItem.quantity, product.stock_quantity, MAX_QTY_PER_ITEM);
            if (effectiveQty <= 0) continue;

            // Upsert: if the product is already in the cart, guest quantity wins.
            // The ON CONFLICT target references the named constraint for clarity.
            await client.query(
                `INSERT INTO cart_items (cart_id, product_id, quantity)
                 VALUES ($1, $2, $3)
                 ON CONFLICT ON CONSTRAINT uq_cart_items_cart_product
                 DO UPDATE SET quantity = EXCLUDED.quantity, added_at = NOW();`,
                [cartId, guestItem.productId, effectiveQty]
            );
            mergedCount++;
        }

        await touchCartTimestamp(client, cartId);
        await client.query("COMMIT");

        console.log(`[Cart Merge] user_id ${userId} — ${mergedCount} item(s) merged from guest cart.`);

        return res.status(200).json({
            status: "success",
            message: `Guest cart merged successfully. ${mergedCount} item(s) added or updated.`,
            data: { cart_id: cartId, merged_count: mergedCount },
        });

    } catch (err) {
        try { await client.query("ROLLBACK"); } catch { }
        err.message = `[DB] Failed to merge cart for user #${userId}: ${err.message}`;
        return next(err);
    } finally {
        client.release();
    }
});

// ── DELETE /api/v1/cart ────────────────────────────────────────────────────────
// Clears all items from the user's cart (the cart row itself is kept).
app.delete("/api/v1/cart", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: invalid user identity in token.",
        });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        const cartId = await getOrCreateCart(client, userId);
        await client.query("DELETE FROM cart_items WHERE cart_id = $1;", [cartId]);
        await touchCartTimestamp(client, cartId);
        await client.query("COMMIT");

        console.log(`[Cart DELETE] user_id ${userId} — cart cleared.`);
        return res.status(200).json({ status: "success", message: "Cart cleared." });
    } catch (err) {
        try { await client.query("ROLLBACK"); } catch { }
        err.message = `[DB] Failed to clear cart for user #${userId}: ${err.message}`;
        return next(err);
    } finally {
        client.release();
    }
});

// ── DELETE /api/v1/cart/items/:productId ──────────────────────────────────────
// Removes a single product from the user's cart.
// Uses product_id (not the cart_items PK) so the frontend doesn't need to
// track internal item ids.
app.delete("/api/v1/cart/items/:productId", verifyUser, async (req, res, next) => {
    const userId = parseUserId(req.user);
    const productId = parseInt(req.params.productId, 10);

    if (isNaN(userId)) {
        return res.status(401).json({
            status: "error", code: 401,
            message: "Unauthorized: invalid user identity in token.",
        });
    }
    if (!Number.isFinite(productId) || productId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid product id: "${req.params.productId}". Must be a positive integer.`,
        });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        // Fetch the cart id (do not auto-create — if no cart exists, there's nothing to delete)
        const cartResult = await client.query(
            "SELECT id FROM cart WHERE user_id = $1;",
            [userId]
        );
        if (cartResult.rowCount === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({
                status: "error", code: 404,
                message: "Cart not found.",
            });
        }
        const cartId = cartResult.rows[0].id;

        const deleteResult = await client.query(
            "DELETE FROM cart_items WHERE cart_id = $1 AND product_id = $2 RETURNING id;",
            [cartId, productId]
        );
        if (deleteResult.rowCount === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({
                status: "error", code: 404,
                message: `Product id ${productId} is not in the cart.`,
            });
        }

        await touchCartTimestamp(client, cartId);
        await client.query("COMMIT");

        console.log(`[Cart DELETE item] user_id ${userId}, product_id ${productId} removed.`);
        return res.status(200).json({
            status: "success",
            message: `Product id ${productId} removed from cart.`,
        });

    } catch (err) {
        try { await client.query("ROLLBACK"); } catch { }
        err.message = `[DB] Failed to remove cart item for user #${userId}: ${err.message}`;
        return next(err);
    } finally {
        client.release();
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/admin/login ───────────────────────────────────────────────────
app.post("/api/v1/admin/login", (req, res) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { username, password } = body;

    if (
        typeof username !== "string" || username.trim() === "" ||
        typeof password !== "string" || password.trim() === ""
    ) {
        return res.status(400).json({
            status: "error", code: 400,
            message: "Both username and password are required.",
        });
    }

    if (username.trim() !== ADMIN_USER || password !== ADMIN_PASS) {
        console.warn(`[Admin Login] Failed — username: "${username.trim()}" at ${new Date().toISOString()}`);
        return res.status(401).json({ status: "error", code: 401, message: "Invalid credentials." });
    }

    const token = jwt.sign(
        { sub: username.trim(), role: "admin" },
        JWT_SECRET,
        { expiresIn: "24h" }
    );

    console.log(`[Admin Login] Success — username: "${username.trim()}" at ${new Date().toISOString()}`);
    return res.status(200).json({
        status: "success",
        message: "Login successful.",
        data: { token, expiresIn: "24h" },
    });
});

// ── GET /api/v1/admin/orders ───────────────────────────────────────────────────
app.get("/api/v1/admin/orders", verifyAdmin, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT id, user_id, customer_name, email, phone, address, pin_code,
                    payment_method, total_amount, status, created_at
             FROM orders
             ORDER BY created_at DESC;`
        );
        return res.status(200).json({ status: "success", count: result.rowCount, data: result.rows });
    } catch (err) {
        err.message = `[DB] Failed to fetch orders: ${err.message}`;
        return next(err);
    }
});

// ── GET /api/v1/admin/orders/:id ──────────────────────────────────────────────
app.get("/api/v1/admin/orders/:id", verifyAdmin, async (req, res, next) => {
    const orderId = parseInt(req.params.id, 10);
    if (!Number.isFinite(orderId) || orderId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid order id: "${req.params.id}". Must be a positive integer.`,
        });
    }

    try {
        const orderResult = await pool.query(
            `SELECT id, user_id, customer_name, email, phone, address, pin_code,
                    payment_method, total_amount, status, created_at
             FROM orders WHERE id = $1;`,
            [orderId]
        );
        if (orderResult.rowCount === 0) {
            return res.status(404).json({
                status: "error", code: 404,
                message: `Order with id ${orderId} not found.`,
            });
        }
        const order = orderResult.rows[0];

        const itemsResult = await pool.query(
            `SELECT
                oi.id,
                oi.product_id,
                COALESCE(oi.name_at_purchase, p.name, 'Product #' || oi.product_id) AS product_name,
                oi.quantity,
                oi.price_at_purchase
             FROM order_items oi
             LEFT JOIN products p ON p.id = oi.product_id
             WHERE oi.order_id = $1
             ORDER BY oi.id ASC;`,
            [orderId]
        );
        order.items = itemsResult.rows;
        return res.status(200).json({ status: "success", data: order });
    } catch (err) {
        err.message = `[DB] Failed to fetch order #${orderId}: ${err.message}`;
        return next(err);
    }
});

// ── PATCH /api/v1/admin/orders/:id/status ─────────────────────────────────────
app.patch("/api/v1/admin/orders/:id/status", verifyAdmin, async (req, res, next) => {
    const orderId = parseInt(req.params.id, 10);
    if (!Number.isFinite(orderId) || orderId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid order id: "${req.params.id}". Must be a positive integer.`,
        });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { status } = body;

    if (!status || typeof status !== "string") {
        return res.status(400).json({
            status: "error", code: 400,
            message: '"status" field is required and must be a string.',
        });
    }

    const normalised = status.trim().toLowerCase();
    if (!VALID_ORDER_STATUSES.includes(normalised)) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid status: "${status}". Must be one of: ${VALID_ORDER_STATUSES.join(", ")}.`,
        });
    }

    try {
        const result = await pool.query(
            `UPDATE orders SET status = $1 WHERE id = $2
             RETURNING id, status, created_at;`,
            [normalised, orderId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({
                status: "error", code: 404,
                message: `Order with id ${orderId} not found.`,
            });
        }
        console.log(`[Admin] Order #${orderId} status → "${normalised}"`);
        return res.status(200).json({ status: "success", data: result.rows[0] });
    } catch (err) {
        err.message = `[DB] Failed to update order #${orderId} status: ${err.message}`;
        return next(err);
    }
});

// ── PATCH /api/v1/admin/products/:id/stock ────────────────────────────────────
app.patch("/api/v1/admin/products/:id/stock", verifyAdmin, async (req, res, next) => {
    const productId = parseInt(req.params.id, 10);
    if (!Number.isFinite(productId) || productId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid product id: "${req.params.id}". Must be a positive integer.`,
        });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const rawQty = body.stock_quantity;
    const newQty = parseInt(rawQty, 10);

    if (rawQty === undefined || rawQty === null) {
        return res.status(400).json({ status: "error", code: 400, message: '"stock_quantity" is required.' });
    }
    if (!Number.isFinite(newQty) || newQty < 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `"stock_quantity" must be a non-negative integer. Received: ${rawQty}`,
        });
    }

    try {
        const result = await pool.query(
            `UPDATE products
             SET
                 stock_quantity = $1,
                 in_stock       = CASE WHEN $1 > 0 THEN true ELSE false END
             WHERE id = $2
             RETURNING id, name, stock_quantity, in_stock, price, category, image_url;`,
            [newQty, productId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({
                status: "error", code: 404,
                message: `Product with id ${productId} not found.`,
            });
        }
        const updated = result.rows[0];
        console.log(`[Admin] Product #${productId} ("${updated.name}") stock → ${newQty} (in_stock: ${updated.in_stock})`);
        if (newQty === 0) console.warn(`OUT OF STOCK: Product #${productId} ("${updated.name}") set to 0.`);
        else if (newQty <= 5) console.warn(`LOW STOCK:    Product #${productId} ("${updated.name}") set to ${newQty}.`);
        return res.status(200).json({ status: "success", data: updated });
    } catch (err) {
        err.message = `[DB] Failed to update stock for product #${productId}: ${err.message}`;
        return next(err);
    }
});

// ── POST /api/v1/admin/products ───────────────────────────────────────────────
app.post("/api/v1/admin/products", verifyAdmin, async (req, res, next) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const validationErrors = [];

    if (!body.name || typeof body.name !== "string" || body.name.trim().length === 0)
        validationErrors.push('"name" is required and must be a non-empty string.');

    const price = parseFloat(body.price);
    if (body.price === undefined || body.price === null || isNaN(price) || price < 0)
        validationErrors.push('"price" is required and must be a non-negative number.');

    if (!body.category || typeof body.category !== "string" || body.category.trim().length === 0)
        validationErrors.push('"category" is required and must be a non-empty string.');

    const stockQty = parseInt(body.stock_quantity, 10);
    if (body.stock_quantity === undefined || body.stock_quantity === null || isNaN(stockQty) || stockQty < 0)
        validationErrors.push('"stock_quantity" is required and must be a non-negative integer.');

    if (validationErrors.length > 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: "Product validation failed.", errors: validationErrors,
        });
    }

    const name = body.name.trim();
    const category = body.category.trim();
    const description = (typeof body.description === "string" && body.description.trim().length > 0)
        ? body.description.trim() : null;
    const imageUrl = (typeof body.image_url === "string" && body.image_url.trim().length > 0)
        ? body.image_url.trim() : null;
    const inStock = stockQty > 0;

    try {
        const result = await pool.query(
            `INSERT INTO products
                (name, description, price, category, in_stock, image_url, stock_quantity)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, name, description, price, category, in_stock, image_url, stock_quantity, created_at;`,
            [name, description, price, category, inStock, imageUrl, stockQty]
        );
        const newProduct = result.rows[0];
        console.log(`[Admin] New product — id: ${newProduct.id}, name: "${newProduct.name}", price: ₹${price}`);
        return res.status(201).json({
            status: "success",
            message: "Product added successfully.",
            data: newProduct,
        });
    } catch (err) {
        err.message = `[DB] Failed to add product: ${err.message}`;
        return next(err);
    }
});

// ── PUT /api/v1/admin/products/:id ────────────────────────────────────────────
// Full product update — replaces all updatable fields.
// Partial updates use COALESCE so omitted fields retain their current values.
app.put("/api/v1/admin/products/:id", verifyAdmin, async (req, res, next) => {
    const productId = parseInt(req.params.id, 10);
    if (!Number.isFinite(productId) || productId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid product id: "${req.params.id}". Must be a positive integer.`,
        });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const validationErrors = [];

    if (body.name !== undefined) {
        if (typeof body.name !== "string" || body.name.trim().length === 0)
            validationErrors.push('"name" must be a non-empty string.');
    }
    if (body.price !== undefined) {
        const price = parseFloat(body.price);
        if (isNaN(price) || price < 0)
            validationErrors.push('"price" must be a non-negative number.');
    }
    if (body.category !== undefined) {
        if (typeof body.category !== "string" || body.category.trim().length === 0)
            validationErrors.push('"category" must be a non-empty string.');
    }
    if (body.stock_quantity !== undefined) {
        const qty = parseInt(body.stock_quantity, 10);
        if (!Number.isFinite(qty) || qty < 0)
            validationErrors.push('"stock_quantity" must be a non-negative integer.');
    }
    if (validationErrors.length > 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: "Product update validation failed.", errors: validationErrors,
        });
    }

    try {
        // Fetch existing product first so we can COALESCE missing fields
        const existing = await pool.query(`SELECT * FROM products WHERE id = $1;`, [productId]);
        if (existing.rowCount === 0) {
            return res.status(404).json({
                status: "error", code: 404,
                message: `Product with id ${productId} not found.`,
            });
        }
        const p = existing.rows[0];

        const name = body.name !== undefined ? body.name.trim() : p.name;
        const description = body.description !== undefined ? (body.description?.trim() || null) : p.description;
        const price = body.price !== undefined ? parseFloat(body.price) : parseFloat(p.price);
        const category = body.category !== undefined ? body.category.trim() : p.category;
        const imageUrl = body.image_url !== undefined ? (body.image_url?.trim() || null) : p.image_url;
        const stockQty = body.stock_quantity !== undefined ? parseInt(body.stock_quantity, 10) : p.stock_quantity;
        const inStock = stockQty > 0;

        const result = await pool.query(
            `UPDATE products
             SET name = $1, description = $2, price = $3, category = $4,
                 in_stock = $5, image_url = $6, stock_quantity = $7
             WHERE id = $8
             RETURNING id, name, description, price, category, in_stock, image_url, stock_quantity, created_at;`,
            [name, description, price, category, inStock, imageUrl, stockQty, productId]
        );

        console.log(`[Admin] Product #${productId} updated — "${name}", price: ₹${price}`);
        return res.status(200).json({
            status: "success",
            message: "Product updated successfully.",
            data: result.rows[0],
        });
    } catch (err) {
        err.message = `[DB] Failed to update product #${productId}: ${err.message}`;
        return next(err);
    }
});

// ── DELETE /api/v1/admin/products/:id ─────────────────────────────────────────
// Hard-deletes a product. Returns 409 if the product has live order references.
// In that case, set stock_quantity = 0 instead to retire it gracefully.
app.delete("/api/v1/admin/products/:id", verifyAdmin, async (req, res, next) => {
    const productId = parseInt(req.params.id, 10);
    if (!Number.isFinite(productId) || productId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid product id: "${req.params.id}". Must be a positive integer.`,
        });
    }

    try {
        // Check for existing order references — deleting would orphan order_items rows.
        const refCheck = await pool.query(
            `SELECT COUNT(*) FROM order_items WHERE product_id = $1;`,
            [productId]
        );
        const refCount = parseInt(refCheck.rows[0].count, 10);
        if (refCount > 0) {
            return res.status(409).json({
                status: "error", code: 409,
                message: `Cannot delete product #${productId} — it appears in ${refCount} order(s). ` +
                    `Set stock_quantity to 0 via PATCH /api/v1/admin/products/${productId}/stock to retire it instead.`,
            });
        }

        const result = await pool.query(
            `DELETE FROM products WHERE id = $1 RETURNING id, name;`,
            [productId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({
                status: "error", code: 404,
                message: `Product with id ${productId} not found.`,
            });
        }

        console.log(`[Admin] Product #${productId} ("${result.rows[0].name}") deleted.`);
        return res.status(200).json({
            status: "success",
            message: `Product "${result.rows[0].name}" deleted successfully.`,
        });
    } catch (err) {
        err.message = `[DB] Failed to delete product #${productId}: ${err.message}`;
        return next(err);
    }
});

// ── GET /api/v1/admin/users ───────────────────────────────────────────────────
// Returns a paginated list of all registered users.
// Supports search by name, email, or phone.
// Passwords and internal hashes are never returned.
app.get("/api/v1/admin/users", verifyAdmin, async (req, res, next) => {
    try {
        const conditions = [];
        const params = [];

        if (req.query.q && typeof req.query.q === "string" && req.query.q.trim()) {
            const term = `%${req.query.q.trim().toLowerCase()}%`;
            params.push(term);
            const idx = params.length;
            conditions.push(
                `(LOWER(full_name) LIKE $${idx} OR LOWER(email) LIKE $${idx} OR phone LIKE $${idx})`
            );
        }

        const rawPage = parseInt(req.query.page, 10);
        const rawLimit = parseInt(req.query.limit, 10);
        const page = Number.isFinite(rawPage) && rawPage > 0 ? rawPage : 1;
        const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 100) : 20;
        const offset = (page - 1) * limit;

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

        const countResult = await pool.query(
            `SELECT COUNT(*) FROM users ${whereClause};`, params
        );
        const total = parseInt(countResult.rows[0].count, 10);

        params.push(limit, offset);
        const result = await pool.query(
            `SELECT id, full_name, email, phone, address, pin_code, created_at
             FROM users
             ${whereClause}
             ORDER BY created_at DESC
             LIMIT $${params.length - 1} OFFSET $${params.length};`,
            params
        );

        return res.status(200).json({
            status: "success",
            count: result.rowCount,
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
            data: result.rows,
        });
    } catch (err) {
        err.message = `[DB] Failed to fetch users: ${err.message}`;
        return next(err);
    }
});

// ── GET /api/v1/admin/users/:id ───────────────────────────────────────────────
// Returns a single user's profile and their full order history.
app.get("/api/v1/admin/users/:id", verifyAdmin, async (req, res, next) => {
    const userId = parseInt(req.params.id, 10);
    if (!Number.isFinite(userId) || userId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid user id: "${req.params.id}". Must be a positive integer.`,
        });
    }
    try {
        const userResult = await pool.query(
            `SELECT id, full_name, email, phone, address, pin_code, created_at
             FROM users WHERE id = $1;`,
            [userId]
        );
        if (userResult.rowCount === 0) {
            return res.status(404).json({
                status: "error", code: 404,
                message: `User with id ${userId} not found.`,
            });
        }
        const ordersResult = await pool.query(
            `SELECT id, total_amount, status, payment_method, created_at
             FROM orders WHERE user_id = $1 ORDER BY created_at DESC;`,
            [userId]
        );
        return res.status(200).json({
            status: "success",
            data: {
                ...userResult.rows[0],
                orders: ordersResult.rows,
                order_count: ordersResult.rowCount,
            },
        });
    } catch (err) {
        err.message = `[DB] Failed to fetch user #${userId}: ${err.message}`;
        return next(err);
    }
});

// ── DELETE /api/v1/admin/users/:id ────────────────────────────────────────────
// Deletes a user account. Orders are preserved (user_id SET NULL).
// Refresh tokens and cart cascade-delete automatically via FK.
app.delete("/api/v1/admin/users/:id", verifyAdmin, async (req, res, next) => {
    const userId = parseInt(req.params.id, 10);
    if (!Number.isFinite(userId) || userId <= 0) {
        return res.status(400).json({
            status: "error", code: 400,
            message: `Invalid user id: "${req.params.id}". Must be a positive integer.`,
        });
    }
    try {
        const result = await pool.query(
            `DELETE FROM users WHERE id = $1 RETURNING id, full_name, email;`,
            [userId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({
                status: "error", code: 404,
                message: `User with id ${userId} not found.`,
            });
        }
        const u = result.rows[0];
        console.log(`[Admin] User #${u.id} ("${u.full_name}" <${u.email}>) deleted.`);
        return res.status(200).json({
            status: "success",
            message: `User account for "${u.full_name}" deleted.`,
        });
    } catch (err) {
        err.message = `[DB] Failed to delete user #${userId}: ${err.message}`;
        return next(err);
    }
});

// ── GET /api/v1/admin/dashboard ───────────────────────────────────────────────
// Returns key metrics for an admin dashboard in a single query bundle.
app.get("/api/v1/admin/dashboard", verifyAdmin, async (req, res, next) => {
    try {
        const [
            ordersStats,
            revenueResult,
            productsStats,
            usersCount,
            recentOrders,
            lowStockProducts,
        ] = await Promise.all([
            pool.query(`
                SELECT
                    COUNT(*)                                          AS total_orders,
                    COUNT(*) FILTER (WHERE status = 'pending')       AS pending_orders,
                    COUNT(*) FILTER (WHERE status = 'confirmed')     AS confirmed_orders,
                    COUNT(*) FILTER (WHERE status = 'shipped')       AS shipped_orders,
                    COUNT(*) FILTER (WHERE status = 'delivered')     AS delivered_orders,
                    COUNT(*) FILTER (WHERE status = 'cancelled')     AS cancelled_orders
                FROM orders;
            `),
            pool.query(`
                SELECT
                    COALESCE(SUM(total_amount), 0)                                AS total_revenue,
                    COALESCE(SUM(total_amount) FILTER (WHERE status = 'delivered'), 0) AS confirmed_revenue
                FROM orders;
            `),
            pool.query(`
                SELECT
                    COUNT(*)                                 AS total_products,
                    COUNT(*) FILTER (WHERE in_stock = true)  AS in_stock_count,
                    COUNT(*) FILTER (WHERE in_stock = false) AS out_of_stock_count,
                    COUNT(*) FILTER (WHERE stock_quantity <= 5 AND in_stock = true) AS low_stock_count
                FROM products;
            `),
            pool.query(`SELECT COUNT(*) AS total_users FROM users;`),
            pool.query(`
                SELECT id, customer_name, total_amount, status, created_at
                FROM orders ORDER BY created_at DESC LIMIT 5;
            `),
            pool.query(`
                SELECT id, name, category, stock_quantity, price
                FROM products
                WHERE stock_quantity <= 5 AND in_stock = true
                ORDER BY stock_quantity ASC LIMIT 10;
            `),
        ]);

        return res.status(200).json({
            status: "success",
            data: {
                orders: ordersStats.rows[0],
                revenue: revenueResult.rows[0],
                products: productsStats.rows[0],
                users: usersCount.rows[0],
                recent_orders: recentOrders.rows,
                low_stock_alerts: lowStockProducts.rows,
            },
        });
    } catch (err) {
        err.message = `[DB] Failed to fetch dashboard metrics: ${err.message}`;
        return next(err);
    }
});

// ── GET /api/v1/admin/messages ────────────────────────────────────────────────
app.get("/api/v1/admin/messages", verifyAdmin, async (req, res, next) => {
    try {
        const conditions = [];
        const params = [];

        if (req.query.subject && typeof req.query.subject === "string" && req.query.subject.trim()) {
            params.push(req.query.subject.trim().toLowerCase());
            conditions.push(`LOWER(subject) = $${params.length}`);
        }

        if (req.query.q && typeof req.query.q === "string" && req.query.q.trim()) {
            const term = `%${req.query.q.trim().toLowerCase()}%`;
            params.push(term);
            const idx = params.length;
            conditions.push(`(LOWER(full_name) LIKE $${idx} OR LOWER(email) LIKE $${idx} OR LOWER(message) LIKE $${idx})`);
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

        const result = await pool.query(
            `SELECT id, full_name, phone, email, subject, message, created_at
             FROM contact_submissions
             ${whereClause}
             ORDER BY created_at DESC;`,
            params
        );
        return res.status(200).json({ status: "success", count: result.rowCount, data: result.rows });
    } catch (err) {
        err.message = `[DB] Failed to fetch messages: ${err.message}`;
        return next(err);
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  ERROR HANDLING
// ══════════════════════════════════════════════════════════════════════════════

// ── 404 ────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({
        status: "error", code: 404,
        message: `Route not found: ${req.method} ${req.originalUrl}`,
    });
});

// ── Global error handler ───────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error("────────────────────────────────────────");
    console.error("[Global Error Handler]");
    console.error(`Timestamp : ${new Date().toISOString()}`);
    console.error(`Route     : ${req.method} ${req.originalUrl}`);
    console.error(`Message   : ${err.message}`);
    console.error("Stack     :", err.stack);
    console.error("────────────────────────────────────────");

    const statusCode = err.status || err.statusCode || 500;
    // Stack traces are already logged above. Never send them to the client.
    res.status(statusCode).json({
        status: "error",
        code: statusCode,
        message: "An unexpected internal server error occurred.",
    });
});

// ══════════════════════════════════════════════════════════════════════════════
//  SERVER BOOT
// ══════════════════════════════════════════════════════════════════════════════
app.listen(PORT, async () => {
    console.log("╔══════════════════════════════════════════════╗");
    console.log("║   MANISH GENERAL STORE — API SERVER v3.0     ║");
    console.log("╠══════════════════════════════════════════════╣");
    console.log(`║  Status   : Running                          ║`);
    console.log(`║  Port     : ${PORT}                               ║`);
    console.log(`║  Env      : ${(process.env.NODE_ENV || "development").padEnd(34)}║`);
    console.log(`║  Health   : http://localhost:${PORT}/api/v1/health ║`);
    console.log(`║  CORS     : ${(ALLOWED_ORIGINS[0] || "*").padEnd(34)}║`);
    console.log("╚══════════════════════════════════════════════╝");
    await initializeDatabase();
    scheduleRefreshTokenCleanup();
    console.log("[Boot] Server fully ready. Accepting connections.");
});

process.on("unhandledRejection", (reason, promise) => {
    console.error("[unhandledRejection] Unhandled Promise Rejection:", reason);
    console.error("Promise:", promise);
    process.exit(1);
});

process.on("uncaughtException", (err) => {
    console.error("[uncaughtException] Uncaught Exception:", err.message);
    console.error(err.stack);
    process.exit(1);
});

// ── Graceful shutdown ──────────────────────────────────────────────────────────
// Closes the DB pool cleanly so in-flight queries can complete before exit.
async function gracefulShutdown(signal) {
    console.log(`\n[Shutdown] Received ${signal}. Closing server gracefully...`);
    try {
        await pool.end();
        console.log("[Shutdown] PostgreSQL pool closed.");
    } catch (err) {
        console.error("[Shutdown] Error closing pool:", err.message);
    }
    process.exit(0);
}
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// ── Expired refresh token cleanup job ─────────────────────────────────────────
// Runs every 24 hours to prune revoked / expired tokens from the DB.
// This is a simple in-process cron — for high-traffic apps, move to a
// dedicated job queue (e.g. pg-boss, BullMQ).
function scheduleRefreshTokenCleanup() {
    const INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
    setInterval(async () => {
        try {
            const result = await pool.query(
                `DELETE FROM refresh_tokens
                 WHERE revoked = true OR expires_at < NOW();`
            );
            if (result.rowCount > 0) {
                console.log(`[Cleanup] Pruned ${result.rowCount} expired/revoked refresh token(s).`);
            }
        } catch (err) {
            console.error("[Cleanup] Failed to prune refresh tokens:", err.message);
        }
    }, INTERVAL_MS);
    console.log("[Cleanup] Refresh token cleanup job scheduled (every 24h).");
}