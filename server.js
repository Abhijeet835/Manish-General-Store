"use strict";

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const JWT_SECRET = process.env.JWT_SECRET || "manish_secret_123";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    ssl: process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: true }   // ✅ Verifies Neon's cert in production
        : false                          // ✅ No SSL needed for local dev
});

pool.on("error", (err) => {
    console.error("[pg Pool] Unexpected error on idle client:", err.message);
});
pool.on("connect", () => {
    console.log("[pg Pool] New client connected to PostgreSQL.");
});
pool.on("remove", () => {
    console.log("[pg Pool] Client removed from pool.");
});

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    optionsSuccessStatus: 200,
}));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

function verifyAdmin(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            status: "error",
            code: 401,
            message: "Unauthorized: missing or malformed Authorization header.",
        });
    }
    const token = authHeader.slice(7);
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        return next();
    } catch (err) {
        return res.status(401).json({
            status: "error",
            code: 401,
            message: "Unauthorized: invalid or expired token.",
        });
    }
}

async function initializeDatabase() {
    let client;
    try {
        client = await pool.connect();
        console.log("[DB Init] Connected to PostgreSQL. Running table migrations...");

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
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_contact_submissions_email
                ON contact_submissions (email);
        `);
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_contact_submissions_created_at
                ON contact_submissions (created_at DESC);
        `);
        console.log("[DB Init] contact_submissions table is ready.");

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

        await client.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id             SERIAL        PRIMARY KEY,
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
        console.log("[DB Init] orders table is ready.");

        await client.query(`
            CREATE TABLE IF NOT EXISTS order_items (
                id                SERIAL        PRIMARY KEY,
                order_id          INT           NOT NULL
                                  REFERENCES orders(id) ON DELETE CASCADE,
                product_id        INT           NOT NULL,
                quantity          INT           NOT NULL CHECK (quantity > 0),
                price_at_purchase NUMERIC(10,2) NOT NULL
            );
        `);
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_order_items_order_id
                ON order_items (order_id);
        `);
        console.log("[DB Init] order_items table is ready.");

    } catch (err) {
        console.error("[DB Init] FATAL: Could not initialise the database.");
        console.error("[DB Init] Error:", err.message);
        process.exit(1);
    } finally {
        if (client) client.release();
    }
}

const validateContactPayload = (body) => {
    const REQUIRED_FIELDS = ["fullName", "email", "subject", "message"];
    const errors = [];
    REQUIRED_FIELDS.forEach((field) => {
        const value = body[field];
        if (value === undefined || value === null) {
            errors.push(`"${field}" is required.`);
        } else if (typeof value !== "string") {
            errors.push(`"${field}" must be a string, received ${typeof value}.`);
        } else if (value.trim().length === 0) {
            errors.push(`"${field}" must not be empty or blank.`);
        }
    });
    return { valid: errors.length === 0, errors };
};

// Health check
app.get("/api/v1/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        message: "Manish General Store API is up and running.",
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || "development",
        uptime: `${process.uptime().toFixed(2)}s`,
        pid: process.pid,
    });
});

// API root
app.get("/api/v1", (req, res) => {
    res.status(200).json({
        message: "Welcome to the Manish General Store API.",
        version: "1.0.0",
        docs: "/api/v1/health",
    });
});

// POST /api/v1/contact
app.post("/api/v1/contact", async (req, res, next) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { valid, errors } = validateContactPayload(body);

    if (!valid) {
        return res.status(400).json({
            status: "error",
            code: 400,
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
    console.log("────────────────────────────────────────────────");
    console.log(`  Timestamp : ${new Date().toISOString()}`);
    console.log(`  Full Name : ${submission.fullName}`);
    console.log(`  Email     : ${submission.email}`);
    console.log(`  Subject   : ${submission.subject}`);
    console.log(`  Phone     : ${submission.phone ?? "not provided"}`);
    console.log(`  Message   : ${submission.message}`);
    console.log("════════════════════════════════════════════════");

    try {
        const result = await pool.query(
            `INSERT INTO contact_submissions
                (full_name, phone, email, subject, message)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, created_at;`,
            [submission.fullName, submission.phone, submission.email, submission.subject, submission.message]
        );
        const { id, created_at } = result.rows[0];
        console.log(`[DB] Submission saved — id: ${id}, created_at: ${created_at}`);
        return res.status(201).json({
            status: "success",
            message: "Message received successfully by the server!",
            data: { id, created_at },
        });
    } catch (dbErr) {
        dbErr.message = `[DB] Failed to save contact submission: ${dbErr.message}`;
        return next(dbErr);
    }
});

// GET /api/v1/products
app.get("/api/v1/products", async (req, res, next) => {
    try {
        const result = await pool.query("SELECT * FROM products ORDER BY id ASC;");
        return res.status(200).json({
            status: "success",
            count: result.rowCount,
            data: result.rows,
        });
    } catch (err) {
        err.message = `[DB] Failed to fetch products: ${err.message}`;
        return next(err);
    }
});

const DELIVERY_FEE = 30.00;

// POST /api/v1/orders
app.post("/api/v1/orders", async (req, res, next) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { cart, contact, address, payment } = body;
    const shapeErrors = [];

    if (!cart || typeof cart !== "object" || Array.isArray(cart)) {
        shapeErrors.push('"cart" must be a non-null object mapping product IDs to quantities.');
    } else if (Object.keys(cart).length === 0) {
        shapeErrors.push('"cart" must not be empty.');
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
    } else if (typeof payment.method !== "string" || payment.method.trim().length === 0) {
        shapeErrors.push('"payment.method" is required.');
    }

    if (shapeErrors.length > 0) {
        return res.status(400).json({ status: "error", code: 400, message: "Order validation failed.", errors: shapeErrors });
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
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        let subtotal = 0;
        const validatedCartLines = [];
        const cartErrors = [];

        for (const [rawId, rawQty] of Object.entries(cart)) {
            const productId = parseInt(rawId, 10);
            const quantity = parseInt(rawQty, 10);

            if (isNaN(productId) || productId <= 0) {
                cartErrors.push(`Invalid product id: "${rawId}".`);
                continue;
            }
            if (isNaN(quantity) || quantity <= 0) {
                cartErrors.push(`Invalid quantity for product id ${productId}: "${rawQty}".`);
                continue;
            }

            const { rows } = await client.query(
                "SELECT id, name, price, in_stock, stock_quantity FROM products WHERE id = $1;",
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
                    `Only ${product.stock_quantity} unit${product.stock_quantity === 1 ? "" : "s"} of "${product.name}" ${product.stock_quantity === 1 ? "is" : "are"} available.`
                );
                continue;
            }

            const unitPrice = parseFloat(product.price);
            subtotal += unitPrice * quantity;
            validatedCartLines.push({ productId, quantity, price: unitPrice });
        }

        if (cartErrors.length > 0) {
            await client.query("ROLLBACK");
            return res.status(400).json({ status: "error", code: 400, message: "One or more cart items are invalid.", errors: cartErrors });
        }

        const totalAmount = parseFloat((subtotal + DELIVERY_FEE).toFixed(2));

        console.log("════════════════════════════════════════════════");
        console.log("[POST /api/v1/orders] New Order Submission");
        console.log("────────────────────────────────────────────────");
        console.log(`  Timestamp : ${new Date().toISOString()}`);
        console.log(`  Customer  : ${orderContact.name} <${orderContact.email}>`);
        console.log(`  Phone     : ${orderContact.phone}`);
        console.log(`  Address   : ${orderAddress.street}, PIN ${orderAddress.pin}`);
        console.log(`  Payment   : ${paymentMethod}`);
        console.log(`  Lines     : ${validatedCartLines.length} item(s)`);
        console.log(`  Subtotal  : ₹${subtotal.toFixed(2)}`);
        console.log(`  Delivery  : ₹${DELIVERY_FEE.toFixed(2)}`);
        console.log(`  Total     : ₹${totalAmount.toFixed(2)}`);
        console.log("════════════════════════════════════════════════");

        const insertOrderResult = await client.query(
            `INSERT INTO orders
                (customer_name, email, phone, address, pin_code, payment_method, total_amount)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id;`,
            [orderContact.name, orderContact.email, orderContact.phone, orderAddress.street, orderAddress.pin, paymentMethod, totalAmount]
        );

        const newOrderId = insertOrderResult.rows[0].id;

        for (const line of validatedCartLines) {
            await client.query(
                `INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase)
                 VALUES ($1, $2, $3, $4);`,
                [newOrderId, line.productId, line.quantity, line.price]
            );
        }

        for (const line of validatedCartLines) {
            const { rows: updatedRows } = await client.query(
                `UPDATE products
                 SET
                     stock_quantity = stock_quantity - $1,
                     in_stock       = CASE WHEN (stock_quantity - $1) <= 0 THEN false ELSE in_stock END
                 WHERE id = $2
                 RETURNING name, stock_quantity, in_stock;`,
                [line.quantity, line.productId]
            );
            if (updatedRows.length > 0) {
                const { name, stock_quantity: remaining, in_stock: stillInStock } = updatedRows[0];
                if (!stillInStock) {
                    console.warn(`OUT OF STOCK: "${name}" (id: ${line.productId}) has sold out.`);
                } else if (remaining <= 5) {
                    console.warn(`LOW STOCK ALERT: "${name}" has only ${remaining} unit${remaining === 1 ? "" : "s"} left!`);
                }
            }
        }

        await client.query("COMMIT");
        console.log(`[DB] Order #${newOrderId} committed — ${validatedCartLines.length} item(s), total ₹${totalAmount.toFixed(2)}`);

        return res.status(201).json({ status: "success", data: { order_id: newOrderId } });

    } catch (err) {
        try {
            await client.query("ROLLBACK");
            console.warn("[DB] Transaction rolled back due to error:", err.message);
        } catch (rollbackErr) {
            console.error("[DB] ROLLBACK failed:", rollbackErr.message);
        }
        err.message = `[DB] Failed to place order: ${err.message}`;
        return next(err);
    } finally {
        client.release();
    }
});

// POST /api/v1/admin/login  (public — no verifyAdmin)
app.post("/api/v1/admin/login", (req, res) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { username, password } = body;

    if (
        typeof username !== "string" || username.trim() === "" ||
        typeof password !== "string" || password.trim() === ""
    ) {
        return res.status(400).json({
            status: "error",
            code: 400,
            message: "Both username and password are required.",
        });
    }

    if (username.trim() !== ADMIN_USER || password !== ADMIN_PASS) {
        console.warn(`[Admin Login] Failed attempt — username: "${username.trim()}" at ${new Date().toISOString()}`);
        return res.status(401).json({
            status: "error",
            code: 401,
            message: "Invalid credentials.",
        });
    }

    const token = jwt.sign(
        { sub: username.trim(), role: "admin" },
        JWT_SECRET,
        { expiresIn: "24h" }
    );

    console.log(`[Admin Login] Successful login — username: "${username.trim()}" at ${new Date().toISOString()}`);

    return res.status(200).json({
        status: "success",
        message: "Login successful.",
        data: { token, expiresIn: "24h" },
    });
});

// GET /api/v1/admin/orders
app.get("/api/v1/admin/orders", verifyAdmin, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT id, customer_name, email, phone, address, pin_code,
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

// GET /api/v1/admin/orders/:id
app.get("/api/v1/admin/orders/:id", verifyAdmin, async (req, res, next) => {
    const orderId = parseInt(req.params.id, 10);
    if (isNaN(orderId) || orderId <= 0) {
        return res.status(400).json({ status: "error", code: 400, message: `Invalid order id: "${req.params.id}". Must be a positive integer.` });
    }

    try {
        const orderResult = await pool.query(
            `SELECT id, customer_name, email, phone, address, pin_code,
                    payment_method, total_amount, status, created_at
             FROM orders
             WHERE id = $1;`,
            [orderId]
        );

        if (orderResult.rowCount === 0) {
            return res.status(404).json({ status: "error", code: 404, message: `Order with id ${orderId} not found.` });
        }

        const order = orderResult.rows[0];

        const itemsResult = await pool.query(
            `SELECT
                oi.id,
                oi.product_id,
                COALESCE(p.name, 'Product #' || oi.product_id) AS product_name,
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

// PATCH /api/v1/admin/orders/:id/status
app.patch("/api/v1/admin/orders/:id/status", verifyAdmin, async (req, res, next) => {
    const orderId = parseInt(req.params.id, 10);
    if (isNaN(orderId) || orderId <= 0) {
        return res.status(400).json({ status: "error", code: 400, message: `Invalid order id: "${req.params.id}". Must be a positive integer.` });
    }

    const VALID_STATUSES = ["pending", "confirmed", "shipped", "delivered", "cancelled"];
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const { status } = body;

    if (!status || typeof status !== "string") {
        return res.status(400).json({ status: "error", code: 400, message: '"status" field is required and must be a string.' });
    }

    const normalised = status.trim().toLowerCase();
    if (!VALID_STATUSES.includes(normalised)) {
        return res.status(400).json({ status: "error", code: 400, message: `Invalid status value: "${status}". Must be one of: ${VALID_STATUSES.join(", ")}.` });
    }

    try {
        const result = await pool.query(
            `UPDATE orders
             SET status = $1
             WHERE id = $2
             RETURNING id, status, created_at;`,
            [normalised, orderId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ status: "error", code: 404, message: `Order with id ${orderId} not found.` });
        }

        console.log(`[Admin] Order #${orderId} status -> "${normalised}"`);
        return res.status(200).json({ status: "success", data: result.rows[0] });

    } catch (err) {
        err.message = `[DB] Failed to update order #${orderId} status: ${err.message}`;
        return next(err);
    }
});

// PATCH /api/v1/admin/products/:id/stock
app.patch("/api/v1/admin/products/:id/stock", verifyAdmin, async (req, res, next) => {
    const productId = parseInt(req.params.id, 10);
    if (isNaN(productId) || productId <= 0) {
        return res.status(400).json({ status: "error", code: 400, message: `Invalid product id: "${req.params.id}". Must be a positive integer.` });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const rawQty = body.stock_quantity;
    const newQty = parseInt(rawQty, 10);

    if (rawQty === undefined || rawQty === null) {
        return res.status(400).json({ status: "error", code: 400, message: '"stock_quantity" field is required.' });
    }
    if (isNaN(newQty) || newQty < 0) {
        return res.status(400).json({ status: "error", code: 400, message: `"stock_quantity" must be a non-negative integer. Received: ${rawQty}` });
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
            return res.status(404).json({ status: "error", code: 404, message: `Product with id ${productId} not found.` });
        }

        const updated = result.rows[0];
        console.log(`[Admin] Product #${productId} ("${updated.name}") stock -> ${newQty} (in_stock: ${updated.in_stock})`);

        if (newQty === 0) {
            console.warn(`OUT OF STOCK: Product #${productId} ("${updated.name}") set to 0.`);
        } else if (newQty <= 5) {
            console.warn(`LOW STOCK: Product #${productId} ("${updated.name}") set to ${newQty} unit(s).`);
        }

        return res.status(200).json({ status: "success", data: updated });

    } catch (err) {
        err.message = `[DB] Failed to update stock for product #${productId}: ${err.message}`;
        return next(err);
    }
});

// POST /api/v1/admin/products
app.post("/api/v1/admin/products", verifyAdmin, async (req, res, next) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const validationErrors = [];

    if (!body.name || typeof body.name !== "string" || body.name.trim().length === 0) {
        validationErrors.push('"name" is required and must be a non-empty string.');
    }

    const price = parseFloat(body.price);
    if (body.price === undefined || body.price === null || isNaN(price) || price < 0) {
        validationErrors.push('"price" is required and must be a non-negative number.');
    }

    if (!body.category || typeof body.category !== "string" || body.category.trim().length === 0) {
        validationErrors.push('"category" is required and must be a non-empty string.');
    }

    const stockQty = parseInt(body.stock_quantity, 10);
    if (body.stock_quantity === undefined || body.stock_quantity === null || isNaN(stockQty) || stockQty < 0) {
        validationErrors.push('"stock_quantity" is required and must be a non-negative integer.');
    }

    if (validationErrors.length > 0) {
        return res.status(400).json({ status: "error", code: 400, message: "Product validation failed.", errors: validationErrors });
    }

    const name = body.name.trim();
    const category = body.category.trim();
    const description = (typeof body.description === "string" && body.description.trim().length > 0) ? body.description.trim() : null;
    const imageUrl = (typeof body.image_url === "string" && body.image_url.trim().length > 0) ? body.image_url.trim() : null;
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
        console.log(`[Admin] New product added — id: ${newProduct.id}, name: "${newProduct.name}", price: ₹${price}, stock: ${stockQty}`);

        return res.status(201).json({ status: "success", message: "Product added successfully.", data: newProduct });

    } catch (err) {
        err.message = `[DB] Failed to add product: ${err.message}`;
        return next(err);
    }
});

// GET /api/v1/admin/messages
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

// 404
app.use((req, res) => {
    res.status(404).json({ status: "error", code: 404, message: `Route not found: ${req.method} ${req.originalUrl}` });
});

// Global error handler
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
    const isProduction = process.env.NODE_ENV === "production";

    res.status(statusCode).json({
        status: "error",
        code: statusCode,
        message: err.message || "An unexpected internal server error occurred.",
        ...(isProduction ? {} : { stack: err.stack }),
    });
});

app.listen(PORT, async () => {
    console.log("╔══════════════════════════════════════════════╗");
    console.log("║       MANISH GENERAL STORE — API SERVER      ║");
    console.log("╠══════════════════════════════════════════════╣");
    console.log(`║  Status   : Running                          ║`);
    console.log(`║  Port     : ${PORT}                               ║`);
    console.log(`║  Env      : ${(process.env.NODE_ENV || "development").padEnd(34)}║`);
    console.log(`║  Health   : http://localhost:${PORT}/api/v1/health ║`);
    console.log("╚══════════════════════════════════════════════╝");
    await initializeDatabase();
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