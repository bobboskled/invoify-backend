require("dotenv").config();
const express    = require("express");
const mysql      = require("mysql2");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const cors       = require("cors");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const { OAuth2Client } = require("google-auth-library");
const nodemailer = require("nodemailer");
const crypto     = require("crypto");

const app          = express();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL, methods: ["GET","POST","PUT","DELETE"], allowedHeaders: ["Content-Type","Authorization"] }));
app.use(express.json({ limit: "5mb" }));

const general  = rateLimit({ windowMs:15*60*1000, max:100, message:{ error:"Too many requests." }, standardHeaders:true, legacyHeaders:false });
const auth     = rateLimit({ windowMs:15*60*1000, max:10,  message:{ error:"Too many attempts." }, standardHeaders:true, legacyHeaders:false });
const emailLim = rateLimit({ windowMs:60*60*1000, max:5,   message:{ error:"Too many reset attempts." }, standardHeaders:true, legacyHeaders:false });
app.use(general);

// ── Database ──────────────────────────────────────────
const db = mysql.createPool({
  host: process.env.DB_HOST, user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 10, queueLimit: 0,
});

db.getConnection((err, conn) => {
  if (err) { console.error("❌ Database connection failed:", err.message); process.exit(1); }
  console.log("✅ Connected to MySQL!");

  conn.query(`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY, full_name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL,
    plan VARCHAR(20) DEFAULT 'free', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL, is_verified BOOLEAN DEFAULT FALSE,
    failed_attempts INT DEFAULT 0, locked_until TIMESTAMP NULL,
    verify_token VARCHAR(255) NULL, token_expires TIMESTAMP NULL
  )`, err => { if (err) console.error("Users table error:", err.message); else console.log("✅ Users table ready!"); });

  conn.query(`CREATE TABLE IF NOT EXISTS clients (
    id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL,
    name VARCHAR(100) NOT NULL, email VARCHAR(150) DEFAULT '',
    phone VARCHAR(30) DEFAULT '', company VARCHAR(100) DEFAULT '',
    address VARCHAR(255) DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`, err => { if (err) console.error("Clients table error:", err.message); else console.log("✅ Clients table ready!"); });

  conn.query(`CREATE TABLE IF NOT EXISTS invoices (
    id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, client_id INT NOT NULL,
    invoice_number VARCHAR(50) NOT NULL, status VARCHAR(20) DEFAULT 'draft',
    issue_date DATE, due_date DATE, notes TEXT,
    subtotal DECIMAL(10,2) DEFAULT 0, tax_rate DECIMAL(5,2) DEFAULT 0,
    tax_amount DECIMAL(10,2) DEFAULT 0, total DECIMAL(10,2) DEFAULT 0,
    stripe_payment_link VARCHAR(500) DEFAULT '', paid_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
  )`, err => { if (err) console.error("Invoices table error:", err.message); else console.log("✅ Invoices table ready!"); });

  conn.query(`CREATE TABLE IF NOT EXISTS invoice_items (
    id INT AUTO_INCREMENT PRIMARY KEY, invoice_id INT NOT NULL,
    description VARCHAR(255) NOT NULL, quantity DECIMAL(10,2) DEFAULT 1,
    unit_price DECIMAL(10,2) DEFAULT 0, total DECIMAL(10,2) DEFAULT 0,
    FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
  )`, err => { if (err) console.error("Items table error:", err.message); else console.log("✅ Invoice items table ready!"); });

  conn.release();
});

// ── Auth Middleware ───────────────────────────────────
const verifyToken = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ error:"No token provided" });
  try { req.user = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET); next(); }
  catch (err) { return res.status(401).json({ error: err.name==="TokenExpiredError" ? "Session expired." : "Invalid token" }); }
};

// ─────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────

app.post("/api/register", auth, [
  body("full_name").trim().notEmpty().isLength({ min:2, max:100 }).matches(/^[a-zA-Z\s'-]+$/),
  body("email").trim().notEmpty().isEmail().normalizeEmail().isLength({ max:150 }),
  body("password").notEmpty().isLength({ min:8 }).matches(/[A-Z]/).matches(/[0-9]/).matches(/[!@#$%^&*(),.?":{}|<>]/),
], async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { full_name, email, password } = req.body;
  db.query("SELECT id FROM users WHERE email=?", [email], async (err, rows) => {
    if (err) return res.status(500).json({ error:"Database error" });
    if (rows.length) return res.status(409).json({ error:"An account with this email already exists" });
    const hashed = await bcrypt.hash(password, 12);
    db.query("INSERT INTO users (full_name,email,password) VALUES (?,?,?)", [full_name, email, hashed], (err, result) => {
      if (err) return res.status(500).json({ error:"Failed to create account" });
      const token = jwt.sign({ id:result.insertId, email }, process.env.JWT_SECRET, { expiresIn:process.env.JWT_EXPIRES_IN });
      res.status(201).json({ token, user:{ id:result.insertId, full_name, email, plan:"free" } });
    });
  });
});

app.post("/api/login", auth, [
  body("email").trim().notEmpty().isEmail().normalizeEmail(),
  body("password").notEmpty(),
], async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { email, password } = req.body;
  db.query("SELECT * FROM users WHERE email=?", [email], async (err, rows) => {
    if (err) return res.status(500).json({ error:"Database error" });
    if (!rows.length) return res.status(401).json({ error:"Invalid email or password" });
    const user = rows[0];
    if (user.locked_until && new Date(user.locked_until) > new Date())
      return res.status(423).json({ error:"Account temporarily locked. Try again later." });
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      const attempts = (user.failed_attempts||0) + 1;
      db.query("UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?", [attempts, attempts>=5?new Date(Date.now()+30*60*1000):null, user.id]);
      return res.status(401).json({ error:"Invalid email or password" });
    }
    db.query("UPDATE users SET failed_attempts=0,locked_until=NULL,last_login=NOW() WHERE id=?", [user.id]);
    const token = jwt.sign({ id:user.id, email:user.email }, process.env.JWT_SECRET, { expiresIn:process.env.JWT_EXPIRES_IN });
    res.json({ token, user:{ id:user.id, full_name:user.full_name, email:user.email, plan:user.plan } });
  });
});

app.post("/api/google-login", auth, async (req, res) => {
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error:"Google token required" });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken:credential, audience:process.env.GOOGLE_CLIENT_ID });
    const { email, name } = ticket.getPayload();
    db.query("SELECT * FROM users WHERE email=?", [email], async (err, rows) => {
      if (err) return res.status(500).json({ error:"Database error" });
      if (!rows.length) {
        db.query("INSERT INTO users (full_name,email,password,is_verified) VALUES (?,?,?,?)", [name,email,"",true], (err,result) => {
          if (err) return res.status(500).json({ error:"Failed to create account" });
          const token = jwt.sign({ id:result.insertId, email }, process.env.JWT_SECRET, { expiresIn:process.env.JWT_EXPIRES_IN });
          res.status(201).json({ token, user:{ id:result.insertId, full_name:name, email, plan:"free" } });
        });
      } else {
        const user = rows[0];
        db.query("UPDATE users SET last_login=NOW() WHERE id=?", [user.id]);
        const token = jwt.sign({ id:user.id, email:user.email }, process.env.JWT_SECRET, { expiresIn:process.env.JWT_EXPIRES_IN });
        res.json({ token, user:{ id:user.id, full_name:user.full_name, email:user.email, plan:user.plan } });
      }
    });
  } catch (err) { console.error("Google error:", err.message); res.status(401).json({ error:"Invalid Google token" }); }
});

app.post("/api/forgot-password", emailLim, [
  body("email").trim().notEmpty().isEmail().normalizeEmail(),
], async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { email } = req.body;
  res.json({ message:"If an account exists, a reset link has been sent." });
  db.query("SELECT id FROM users WHERE email=?", [email], async (err, rows) => {
    if (err || !rows.length) return;
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 60*60*1000);
    db.query("UPDATE users SET verify_token=?,token_expires=? WHERE id=?", [token, expires, rows[0].id], async (err) => {
      if (err) return;
      const resetUrl = `${process.env.FRONTEND_URL}?token=${token}`;
      try {
        await transporter.sendMail({
          from: `"Invoify" <${process.env.EMAIL_USER}>`, to: email,
          subject: "Reset your Invoify password",
          html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
            <h2 style="color:#0D3D2E;">Reset your password</h2>
            <p style="color:#6A8A7A;">Click below to set a new password. Link expires in 1 hour.</p>
            <a href="${resetUrl}" style="display:block;background:#0D3D2E;color:#fff;text-decoration:none;padding:14px;border-radius:11px;text-align:center;font-weight:600;margin:24px 0;">Reset My Password →</a>
            <p style="color:#8AADA0;font-size:12px;">If you didn't request this, ignore this email.</p>
          </div>`,
        });
      } catch (e) { console.error("Email failed:", e.message); }
    });
  });
});

app.get("/api/verify-reset-token", (req, res) => {
  const { token } = req.query;
  if (!token) return res.json({ valid:false });
  db.query("SELECT id,token_expires FROM users WHERE verify_token=?", [token], (err, rows) => {
    if (err || !rows.length) return res.json({ valid:false });
    res.json({ valid: new Date(rows[0].token_expires) > new Date() });
  });
});

app.post("/api/reset-password", [
  body("token").notEmpty(),
  body("password").notEmpty().isLength({ min:8 }).matches(/[A-Z]/).matches(/[0-9]/).matches(/[!@#$%^&*(),.?":{}|<>]/),
], async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { token, password } = req.body;
  db.query("SELECT id,token_expires FROM users WHERE verify_token=?", [token], async (err, rows) => {
    if (err) return res.status(500).json({ error:"Database error" });
    if (!rows.length) return res.status(400).json({ error:"Invalid or expired reset link." });
    if (new Date(rows[0].token_expires) < new Date()) return res.status(400).json({ error:"This reset link has expired." });
    const hashed = await bcrypt.hash(password, 12);
    db.query("UPDATE users SET password=?,verify_token=NULL,token_expires=NULL,failed_attempts=0,locked_until=NULL WHERE id=?", [hashed, rows[0].id], (err) => {
      if (err) return res.status(500).json({ error:"Failed to update password." });
      res.json({ message:"Password updated successfully!" });
    });
  });
});

app.get("/api/me", verifyToken, (req, res) => {
  db.query("SELECT id,full_name,email,plan,created_at FROM users WHERE id=?", [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error:"Database error" });
    if (!rows.length) return res.status(404).json({ error:"User not found" });
    res.json({ user:rows[0] });
  });
});

// ─────────────────────────────────────────────────────
// CLIENTS ROUTES
// ─────────────────────────────────────────────────────

app.get("/api/clients", verifyToken, (req, res) => {
  db.query(
    `SELECT c.*, COUNT(i.id) as invoice_count FROM clients c
     LEFT JOIN invoices i ON i.client_id = c.id
     WHERE c.user_id = ? GROUP BY c.id ORDER BY c.created_at DESC`,
    [req.user.id], (err, rows) => {
      if (err) return res.status(500).json({ error:"Database error" });
      res.json({ clients: rows });
    }
  );
});

app.post("/api/clients", verifyToken, [
  body("name").trim().notEmpty().withMessage("Client name is required").isLength({ max:100 }),
  body("email").optional({ checkFalsy:true }).isEmail().withMessage("Enter a valid email").normalizeEmail(),
  body("phone").optional({ checkFalsy:true }).isLength({ max:30 }),
  body("company").optional({ checkFalsy:true }).isLength({ max:100 }),
  body("address").optional({ checkFalsy:true }).isLength({ max:255 }),
], (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { name, email="", phone="", company="", address="" } = req.body;
  db.query("INSERT INTO clients (user_id,name,email,phone,company,address) VALUES (?,?,?,?,?,?)",
    [req.user.id, name, email, phone, company, address], (err, result) => {
      if (err) return res.status(500).json({ error:"Failed to create client" });
      db.query("SELECT * FROM clients WHERE id=?", [result.insertId], (err, rows) => {
        if (err) return res.status(500).json({ error:"Database error" });
        res.status(201).json({ client: { ...rows[0], invoice_count:0 } });
      });
    }
  );
});

app.put("/api/clients/:id", verifyToken, [
  body("name").trim().notEmpty().withMessage("Client name is required").isLength({ max:100 }),
  body("email").optional({ checkFalsy:true }).isEmail().normalizeEmail(),
], (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { name, email="", phone="", company="", address="" } = req.body;
  db.query("UPDATE clients SET name=?,email=?,phone=?,company=?,address=? WHERE id=? AND user_id=?",
    [name, email, phone, company, address, req.params.id, req.user.id], (err, result) => {
      if (err) return res.status(500).json({ error:"Database error" });
      if (!result.affectedRows) return res.status(404).json({ error:"Client not found" });
      db.query(
        "SELECT c.*, COUNT(i.id) as invoice_count FROM clients c LEFT JOIN invoices i ON i.client_id=c.id WHERE c.id=? GROUP BY c.id",
        [req.params.id], (err, rows) => {
          if (err) return res.status(500).json({ error:"Database error" });
          res.json({ client: rows[0] });
        }
      );
    }
  );
});

app.delete("/api/clients/:id", verifyToken, (req, res) => {
  db.query("DELETE FROM clients WHERE id=? AND user_id=?", [req.params.id, req.user.id], (err, result) => {
    if (err) return res.status(500).json({ error:"Database error" });
    if (!result.affectedRows) return res.status(404).json({ error:"Client not found" });
    res.json({ message:"Client deleted" });
  });
});

// ─────────────────────────────────────────────────────
// INVOICES ROUTES
// ─────────────────────────────────────────────────────

app.get("/api/invoices", verifyToken, (req, res) => {
  db.query(
    `SELECT i.*, c.name as client_name, c.company as client_company, c.email as client_email
     FROM invoices i JOIN clients c ON c.id = i.client_id
     WHERE i.user_id = ? ORDER BY i.created_at DESC`,
    [req.user.id], (err, rows) => {
      if (err) return res.status(500).json({ error:"Database error" });
      if (!rows.length) return res.json({ invoices:[] });
      const ids = rows.map(r => r.id);
      db.query("SELECT * FROM invoice_items WHERE invoice_id IN (?)", [ids], (err, items) => {
        if (err) return res.status(500).json({ error:"Database error" });
        res.json({ invoices: rows.map(inv => ({ ...inv, items: items.filter(it => it.invoice_id === inv.id) })) });
      });
    }
  );
});

app.post("/api/invoices", verifyToken, [
  body("client_id").notEmpty().withMessage("Client is required"),
  body("issue_date").notEmpty().withMessage("Issue date is required"),
  body("due_date").notEmpty().withMessage("Due date is required"),
  body("items").isArray({ min:1 }).withMessage("At least one item is required"),
], (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });

  db.query("SELECT id FROM clients WHERE id=? AND user_id=?", [req.body.client_id, req.user.id], (err, rows) => {
    if (err || !rows.length) return res.status(400).json({ error:"Invalid client" });

    db.query("SELECT COUNT(*) as cnt FROM invoices WHERE user_id=?", [req.user.id], (err, countRows) => {
      if (err) return res.status(500).json({ error:"Database error" });
      const invNum = `INV-${String(countRows[0].cnt + 1).padStart(3, "0")}`;
      const { client_id, issue_date, due_date, notes="", tax_rate=0, status="draft", subtotal=0, tax_amount=0, total=0, items } = req.body;

      db.query(
        "INSERT INTO invoices (user_id,client_id,invoice_number,status,issue_date,due_date,notes,subtotal,tax_rate,tax_amount,total) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [req.user.id, client_id, invNum, status, issue_date, due_date, notes, subtotal, tax_rate, tax_amount, total],
        (err, result) => {
          if (err) return res.status(500).json({ error:"Failed to create invoice" });
          const invoiceId = result.insertId;
          const itemRows  = items.filter(it => it.description?.trim()).map(it => [
            invoiceId, it.description,
            parseFloat(it.quantity)||1, parseFloat(it.unit_price)||0,
            (parseFloat(it.quantity)||1) * (parseFloat(it.unit_price)||0)
          ]);
          if (!itemRows.length) return res.status(400).json({ error:"Add at least one item with a description" });
          db.query("INSERT INTO invoice_items (invoice_id,description,quantity,unit_price,total) VALUES ?", [itemRows], (err) => {
            if (err) return res.status(500).json({ error:"Failed to save items" });
            db.query(
              "SELECT i.*, c.name as client_name, c.company as client_company FROM invoices i JOIN clients c ON c.id=i.client_id WHERE i.id=?",
              [invoiceId], (err, invRows) => {
                db.query("SELECT * FROM invoice_items WHERE invoice_id=?", [invoiceId], (err, savedItems) => {
                  res.status(201).json({ invoice: { ...invRows[0], items: savedItems } });
                });
              }
            );
          });
        }
      );
    });
  });
});

app.put("/api/invoices/:id", verifyToken, [
  body("client_id").notEmpty(),
  body("items").isArray({ min:1 }),
], (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { client_id, issue_date, due_date, notes="", tax_rate=0, status="draft", subtotal=0, tax_amount=0, total=0, items } = req.body;
  db.query(
    "UPDATE invoices SET client_id=?,issue_date=?,due_date=?,notes=?,tax_rate=?,status=?,subtotal=?,tax_amount=?,total=? WHERE id=? AND user_id=?",
    [client_id, issue_date, due_date, notes, tax_rate, status, subtotal, tax_amount, total, req.params.id, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ error:"Database error" });
      if (!result.affectedRows) return res.status(404).json({ error:"Invoice not found" });
      db.query("DELETE FROM invoice_items WHERE invoice_id=?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ error:"Database error" });
        const itemRows = items.filter(it => it.description?.trim()).map(it => [
          req.params.id, it.description,
          parseFloat(it.quantity)||1, parseFloat(it.unit_price)||0,
          (parseFloat(it.quantity)||1) * (parseFloat(it.unit_price)||0)
        ]);
        db.query("INSERT INTO invoice_items (invoice_id,description,quantity,unit_price,total) VALUES ?", [itemRows], (err) => {
          if (err) return res.status(500).json({ error:"Failed to save items" });
          db.query(
            "SELECT i.*, c.name as client_name, c.company as client_company FROM invoices i JOIN clients c ON c.id=i.client_id WHERE i.id=?",
            [req.params.id], (err, invRows) => {
              db.query("SELECT * FROM invoice_items WHERE invoice_id=?", [req.params.id], (err, savedItems) => {
                res.json({ invoice: { ...invRows[0], items: savedItems } });
              });
            }
          );
        });
      });
    }
  );
});

app.put("/api/invoices/:id/status", verifyToken, [
  body("status").isIn(["draft","sent","paid","overdue"]).withMessage("Invalid status"),
], (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { status } = req.body;
  db.query(
    "UPDATE invoices SET status=?,paid_at=? WHERE id=? AND user_id=?",
    [status, status==="paid"?new Date():null, req.params.id, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ error:"Database error" });
      if (!result.affectedRows) return res.status(404).json({ error:"Invoice not found" });
      db.query(
        "SELECT i.*, c.name as client_name, c.company as client_company FROM invoices i JOIN clients c ON c.id=i.client_id WHERE i.id=?",
        [req.params.id], (err, invRows) => {
          db.query("SELECT * FROM invoice_items WHERE invoice_id=?", [req.params.id], (err, savedItems) => {
            res.json({ invoice: { ...invRows[0], items: savedItems } });
          });
        }
      );
    }
  );
});

app.delete("/api/invoices/:id", verifyToken, (req, res) => {
  db.query("DELETE FROM invoices WHERE id=? AND user_id=?", [req.params.id, req.user.id], (err, result) => {
    if (err) return res.status(500).json({ error:"Database error" });
    if (!result.affectedRows) return res.status(404).json({ error:"Invoice not found" });
    res.json({ message:"Invoice deleted" });
  });
});


// ─────────────────────────────────────────────────────
// SETTINGS ROUTES
// ─────────────────────────────────────────────────────

// Ensure business_profiles table exists
db.getConnection((err, conn) => {
  if (err) return;
  conn.query(`CREATE TABLE IF NOT EXISTS business_profiles (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NOT NULL UNIQUE,
    business_name VARCHAR(150) DEFAULT '',
    address       VARCHAR(255) DEFAULT '',
    phone         VARCHAR(50)  DEFAULT '',
    email         VARCHAR(150) DEFAULT '',
    website       VARCHAR(255) DEFAULT '',
    tax_id        VARCHAR(100) DEFAULT '',
    currency      VARCHAR(10)  DEFAULT 'USD',
    invoice_notes TEXT,
    logo_url      VARCHAR(500) DEFAULT '',
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`, err => { if (err) console.error("Business profiles table error:", err.message); else console.log("✅ Business profiles table ready!"); });
  conn.release();
});

app.get("/api/settings", verifyToken, (req, res) => {
  db.query("SELECT * FROM business_profiles WHERE user_id=?", [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error:"Database error" });
    res.json({ business: rows[0] || null });
  });
});

app.put("/api/settings/profile", verifyToken, [
  body("full_name").trim().notEmpty().withMessage("Name is required").isLength({ max:100 }),
  body("email").trim().notEmpty().isEmail().normalizeEmail().withMessage("Valid email required"),
], (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { full_name, email } = req.body;
  db.query("UPDATE users SET full_name=?,email=? WHERE id=?", [full_name, email, req.user.id], (err) => {
    if (err) return res.status(500).json({ error:"Database error" });
    res.json({ user:{ id:req.user.id, full_name, email } });
  });
});

app.put("/api/settings/business", verifyToken, (req, res) => {
  const { business_name="", address="", phone="", email="", website="", tax_id="", currency="USD", invoice_notes="", logo_url="" } = req.body;
  db.query(
    `INSERT INTO business_profiles (user_id,business_name,address,phone,email,website,tax_id,currency,invoice_notes,logo_url)
     VALUES (?,?,?,?,?,?,?,?,?,?)
     ON DUPLICATE KEY UPDATE business_name=VALUES(business_name),address=VALUES(address),phone=VALUES(phone),
     email=VALUES(email),website=VALUES(website),tax_id=VALUES(tax_id),currency=VALUES(currency),
     invoice_notes=VALUES(invoice_notes),logo_url=VALUES(logo_url)`,
    [req.user.id, business_name, address, phone, email, website, tax_id, currency, invoice_notes, logo_url],
    (err) => {
      if (err) return res.status(500).json({ error:"Database error" });
      db.query("SELECT * FROM business_profiles WHERE user_id=?", [req.user.id], (err, rows) => {
        res.json({ business: rows[0] });
      });
    }
  );
});

app.put("/api/settings/password", verifyToken, [
  body("current_password").notEmpty().withMessage("Current password required"),
  body("new_password").notEmpty().isLength({ min:8 }).matches(/[A-Z]/).matches(/[0-9]/).withMessage("Password too weak"),
], async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ error: errs.array()[0].msg });
  const { current_password, new_password } = req.body;
  db.query("SELECT password FROM users WHERE id=?", [req.user.id], async (err, rows) => {
    if (err || !rows.length) return res.status(500).json({ error:"Database error" });
    if (!rows[0].password) return res.status(400).json({ error:"Google accounts cannot set a password here." });
    const match = await bcrypt.compare(current_password, rows[0].password);
    if (!match) return res.status(401).json({ error:"Current password is incorrect." });
    const hashed = await bcrypt.hash(new_password, 12);
    db.query("UPDATE users SET password=? WHERE id=?", [hashed, req.user.id], (err) => {
      if (err) return res.status(500).json({ error:"Database error" });
      res.json({ message:"Password updated!" });
    });
  });
});

// ─────────────────────────────────────────────────────
// DASHBOARD STATS ROUTE
// ─────────────────────────────────────────────────────

app.get("/api/stats", verifyToken, (req, res) => {
  const uid = req.user.id;
  const now = new Date().toISOString().slice(0,7); // YYYY-MM

  db.query(`
    SELECT
      COALESCE(SUM(CASE WHEN status='paid' THEN total ELSE 0 END), 0)                                      AS total_earned,
      COALESCE(SUM(CASE WHEN status IN ('sent','overdue') THEN total ELSE 0 END), 0)                        AS total_pending,
      COALESCE(SUM(CASE WHEN status='overdue' THEN total ELSE 0 END), 0)                                    AS total_overdue,
      COALESCE(SUM(CASE WHEN status='paid' AND DATE_FORMAT(paid_at,'%Y-%m')=? THEN total ELSE 0 END), 0)    AS paid_this_month,
      COUNT(*)                                                                                               AS total_invoices,
      COUNT(CASE WHEN status='draft'   THEN 1 END)                                                          AS draft_count,
      COUNT(CASE WHEN status='sent'    THEN 1 END)                                                          AS sent_count,
      COUNT(CASE WHEN status='paid'    THEN 1 END)                                                          AS paid_count,
      COUNT(CASE WHEN status='overdue' THEN 1 END)                                                          AS overdue_count
    FROM invoices WHERE user_id=?
  `, [now, uid], (err, rows) => {
    if (err) return res.status(500).json({ error:"Database error" });
    db.query("SELECT COUNT(*) as client_count FROM clients WHERE user_id=?", [uid], (err, cRows) => {
      res.json({ stats: { ...rows[0], client_count: cRows?.[0]?.client_count || 0 } });
    });
  });
});


// ─────────────────────────────────────────────────────
// 404 & ERROR HANDLER — MUST BE LAST
// ─────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error:"Route not found" }));
app.use((err, req, res, next) => { console.error("Error:", err.message); res.status(500).json({ error:"Something went wrong." }); });

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Invoify backend running on http://localhost:${PORT}`);
  console.log(`🔒 Auth ✅ | Clients ✅ | Invoices ✅ | Security ✅`);
});
