console.log("✅✅✅ RUNNING THE LATEST SERVER.JS FILE (OpenAI Ready & FINAL RESPONSE FORMAT FIX) ✅✅✅");
console.log("👉 Running THIS server.js from smart3/smart/server");

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');
const { setupWSConnection } = require('y-websocket/bin/utils');
// 👇 استيراد مكتبة الإيميلات
const nodemailer = require('nodemailer');
require('dotenv').config();

// (ملفات الـ middleware... لم تتغير)
const {
  requireScheduler,
  requireCommitteeRole,
  requireFaculty,
  requireStaff,
  requireStudent,
  requireOwnData,
  requireOwnDataOrStaff,
  verifyCommitteePassword
} = require('./middleware/auth');

const {
  validateUserRegistration,
  validateStudentRegistration,
  validateLogin,
  validateStudentUpdate,
  validateCourseCreation,
  validateComment,
  validateVote,
  validateScheduleVersion,
  validateRule,
  validateIdParam
} = require('./middleware/validation');

const app = express();
const server = http.createServer(app);
const COLLAB_NAMESPACE = 'collaboration';
const wss = new WebSocket.Server({ server });

// 👇 run backend on 5000
const PORT = process.env.PORT || 5000;

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

// ✅✅✅ التعديل المطلوب: تحديث قائمة CORS بالرابط الصحيح 
app.use(
  cors({
    origin: [
      'http://localhost:3000',
      'https://smart-uf30.onrender.com', // رابط السيرفر على Render
      'https://lighthearted-speculoos-572bb2.netlify.app' // ✅ الرابط الجديد والحقيقي من المتصفح
    ],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// (إعداد خدمة البريد الإلكتروني... لم تتغير)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, 
    pass: process.env.EMAIL_PASS  
  }
});

wss.on('connection', (ws, req) => {
  const pathName = (req.url || '').split('?')[0];
  const segments = pathName.split('/').filter(Boolean);
  if (segments[0] !== COLLAB_NAMESPACE) {
    ws.close(1008, 'Unknown collaboration namespace');
    return;
  }
  const docName = segments[1] || 'shared-rules';
  console.log(`[collaboration] client connected to room: ${docName}`);
  setupWSConnection(ws, req, { docName, gc: true });
});

wss.on('error', (err) => {
  console.error('[collaboration] websocket error:', err);
});

// PostgreSQL Connection Pool - (تم التعديل لاستخدام DATABASE_URL و SSL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // ✅ استخدام URI بالكامل
  ssl: {
    rejectUnauthorized: false // ✅ إعداد حاسم للاتصال بـ Supabase من Render
  },
  keepAlive: true,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 20000,
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Error connecting to PostgreSQL database:', err.stack);
  } else {
    console.log('✅ Successfully connected to PostgreSQL database');
    release();
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next(0);
  });
};

async function runMigrations() {
  // (كود الهجرة... لم يتغير)
  const dir = path.join(__dirname, 'migrations');
  try {
    if (!fs.existsSync(dir)) return;
    const files = fs.readdirSync(dir).filter(f => f.toLowerCase().endsWith('.sql')).sort();
    if (files.length === 0) return;
    const client = await pool.connect();
    try {
      for (const f of files) {
        const full = path.join(dir, f);
        const sql = fs.readFileSync(full, 'utf8');
        await client.query(sql);
      }
      console.log('[migrate] Completed');
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('[migrate] Migration error:', e);
  }
}

runMigrations().catch(() => { });

// (بقية المسارات... لم تتغير)

// ============================================
// AUTHENTICATION ROUTES
// ============================================

app.post('/api/auth/login', validateLogin, async (req, res) => {
  // (كود تسجيل الدخول... لم يتغير)
  const client = await pool.connect();
  try {
    const { email, password } = req.validatedData;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const query = `SELECT u.user_id, u.name, u.email, u.password, u.role, s.student_id, s.level, s.is_ir FROM users u LEFT JOIN students s ON u.user_id = s.user_id WHERE u.email = $1`;
    const result = await client.query(query, [email]);

    if (result.rows.length === 0) return res.status(401).json({ error: 'Incorrect credentials' });
    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Incorrect credentials' });

    if (user.role === 'student') {
      let studentId = user.student_id;
      let level = user.level;
      let is_ir = user.is_ir;

      if (!studentId) {
        const studentResult = await client.query('SELECT student_id, level, is_ir FROM students WHERE user_id = $1', [user.user_id]);
        if (studentResult.rowCount > 0) {
          studentId = studentResult.rows[0].student_id;
          level = studentResult.rows[0].level;
          is_ir = studentResult.rows[0].is_ir;
        }
      }
      const token = jwt.sign({ id: studentId, user_id: user.user_id, email: user.email, type: 'student' }, process.env.JWT_SECRET, { expiresIn: '24h' });
      return res.json({ token, user: { id: studentId, user_id: user.user_id, email: user.email, name: user.name, level, is_ir, type: 'student', role: 'student' } });
    }

    const token = jwt.sign({ id: user.user_id, email: user.email, role: user.role, type: 'user' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token, user: { id: user.user_id, email: user.email, name: user.name, role: user.role, type: 'user' } });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// ✅ (جديد) مسار طلب إعادة تعيين كلمة المرور
app.post('/api/auth/forgot-password', async (req, res) => {
  // (كود forgot-password... لم يتغير)
  const client = await pool.connect();
  try {
    const { email } = req.body;
    const userCheck = await client.query('SELECT * FROM users WHERE email = $1', [email]);

    if (userCheck.rows.length === 0) {
      return res.json({ message: 'If an account exists, reset instructions have been sent.' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const expireDate = new Date(Date.now() + 3600000); // 1 hour

    await client.query('UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3', [resetToken, expireDate, email]);

    // 👇 رابط الصفحة في Netlify
    const resetLink = `https://lighthearted-speculoos-572bb2.netlify.app/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'SmartSchedule - Reset Password',
      html: `<p>You requested a password reset.</p><p>Click here to reset: <a href="${resetLink}">Reset Password</a></p>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Email sent successfully' });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).json({ error: 'Failed to send email' });
  } finally {
    client.release();
  }
});

// (بقية المسارات... لم تتغير)

app.post('/api/auth/reset-password', async (req, res) => {
  // (كود reset password لم يتغير)
  const client = await pool.connect();
  try {
    const { token, newPassword } = req.body;
    const result = await client.query('SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()', [token]);

    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired token' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await client.query('UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE user_id = $2', [hashedPassword, result.rows[0].user_id]);

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset Password Error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/register-user', validateUserRegistration, async (req, res) => {
  // (كود register user لم يتغير)
  const client = await pool.connect();
  try {
    const { email, password, name, role } = req.validatedData;
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4) RETURNING user_id, email, name, role`;
    const result = await client.query(query, [email, hashedPassword, name, role]);
    res.json({ success: true, message: 'User added successfully!', user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') res.status(400).json({ error: 'Email already exists' });
    else res.status(500).json({ error: 'Error creating user' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/register-student', validateStudentRegistration, async (req, res) => {
  // (كود register student لم يتغير)
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { email, password, name, level, is_ir } = req.validatedData;
    const hashedPassword = await bcrypt.hash(password, 10);
    const userQuery = `INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, 'student') RETURNING user_id`;
    const userResult = await client.query(userQuery, [email, hashedPassword, name]);
    const userId = userResult.rows[0].user_id;
    const studentQuery = `INSERT INTO students (user_id, level, is_ir) VALUES ($1, $2, $3) RETURNING student_id`;
    const studentResult = await client.query(studentQuery, [userId, level, is_ir || false]);
    await client.query('COMMIT');
    res.json({ success: true, message: 'Student added successfully!', studentId: studentResult.rows[0].student_id, userId });
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') res.status(400).json({ error: 'Email already exists' });
    else res.status(500).json({ error: 'Error creating student' });
  } finally {
    client.release();
  }
});

// (بقية المسارات... لم تتغير)

// Utils
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK-V2', timestamp: new Date().toISOString() });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'خطأ داخلي في الخادم' });
});

server.listen(PORT, () => {
  console.log(`dYs? SmartSchedule Server running on port ${PORT}`);
  console.log(`dY"S Connected to PostgreSQL database: ${process.env.DATABASE_URL}`);
  console.log(`[collaboration] WebSocket namespace ready at ws://localhost:${PORT}/${COLLAB_NAMESPACE}/:roomId`);
});

let shuttingDown = false;
const gracefulShutdown = () => {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('dY>` Shutting down server (HTTP + collaboration WS)...');
  wss.clients.forEach((client) => {
    try { client.terminate(); } catch { }
  });
  wss.close(() => console.log('[collaboration] websocket server closed'));
  server.close(() => {
    console.log('HTTP server closed');
    pool.end(() => {
      console.log('Database pool closed');
      process.exit(0);
    });
  });
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
