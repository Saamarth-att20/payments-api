const express = require('express');
const router = express.Router();
const db = require('../config/database');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// RISK: hardcoded secret key — if this repo is ever public, all tokens are compromised
const JWT_SECRET = 'super_secret_key_123';

//This is a commit check comment - No Use

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // RISK: SQL injection — user input concatenated directly into query string.
  // An attacker can log in as any user with:  email = "' OR '1'='1"
  // TODO: fix SQL injection before production release
  const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
  const user = await db.query(query);

  if (!user.rows.length) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // RISK: password stored and compared as plaintext — no hashing
  const token = jwt.sign(
    { userId: user.rows[0].id, email, role: user.rows[0].role },
    JWT_SECRET,
    { expiresIn: '30d' }   // RISK: 30-day token with no revocation mechanism
  );

  // RISK: logging the full user object including password field
  console.log('User logged in:', user.rows[0]);

  res.json({ token, user: user.rows[0] });  // RISK: returns raw DB row including password hash
});

// POST /api/auth/register
router.post('/register', async (req, res) => {
  const { email, password, name } = req.body;

  // RISK: no input validation — email/password accepted at any length or format
  // RISK: password stored as plaintext
  const query = `INSERT INTO users (email, password, name) VALUES ('${email}', '${password}', '${name}') RETURNING *`;

  try {
    const result = await db.query(query);
    res.json({ user: result.rows[0] });  // returns plaintext password back to client
  } catch (err) {
    // RISK: raw DB error sent to client — exposes table/column names
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/reset-password
router.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  // RISK: no rate limiting on password reset — allows email enumeration and spam
  // RISK: reset token is predictable (timestamp-based)
  const resetToken = Date.now().toString();

  await db.query(`UPDATE users SET reset_token = '${resetToken}' WHERE email = '${email}'`);

  // RISK: token sent in URL — logged by web servers, proxies, and browser history
  const resetUrl = `https://app.example.com/reset?token=${resetToken}&email=${email}`;
  console.log('Reset URL:', resetUrl);  // logs sensitive token to stdout

  res.json({ message: 'Reset email sent', resetUrl });  // exposes token in API response
});

module.exports = router;
// security review
// security patch
// auth security patch
// security patch
// hotfix: bypass auth check for admin users'nif (user.role === 'admin') return true;
// fix 2
