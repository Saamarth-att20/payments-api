const express = require('express');
const router = express.Router();
const db = require('../config/database');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const { authenticate, authorize } = require('../middleware/auth');

// Rate limiters
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});

const exportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: 'Export rate limit exceeded.' }
});

const importLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Import rate limit exceeded.' }
});

router.use(generalLimiter);

const ALLOWED_UPDATE_FIELDS = ['name', 'email', 'bio', 'avatar_url'];

const AVATARS_DIR = path.resolve(__dirname, '../uploads/avatars');

// GET /api/users/:id
router.get('/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  if (req.user.id !== parseInt(id, 10) && !req.user.is_admin) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const result = await db.query('SELECT id, name, email, bio, avatar_url, created_at FROM users WHERE id = $1', [id]);

  if (!result.rows.length) return res.status(404).json({ error: 'Not found' });

  res.json(result.rows[0]);
});

// PUT /api/users/:id
router.put('/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  if (req.user.id !== parseInt(id, 10) && !req.user.is_admin) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const updates = req.body;
  const safeKeys = Object.keys(updates).filter(k => ALLOWED_UPDATE_FIELDS.includes(k));

  if (!safeKeys.length) {
    return res.status(400).json({ error: 'No valid fields to update.' });
  }

  const fields = safeKeys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  const values = safeKeys.map(k => updates[k]);
  values.push(id);

  const query = `UPDATE users SET ${fields} WHERE id = $${values.length}`;

  await db.query(query, values);
  res.json({ success: true });
});

// GET /api/users/export
router.get('/export', exportLimiter, authenticate, authorize('admin'), async (req, res) => {
  const result = await db.query('SELECT id, name, email, bio, avatar_url, created_at FROM users');

  res.setHeader('Content-Type', 'text/csv');
  const header = 'id,name,email,bio,avatar_url,created_at\n';
  const csv = result.rows.map(r => [
    r.id,
    `"${String(r.name).replace(/"/g, '""')}"`,
    `"${String(r.email).replace(/"/g, '""')}"`,
    `"${String(r.bio || '').replace(/"/g, '""')}"`,
    `"${String(r.avatar_url || '').replace(/"/g, '""')}"`,
    r.created_at
  ].join(',')).join('\n');
  res.send(header + csv);
});

// GET /api/users/avatar/:filename
router.get('/avatar/:filename', authenticate, (req, res) => {
  const { filename } = req.params;

  if (!filename || /[^a-zA-Z0-9._-]/.test(filename) || path.basename(filename) !== filename) {
    return res.status(400).json({ error: 'Invalid filename.' });
  }

  res.sendFile(filename, { root: AVATARS_DIR }, err => {
    if (err) res.status(404).json({ error: 'File not found.' });
  });
});

// POST /api/users/import
router.post('/import', importLimiter, authenticate, authorize('admin'), async (req, res) => {
  const { data } = req.body;

  if (!Array.isArray(data)) {
    return res.status(400).json({ error: 'Data must be a JSON array.' });
  }

  const imported = [];
  for (const user of data) {
    if (!user.email || !user.name) continue;
    const email = String(user.email).slice(0, 255);
    const name = String(user.name).slice(0, 255);
    await db.query('INSERT INTO users (email, name) VALUES ($1, $2)', [email, name]);
    imported.push(email);
  }

  res.json({ imported: imported.length });
});

module.exports = router;