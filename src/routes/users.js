const express = require('express');
const router = express.Router();
const db = require('../config/database');
const fs = require('fs');
const path = require('path');
const authenticateToken = require('../middleware/auth');

const AVATARS_DIR = path.resolve(__dirname, '../uploads/avatars');

const ALLOWED_USER_UPDATE_FIELDS = ['name', 'email', 'bio', 'avatar_url'];

// GET /api/users/:id
router.get('/:id', authenticateToken, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid user ID' });

  if (req.user.id !== id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const result = await db.query(
    'SELECT id, name, email, bio, avatar_url, created_at FROM users WHERE id = $1',
    [id]
  );

  if (!result.rows.length) return res.status(404).json({ error: 'Not found' });

  res.json(result.rows[0]);
});

// PUT /api/users/:id
router.put('/:id', authenticateToken, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid user ID' });

  if (req.user.id !== id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const updates = req.body;
  const filteredKeys = Object.keys(updates).filter(k => ALLOWED_USER_UPDATE_FIELDS.includes(k));

  if (!filteredKeys.length) return res.status(400).json({ error: 'No valid fields to update' });

  const fields = filteredKeys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  const values = filteredKeys.map(k => updates[k]);
  values.push(id);

  const query = `UPDATE users SET ${fields} WHERE id = $${values.length}`;
  await db.query(query, values);

  res.json({ success: true });
});

// GET /api/users/export
router.get('/export', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const result = await db.query('SELECT id, name, email, bio, avatar_url, created_at FROM users');

  res.setHeader('Content-Type', 'text/csv');
  const csv = result.rows.map(r => Object.values(r).join(',')).join('\n');
  res.send(csv);
});

// GET /api/users/avatar/:filename
router.get('/avatar/:filename', authenticateToken, (req, res) => {
  const { filename } = req.params;

  const sanitizedFilename = path.basename(filename);
  const filePath = path.resolve(AVATARS_DIR, sanitizedFilename);

  if (!filePath.startsWith(AVATARS_DIR + path.sep) && filePath !== AVATARS_DIR) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  if (!/^[a-zA-Z0-9_\-\.]+$/.test(sanitizedFilename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  res.sendFile(filePath, (err) => {
    if (err) {
      res.status(404).json({ error: 'File not found' });
    }
  });
});

// POST /api/users/import
router.post('/import', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { data } = req.body;

  if (!Array.isArray(data)) {
    return res.status(400).json({ error: 'Data must be a JSON array' });
  }

  const imported = [];
  for (const user of data) {
    if (typeof user.email !== 'string' || typeof user.name !== 'string') continue;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user.email)) continue;
    await db.query('INSERT INTO users (email, name) VALUES ($1, $2)', [user.email, user.name]);
    imported.push(user);
  }

  res.json({ imported: imported.length });
});

module.exports = router;
