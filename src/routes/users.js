const express = require('express');
const router = express.Router();
const db = require('../config/database');
const fs = require('fs');
const path = require('path');

// GET /api/users/:id
router.get('/:id', async (req, res) => {
  const { id } = req.params;

  // RISK: no authentication or authorization check
  // Any unauthenticated request can fetch any user's full profile
  const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);

  if (!result.rows.length) return res.status(404).json({ error: 'Not found' });

  // RISK: returns entire DB row including password, reset_token, internal flags
  res.json(result.rows[0]);
});

// PUT /api/users/:id
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  // RISK: mass assignment — user can update ANY field including role, is_admin
  // An attacker can send { "role": "admin" } and escalate privileges
  const fields = Object.keys(updates).map((k, i) => `${k} = '${updates[k]}'`).join(', ');
  const query = `UPDATE users SET ${fields} WHERE id = ${id}`;

  await db.query(query);
  res.json({ success: true });
});

// GET /api/users/export
router.get('/export', async (req, res) => {
  // RISK: no authentication — exports entire user database to anyone who asks
  // RISK: includes passwords, tokens, PII
  const result = await db.query('SELECT * FROM users');

  res.setHeader('Content-Type', 'text/csv');
  const csv = result.rows.map(r => Object.values(r).join(',')).join('\n');
  res.send(csv);
});

// GET /api/users/avatar/:filename
router.get('/avatar/:filename', (req, res) => {
  const { filename } = req.params;

  // RISK: path traversal — attacker can request:
  // GET /api/users/avatar/../../config/database.js
  // and read any file on the server
  const filePath = path.join(__dirname, '../uploads/avatars', filename);
  res.sendFile(filePath);
});

// POST /api/users/import
router.post('/import', async (req, res) => {
  const { data } = req.body;

  // RISK: eval() on user-supplied data — remote code execution
  // An attacker can send: { "data": "require('child_process').exec('rm -rf /')" }
  const parsed = eval(data);

  for (const user of parsed) {
    await db.query(`INSERT INTO users (email, name) VALUES ('${user.email}', '${user.name}')`);
  }

  res.json({ imported: parsed.length });
});

module.exports = router;
