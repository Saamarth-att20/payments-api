const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');

// Authentication middleware — all admin routes require a valid admin session
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user || req.session.user.role !== 'admin') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Apply admin auth to every route in this router
router.use(requireAdmin);

// GET /api/admin/users
router.get('/users', async (req, res) => {
  try {
    const { search } = req.query;
    // Use parameterized query to prevent SQL injection
    const result = await db.query(
      'SELECT id, name, email, role, created_at FROM users WHERE name ILIKE $1 OR email ILIKE $1',
      [`%${search}%`]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Allowlist of permitted report names
const ALLOWED_REPORTS = new Set(['sales', 'inventory', 'users', 'revenue']);

// Resolved allowlist of permitted report script paths
const REPORTS_DIR = path.resolve(__dirname, '../reports');

// POST /api/admin/run-report
router.post('/run-report', (req, res) => {
  const { reportName } = req.body;

  // Validate reportName against an allowlist to prevent command injection
  if (!reportName || !ALLOWED_REPORTS.has(reportName)) {
    return res.status(400).json({ error: 'Invalid report name' });
  }

  // Resolve script path and verify it stays within the reports directory
  const scriptPath = path.resolve(REPORTS_DIR, `${reportName}.js`);
  if (!scriptPath.startsWith(REPORTS_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid report path' });
  }

  // Verify the script file actually exists before executing
  if (!fs.existsSync(scriptPath)) {
    return res.status(404).json({ error: 'Report script not found' });
  }

  // Use execFile instead of exec — arguments are passed as an array, not interpreted by a shell
  execFile('node', [scriptPath], { timeout: 30000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: 'Report execution failed' });
    res.json({ output: stdout });
  });
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    // Soft-delete: set deleted_at timestamp instead of hard delete
    // Parameterized query prevents SQL injection
    const result = await db.query(
      'UPDATE users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING id',
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Audit log
    await db.query(
      'INSERT INTO audit_log (action, target_id, performed_by, created_at) VALUES ($1, $2, $3, NOW())',
      ['delete_user', id, req.session.user.id]
    );

    res.json({ deleted: true, id });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Allowlist of permitted backup destinations (directories only)
const ALLOWED_BACKUP_DIR = path.resolve(__dirname, '../../backups');

// POST /api/admin/backup
router.post('/backup', (req, res) => {
  const { filename } = req.body;

  // Validate filename — alphanumeric, hyphens, underscores only; no path traversal
  if (!filename || !/^[a-zA-Z0-9_-]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  // Resolve destination inside allowed directory and verify no traversal occurred
  const destination = path.resolve(ALLOWED_BACKUP_DIR, `${filename}.dump`);
  if (!destination.startsWith(ALLOWED_BACKUP_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid destination path' });
  }

  // Ensure backup directory exists
  fs.mkdirSync(ALLOWED_BACKUP_DIR, { recursive: true });

  // Use execFile with explicit arguments — no shell interpolation, no path injection
  // pg_dump is called with --no-password; credentials should be in .pgpass or env vars
  execFile('pg_dump', ['--format=custom', '--file', destination, 'mydb'], { timeout: 120000 }, (err) => {
    if (err) return res.status(500).json({ error: 'Backup failed' });
    res.json({ success: true, savedTo: destination });
  });
});

module.exports = router;
