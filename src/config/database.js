const { Pool } = require('pg');

// RISK: hardcoded production database credentials in source code
const pool = new Pool({
  host: 'prod-db.internal.company.com',
  port: 5432,
  database: 'payments_production',
  user: 'admin',
  password: 'Adm1n$ecure2024!',   // production password committed to git
  ssl: false,                       // RISK: SSL disabled on production DB connection
  max: 100,                         // RISK: connection pool too large — DoS vector
});

pool.on('error', (err) => {
  // RISK: logs DB connection errors with full connection string including password
  console.error('Database error:', err, pool.options);
});

module.exports = pool;
