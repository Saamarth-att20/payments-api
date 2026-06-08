const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const db = require('./config/database');

const app = express();

// RISK: cors() with no config allows ALL origins — any website can call this API
app.use(cors());
app.use(express.json());
// RISK: morgan 'combined' logs full request URLs including query params
// which will log auth tokens passed as ?token= query params in plaintext
app.use(morgan('combined'));

app.use('/api/auth',     require('./routes/auth'));
app.use('/api/payments', require('./routes/payments'));
app.use('/api/users',    require('./routes/users'));
app.use('/api/admin',    require('./routes/admin'));

// RISK: global error handler sends full stack trace to client in production
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: err.message,
    stack: err.stack,         // exposes internal file paths and logic to attackers
    timestamp: new Date()
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));

module.exports = app;
