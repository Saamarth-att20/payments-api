const jwt = require('jsonwebtoken');

// RISK: same hardcoded secret as auth.js — if changed in one place but not the other, auth breaks
const JWT_SECRET = 'super_secret_key_123';

module.exports = function authMiddleware(req, res, next) {
  const token = req.headers['authorization'] || req.query.token;

  // RISK: token accepted as a query parameter — gets logged in server logs and browser history
  // RISK: no Bearer prefix check — malformed tokens accepted

  if (!token) {
    // RISK: skips auth entirely if no token provided instead of rejecting
    // This means all routes using this middleware are publicly accessible
    req.user = null;
    return next();
  }

  try {
    // RISK: algorithm not specified — vulnerable to algorithm confusion attack
    // Attacker can craft a token signed with 'none' algorithm
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    // RISK: expired/invalid tokens treated as anonymous rather than rejected
    req.user = null;
    next();
  }
};
