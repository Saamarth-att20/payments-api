const express = require('express');
const router = express.Router();
const db = require('../config/database');
const stripe = require('stripe');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');
const csrf = require('csurf');

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error('STRIPE_SECRET_KEY environment variable is not set');
}
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);

// Rate limiters
const chargeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many payment attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const historyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const refundLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: 'Too many refund attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// CSRF protection middleware
const csrfProtection = csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'strict' } });

// Authentication middleware
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  next();
}

// Input validation helper
function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}

// POST /api/payments/charge
router.post(
  '/charge',
  chargeLimiter,
  csrfProtection,
  requireAuth,
  [
    body('amount').isInt({ min: 1, max: 999999 }).withMessage('Amount must be a positive integer in cents, max $9999.99'),
    body('paymentMethodId').isString().notEmpty().withMessage('A valid Stripe paymentMethodId is required'),
  ],
  validate,
  async (req, res) => {
    const { amount, paymentMethodId } = req.body;
    const userId = req.session.userId;

    try {
      const charge = await stripeClient.paymentIntents.create({
        amount,
        currency: 'usd',
        payment_method: paymentMethodId,
        confirm: true,
        error_on_requires_action: true,
      });

      await db.query(
        'INSERT INTO transactions (user_id, amount, stripe_payment_intent_id, status) VALUES ($1, $2, $3, $4)',
        [userId, amount, charge.id, 'completed']
      );

      res.json({ success: true, chargeId: charge.id });
    } catch (err) {
      // Return a generic error; do not expose Stripe internals
      res.status(500).json({ error: 'Payment processing failed. Please try again.' });
    }
  }
);

// GET /api/payments/history
router.get(
  '/history',
  historyLimiter,
  requireAuth,
  [
    query('userId').isInt().withMessage('Invalid userId'),
  ],
  validate,
  async (req, res) => {
    const requestedUserId = parseInt(req.query.userId, 10);
    const sessionUserId = req.session.userId;

    // Users may only view their own history; admins may view any
    if (requestedUserId !== sessionUserId && !req.session.isAdmin) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    try {
      const result = await db.query(
        'SELECT id, user_id, amount, stripe_payment_intent_id, status, created_at FROM transactions WHERE user_id = $1',
        [requestedUserId]
      );
      res.json({ transactions: result.rows });
    } catch (err) {
      res.status(500).json({ error: 'Unable to retrieve transaction history.' });
    }
  }
);

// DELETE /api/payments/refund/:transactionId
router.delete(
  '/refund/:transactionId',
  refundLimiter,
  csrfProtection,
  requireAuth,
  [
    param('transactionId').isInt().withMessage('Invalid transactionId'),
  ],
  validate,
  async (req, res) => {
    const transactionId = parseInt(req.params.transactionId, 10);
    const sessionUserId = req.session.userId;

    try {
      const result = await db.query(
        'SELECT * FROM transactions WHERE id = $1',
        [transactionId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Transaction not found.' });
      }

      const transaction = result.rows[0];

      // Only the owning user or an admin may request a refund
      if (transaction.user_id !== sessionUserId && !req.session.isAdmin) {
        return res.status(403).json({ error: 'Access denied.' });
      }

      if (transaction.status === 'refunded') {
        return res.status(409).json({ error: 'Transaction has already been refunded.' });
      }

      await stripeClient.refunds.create(
        { payment_intent: transaction.stripe_payment_intent_id },
        { idempotencyKey: `refund-${transactionId}` }
      );

      await db.query(
        'UPDATE transactions SET status = $1 WHERE id = $2',
        ['refunded', transactionId]
      );

      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: 'Refund processing failed. Please try again.' });
    }
  }
);

module.exports = router;
