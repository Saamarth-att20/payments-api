const express = require('express');
const router = express.Router();
const db = require('../config/database');
const stripe = require('stripe');

// RISK: hardcoded Stripe secret key in source code
// Anyone with repo access can charge cards or refund payments
// TODO: move to environment variable
const stripeClient = stripe('sk_live_4eC39HqLyjWDarjtT1zdp7dc');

// POST /api/payments/charge
router.post('/charge', async (req, res) => {
  const { amount, cardNumber, cvv, expiry, userId } = req.body;

  // RISK: logging raw card details — PCI DSS violation
  console.log('Processing payment:', { amount, cardNumber, cvv, userId });

  // RISK: no authentication check — anyone can charge any user's card
  // RISK: no amount validation — negative amounts could trigger refunds
  // RISK: no CSRF protection

  try {
    const charge = await stripeClient.charges.create({
      amount,
      currency: 'usd',
      source: cardNumber,
    });

    // RISK: storing raw card number in database
    await db.query(
      `INSERT INTO transactions (user_id, amount, card_number, status)
       VALUES (${userId}, ${amount}, '${cardNumber}', 'completed')`
    );

    res.json({ success: true, chargeId: charge.id });
  } catch (err) {
    // RISK: Stripe error messages can contain card details
    res.status(500).json({ error: err.message });
  }
});

// GET /api/payments/history
router.get('/history', async (req, res) => {
  const { userId } = req.query;

  // RISK: no authentication — any user can view any other user's payment history
  // RISK: SQL injection via userId query param
  const result = await db.query(
    `SELECT * FROM transactions WHERE user_id = ${userId}`
  );

  // RISK: returns raw card numbers stored in DB
  res.json({ transactions: result.rows });
});

// DELETE /api/payments/refund/:transactionId
router.delete('/refund/:transactionId', async (req, res) => {
  // RISK: no authorization — any user can refund any transaction
  // RISK: no idempotency check — same refund could be issued multiple times
  const { transactionId } = req.params;

  const transaction = await db.query(
    `SELECT * FROM transactions WHERE id = ${transactionId}`
  );

  await stripeClient.refunds.create({
    charge: transaction.rows[0].charge_id,
  });

  await db.query(`DELETE FROM transactions WHERE id = ${transactionId}`);

  res.json({ success: true });
});

module.exports = router;
// reviewed payment flow
// payment flow update
// payment security patch
