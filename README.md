# payments-api

Internal payment processing API for handling charges, refunds, and user accounts.

## Stack
- Node.js / Express
- PostgreSQL
- Stripe

## Setup
```
npm install
npm run dev
```

## Endpoints
- `POST /api/auth/login`
- `POST /api/auth/register`
- `POST /api/payments/charge`
- `GET  /api/payments/history`
- `GET  /api/users/:id`
- `GET  /api/admin/users`
