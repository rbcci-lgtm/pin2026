'use strict';

// ─── Dependencies ─────────────────────────────────────────────────────────────
require('dotenv').config();
const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const path       = require('path');
const rateLimit  = require('express-rate-limit');

// ─── App Initialisation ───────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ───────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
        scriptSrc:  ["'self'", "'unsafe-inline'"],   // inline scripts used in the HTML
        imgSrc:     ["'self'", 'data:'],
        connectSrc: ["'self'"],
      },
    },
  })
);

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',  // tighten in production
  methods: ['GET', 'POST'],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ─── Rate Limiting ────────────────────────────────────────────────────────────
// Global limiter — 100 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs : 15 * 60 * 1000,
  max      : 100,
  message  : { success: false, message: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders  : false,
});

// Tighter limiter for the registration endpoint
const registrationLimiter = rateLimit({
  windowMs : 60 * 60 * 1000,   // 1 hour
  max      : 10,                // max 10 submissions per IP per hour
  message  : { success: false, message: 'Too many registration attempts. Please try again in an hour.' },
  standardHeaders: true,
  legacyHeaders  : false,
});

app.use(globalLimiter);

// ─── Static Files ─────────────────────────────────────────────────────────────
// Serves the HTML form (and any future assets placed in /public)
app.use(express.static(path.join(__dirname, 'public')));

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * GET /
 * Serve the PIN registration form.
 */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'bank-pin-registration.html'));
});

/**
 * POST /api/register
 * Receives the completed registration payload from the front end.
 *
 * Expected JSON body:
 * {
 *   firstName     : string,
 *   lastName      : string,
 *   accountNumber : string,
 *   email         : string,
 *   accountType   : string,
 *   dob           : string,   // MM/DD/YYYY
 *   pin           : string    // 6-digit string (send over HTTPS only)
 * }
 *
 * NOTE: In a production system the PIN should be hashed (e.g. bcrypt) before
 * persistence and never logged.  The raw PIN is intentionally not logged here.
 */
app.post('/api/register', registrationLimiter, (req, res) => {
  const {
    firstName,
    lastName,
    accountNumber,
    email,
    accountType,
    dob,
    pin,
  } = req.body;

  // ── Validation ──────────────────────────────────────────────────────────────
  const errors = [];

  if (!firstName || !lastName) {
    errors.push('Full name is required.');
  }

  const cleanAccount = (accountNumber || '').replace(/[^0-9]/g, '');
  if (cleanAccount.length < 12) {
    errors.push('Account number must be at least 12 digits.');
  }

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.push('A valid email address is required.');
  }

  const validAccountTypes = [
    'savings',
    'checking',
    'time-deposit',
    'current',
  ];
  if (!accountType || !validAccountTypes.includes(accountType)) {
    errors.push('A valid account type is required.');
  }

  if (!dob) {
    errors.push('Date of birth is required.');
  }

  if (!pin || !/^\d{6}$/.test(pin)) {
    errors.push('PIN must be exactly 6 digits.');
  }

  if (errors.length > 0) {
    return res.status(422).json({ success: false, errors });
  }

  // ── Business logic placeholder ───────────────────────────────────────────────
  // Replace this block with your actual database / service calls.
  // Example: await db.saveRegistration({ firstName, lastName, cleanAccount, email, accountType, dob, hashedPin });
  console.log(`[${new Date().toISOString()}] New PIN registration — account: ${maskAccount(cleanAccount)}`);

  // ── Response ─────────────────────────────────────────────────────────────────
  return res.status(201).json({
    success  : true,
    message  : 'PIN registration completed successfully.',
    reference: generateReference(),
  });
});

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found.' });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Unhandled error:`, err.message);
  res.status(500).json({ success: false, message: 'An internal server error occurred.' });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  Rural Bank of Calbayog City — PIN Registration`);
  console.log(`  Server running at http://localhost:${PORT}`);
  console.log(`  Environment : ${process.env.NODE_ENV || 'development'}\n`);
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Masks all but the last 4 digits of an account number for safe logging.
 * @param {string} acct  — digits-only account string
 * @returns {string}
 */
function maskAccount(acct) {
  if (acct.length <= 4) return acct;
  return '••••-••••-' + acct.slice(-4);
}

/**
 * Generates a simple alphanumeric reference code for the registration record.
 * @returns {string}
 */
function generateReference() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous chars
  let ref = 'RBCC-';
  for (let i = 0; i < 8; i++) {
    ref += chars[Math.floor(Math.random() * chars.length)];
  }
  return ref;
}

module.exports = app; // exported for testing
