require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const { body, header, validationResult } = require('express-validator');
const db = require('./database');
const app = express();
const PORT = process.env.PORT || 3000;
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Domain', 'X-Product-ID', 'X-Request-Timestamp']
}));
// Aggressive rate limiting for license verification endpoint
const licenseVerifyLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 5, // Max 5 requests per minute
  message: 'Too many verification requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many verification requests. Please wait before trying again.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  },
  keyGenerator: (req) => {
    // Rate limit by IP + License Key combination
    const licenseKey = req.headers.authorization?.replace('Bearer ', '').trim() || 'no-key';
    return `${req.ip}:${licenseKey}`;
  }
});
const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', generalLimiter);
app.disable('x-powered-by');
function normalizeDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    return null;
  }

  let normalized = domain.toLowerCase().trim();
  normalized = normalized.replace(/^[a-z][a-z0-9+\-.]*:\/\//i, '');
  normalized = normalized.replace(/^\/+/, '');
  normalized = normalized.replace(/\/+$/, '');
  normalized = normalized.replace(/:\d+$/, '');
  normalized = normalized.replace(/^www\./, '');
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(normalized)) {
    return null;
  }
  return normalized;
}
function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufferA = Buffer.from(a, 'utf8');
  const bufferB = Buffer.from(b, 'utf8');
  if (bufferA.length !== bufferB.length) {
    return crypto.timingSafeEqual(
      Buffer.from(a.padEnd(Math.max(a.length, b.length))),
      Buffer.from(b.padEnd(Math.max(a.length, b.length)))
    ) && false; 
  }

  return crypto.timingSafeEqual(bufferA, bufferB);
}
const enforceHTTPS = (req, res, next) => {
  if (process.env.ENFORCE_HTTPS !== 'true') {
    return next();
  }

  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  if (proto !== 'https') {
    return res.status(400).json({
      success: false,
      message: 'HTTPS required'
    });
  }

  next();
};
app.use('/api/', enforceHTTPS);
const validateLicenseRequest = [
  header('Authorization')
    .exists().withMessage('Authorization header is required')
    .matches(/^Bearer\s+[A-Z0-9_]+$/).withMessage('Invalid authorization format'),
  header('X-Domain')
    .exists().withMessage('X-Domain header is required')
    .trim()
    .isLength({ min: 1, max: 255 }).withMessage('Domain must be between 1 and 255 characters')
    .customSanitizer(value => {
      return normalizeDomain(value);
    }),
  header('X-Product-ID')
    .exists().withMessage('X-Product-ID header is required')
    .isInt({ min: 1 }).withMessage('Product ID must be a positive integer')
    .toInt(),
  header('X-Request-Timestamp')
    .optional()
    .isISO8601().withMessage('Invalid timestamp format')
];
app.get('/api/license/verify', licenseVerifyLimiter, validateLicenseRequest, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }
    const requestTimestamp = req.headers['x-request-timestamp'];
    if (requestTimestamp) {
      const requestTime = new Date(requestTimestamp);
      const currentTime = new Date();
      const timeDiff = Math.abs(currentTime - requestTime);
      if (timeDiff > 5 * 60 * 1000 || requestTime > new Date(currentTime.getTime() + 60 * 1000)) {
        return res.status(401).json({
          success: false,
          message: 'Request expired or invalid timestamp'
        });
      }
    }

    const authHeader = req.headers.authorization;
    const licenseKey = authHeader.replace('Bearer ', '').trim();
    const domain = req.headers['x-domain'];
    const productId = parseInt(req.headers['x-product-id']);

    if (!/^[A-Z0-9_]{20,50}$/.test(licenseKey)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid license key format'
      });
    }

    const normalizedProvidedDomain = normalizeDomain(domain);
    if (!normalizedProvidedDomain) {
      return res.status(400).json({
        success: false,
        message: 'Invalid domain format'
      });
    }

    const connection = await db.getConnection();
    try {
      await connection.beginTransaction();

      const [rows] = await connection.query(
        `SELECT
          id,
          license_key,
          user_id,
          product_id,
          domain,
          ip_address,
          service_id,
          is_active,
          created_at,
          updated_at,
          last_rotated
        FROM module_licenses
        WHERE license_key = ?
          AND product_id = ?
          AND is_active = 1
        LIMIT 1
        FOR UPDATE`,
        [licenseKey, productId]
      );

      if (rows.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(403).json({
          success: false,
          message: 'Invalid license credentials'
        });
      }

      const license = rows[0];

      // Domain validation using constant-time comparison
      if (license.domain) {
        const normalizedLicenseDomain = normalizeDomain(license.domain);

        if (!normalizedLicenseDomain || !constantTimeCompare(normalizedLicenseDomain, normalizedProvidedDomain)) {
          await connection.rollback();
          connection.release();
          return res.status(403).json({
            success: false,
            message: 'License validation failed'
          });
        }
      }

      // No database updates needed for verification (read-only operation)
      await connection.commit();
      connection.release();

      return res.status(200).json({
        success: true,
        message: 'License verified successfully',
        data: {
          license_key: license.license_key,
          product_id: license.product_id,
          domain: license.domain,
          service_id: license.service_id,
          is_active: license.is_active,
          created_at: license.created_at
        }
      });

    } catch (txError) {
      await connection.rollback();
      connection.release();
      throw txError;
    }

  } catch (error) {
    console.error('License verification error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});
app.listen(PORT, () => {
  console.log(`Fallback License Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
});
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing server...');
  await db.end();
  process.exit(0);
});
process.on('SIGINT', async () => {
  console.log('SIGINT received, closing server...');
  await db.end();
  process.exit(0);
});
