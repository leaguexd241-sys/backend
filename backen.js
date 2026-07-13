// server.js - USANDO SOLO personal_sign - VERSIÓN CORREGIDA, CON LOAD/SAVE SEGURO
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { ethers } = require('ethers');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { body, param, validationResult } = require('express-validator');

// --- Config (desde .env) ---
const PORT = parseInt(process.env.PORT || '3001', 10);
const MONGO = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/grassland';
const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_TOKEN_EXPIRES = process.env.ACCESS_EXPIRES || '15m';
const REFRESH_TOKEN_TTL_DAYS = parseInt(process.env.REFRESH_TTL_DAYS || '7', 10);
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;
const FRONTEND_ORIGINS_RAW = process.env.FRONTEND_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000,http://127.0.0.1:5501,http://localhost:5501';
const APP_NAME = process.env.APP_NAME || 'Grassland Forest';
const NODE_ENV = process.env.NODE_ENV || 'development';

// --- Validación estricta de JWT_SECRET ---
if (!JWT_SECRET || JWT_SECRET === 'replace_this_secret') {
  console.error('❌ ERROR CRÍTICO: JWT_SECRET no configurado o es débil');
  console.error('   Configura JWT_SECRET en .env con al menos 32 caracteres aleatorios');
  console.error('   Ejemplo: JWT_SECRET=' + crypto.randomBytes(32).toString('hex'));
  process.exit(1);
}

if (JWT_SECRET.length < 32) {
  console.error('❌ ERROR: JWT_SECRET demasiado corto. Mínimo 32 caracteres');
  process.exit(1);
}

// --- Prepare allowed origins ---
const allowedOrigins = FRONTEND_ORIGINS_RAW.split(',').map(s => s.trim()).filter(Boolean);

// --- Mongoose schemas/models ---

// Auth / rate-limit player (ampliado con playerName)
const playerSchema = new mongoose.Schema({
  address: { type: String, required: true, unique: true, index: true },
  playerName: { type: String, default: null },
  nonce: { type: String, default: null },
  nonceTimestamp: { type: Date, default: null },
  refreshTokenHash: { type: String, default: null },
  refreshTokenId: { type: String, default: null, index: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: null },
  loginAttempts: { type: Number, default: 0 },
  loginBlockedUntil: { type: Date, default: null }
});

// Índices
playerSchema.index({ refreshTokenId: 1 });
playerSchema.index({ nonceTimestamp: 1 }, { expireAfterSeconds: 600 }); // Expira nonce en 10 min

const PlayerAuth = mongoose.model('PlayerAuth', playerSchema);

// Modelo para tracking de rate limiting
const rateLimitSchema = new mongoose.Schema({
  ip: { type: String, required: true, index: true },
  endpoint: { type: String, required: true },
  count: { type: Number, default: 1 },
  firstAttempt: { type: Date, default: Date.now },
  lastAttempt: { type: Date, default: Date.now },
  blockedUntil: { type: Date, default: null }
});
const RateLimit = mongoose.model('RateLimit', rateLimitSchema);

// ---------------------------
// Game data model (Player data)
// ---------------------------
const gamePlayerSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true },
  posicionplayerx: { type: Number, default: 2097 },
  posicionplayery: { type: Number, default: 2359 },
  vidaPorcentaje: { type: Number, default: 100000 },
  aguaPorcentaje: { type: Number, default: 100000 },
  comidaPorcentaje: { type: Number, default: 10000 },
  speed: { type: Number, default: 240 },
  mundo: { type: Number, default: 1 },
  moneda: { type: Number, default: 100000 },
  Username: { type: String, default: '---' },
  lenguaje: { type: Number, default: 1 },
  nivel: { type: Number, default: 0 },
  nivel_exp: { type: Number, default: 0 },
  mineria: { type: Number, default: 0 },
  mineria_exp: { type: Number, default: 0 },
  pesca: { type: Number, default: 0 },
  pesca_exp: { type: Number, default: 0 },
  cocina: { type: Number, default: 0 },
  cocina_exp: { type: Number, default: 0 },
  deforestacion: { type: Number, default: 0 },
  deforestacion_exp: { type: Number, default: 0 },
  fuerza: { type: Number, default: 0 },
  fuerza_exp: { type: Number, default: 0 },
  agricultura: { type: Number, default: 0 },
  agricultura_exp: { type: Number, default: 0 },
  misiones: { type: Number, default: 0 },
  inventory: { type: Array, default: [] },
  chest: { type: Array, default: [] },
  address: { type: String, lowercase: true, default: null }
}, { timestamps: true, versionKey: false });

const GamePlayer = mongoose.model('GamePlayer', gamePlayerSchema);

// Admin config simple (hora, dia_noche)
const adminSchema = new mongoose.Schema({
  _id: { type: String, default: 'config' },
  hora: { type: Number, default: 1200 },
  dia_noche: { type: Number, default: 1 }
}, { versionKey: false });

const Admin = mongoose.model('Admin', adminSchema);

// MissionsPlayer (esquema simple para compatibilidad)
const missionsPlayerSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true },
}, { strict: false, timestamps: true });

const MissionsPlayer = mongoose.model('MissionsPlayer', missionsPlayerSchema);

// --- App ---
const app = express();

// Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginResourcePolicy: { policy: "same-site" },
  hsts: NODE_ENV === 'production' ? {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  } : false
}));

app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.set('trust proxy', 1);

// --- Force HTTPS in production ---
if (NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https' && !req.secure) {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

// --- CORS dynamic ---
const corsOptions = {
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    if (NODE_ENV === 'development') {
      const localhostRegex = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(:\d+)?$/;
      if (localhostRegex.test(origin)) return callback(null, true);
    }
    console.warn('❌ CORS blocked for origin:', origin);
    return callback(new Error('CORS not allowed'), false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','Accept','X-Requested-With','Cache-Control','Origin','X-CSRF-Token'],
  exposedHeaders: ['Set-Cookie', 'X-CSRF-Token'],
  maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// --- Logging middleware (safe) ---
app.use((req, res, next) => {
  const safeLog = {
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    origin: req.headers.origin || 'none',
    ip: req.ip,
    userAgent: req.headers['user-agent'] ? req.headers['user-agent'].substring(0, 100) : 'unknown'
  };
  console.log(`${safeLog.timestamp} ${safeLog.method} ${safeLog.path} - IP: ${safeLog.ip}`);
  next();
});

// --- CSRF Protection ---
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

function verifyCSRFToken(req) {
  const tokenFromHeader = req.headers['x-csrf-token'];
  const tokenFromCookie = req.cookies && req.cookies['csrf-token'];
  if (!tokenFromHeader || !tokenFromCookie) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(tokenFromHeader), Buffer.from(tokenFromCookie));
  } catch {
    return false;
  }
}

function csrfProtection(req, res, next) {
  if (req.method === 'GET' || req.path === '/api/auth/nonce') {
    return next();
  }
  if (!verifyCSRFToken(req)) {
    console.warn('❌ CSRF attempt from IP:', req.ip);
    return res.status(403).json({ error: 'csrf_token_invalid' });
  }
  next();
}

// --- Rate limiters ---
function createMongoRateLimiter(windowMs, maxRequests, endpoint) {
  return async function(req, res, next) {
    const ip = req.ip;
    const now = new Date();
    try {
      let record = await RateLimit.findOne({ ip, endpoint });
      if (!record) {
        record = new RateLimit({ ip, endpoint });
        await record.save();
        return next();
      }
      if (record.blockedUntil && record.blockedUntil > now) {
        const remaining = Math.ceil((record.blockedUntil - now) / 1000);
        res.set('Retry-After', remaining.toString());
        return res.status(429).json({ error: 'rate_limit_exceeded', retryAfter: remaining });
      }
      if (now - record.firstAttempt > windowMs) {
        record.count = 1;
        record.firstAttempt = now;
        record.lastAttempt = now;
        await record.save();
        return next();
      }
      record.count += 1;
      record.lastAttempt = now;
      if (record.count > maxRequests) {
        record.blockedUntil = new Date(now.getTime() + 600000); // 10 min
        await record.save();
        res.set('Retry-After', '600');
        return res.status(429).json({ error: 'rate_limit_exceeded', retryAfter: 600 });
      }
      await record.save();
      next();
    } catch (err) {
      console.error('Rate limiter error:', err);
      next();
    }
  };
}

const nonceLimiter = createMongoRateLimiter(60 * 1000, 5, '/api/auth/nonce');
const loginLimiter = createMongoRateLimiter(15 * 60 * 1000, 10, '/api/auth/login');

// express-rate-limit instances
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'too_many_requests' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/auth', authLimiter);

// <-- MISSING apiLimiter fixed here -->
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120,            // 120 requests per IP per minute
  message: { error: 'too_many_requests' },
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Connect to MongoDB ---
mongoose.connect(MONGO, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error', err);
    process.exit(1);
  });

// --- Helpers ---
function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function isValidEthereumAddress(address) {
  if (!address) return false;
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return false;
  try {
    const checksummed = ethers.getAddress(address);
    return checksummed === address || checksummed.toLowerCase() === address.toLowerCase();
  } catch {
    return false;
  }
}

function setCookieOptions(maxAgeSeconds, csrf = false) {
  const opts = {
    httpOnly: !csrf,
    secure: NODE_ENV === 'production',
    sameSite: NODE_ENV === 'production' ? 'Strict' : 'Lax',
    maxAge: (maxAgeSeconds || 0) * 1000,
    path: '/',
  };
  if (NODE_ENV === 'production' && COOKIE_DOMAIN) {
    opts.domain = COOKIE_DOMAIN;
  }
  return opts;
}

function validateSignedMessage(message, expectedToken) {
  if (!message || !expectedToken) return false;
  try {
    const prefix = `Signing in to ${APP_NAME}: `;
    if (!message.startsWith(prefix)) return false;
    const encodedToken = message.substring(prefix.length);
    const decodedToken = Buffer.from(encodedToken, 'base64').toString('utf8');
    return crypto.timingSafeEqual(Buffer.from(decodedToken), Buffer.from(expectedToken));
  } catch {
    return false;
  }
}

// --- Routes ---

// Health
app.get('/api/health', (req, res) => {
  res.json({ ok: true, timestamp: Date.now(), service: 'Auth Service', version: '2.0.0-secure', environment: NODE_ENV });
});

// CSRF token endpoint
app.get('/api/auth/csrf-token', (req, res) => {
  const csrfToken = generateCSRFToken();
  res.cookie('csrf-token', csrfToken, setCookieOptions(3600, true));
  res.setHeader('X-CSRF-Token', csrfToken);
  return res.json({ csrfToken });
});

// Nonce endpoint
app.get('/api/auth/nonce', nonceLimiter, async (req, res) => {
  try {
    const address = (req.query.address || '').toLowerCase();
    if (!address || !isValidEthereumAddress(address)) return res.status(400).json({ error: 'valid_ethereum_address_required' });
    const player = await PlayerAuth.findOne({ address }).exec();
    if (player && player.loginBlockedUntil && player.loginBlockedUntil > new Date()) {
      const remaining = Math.ceil((player.loginBlockedUntil - new Date()) / 1000);
      return res.status(429).json({ error: 'account_temporarily_blocked', retryAfter: remaining });
    }
    const nonce = generateNonce();
    const nonceTimestamp = new Date();
    await PlayerAuth.findOneAndUpdate({ address }, { $set: { nonce, nonceTimestamp, loginAttempts: 0, loginBlockedUntil: null } }, { upsert: true, new: true });
    console.log(`🔢 Nonce generado para ${address.substring(0, 10)}...`);
    return res.json({ nonce });
  } catch (err) {
    console.error('❌ Nonce error:', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// Login
app.post('/api/auth/login', loginLimiter, csrfProtection, async (req, res) => {
  const startTime = Date.now();
  try {
    const { address, signature, token, message } = req.body || {};
    if (!address || !signature || !token || !message) return res.status(400).json({ error: 'missing_required_parameters' });
    const lcAddress = address.toLowerCase();
    if (!isValidEthereumAddress(lcAddress)) return res.status(400).json({ error: 'invalid_ethereum_address' });

    let player = await PlayerAuth.findOne({ address: lcAddress }).exec();
    if (!player || !player.nonce) {
      console.warn(`❌ No nonce encontrado para ${lcAddress.substring(0, 10)}...`);
      return res.status(401).json({ error: 'authentication_failed' });
    }

    if (player.nonceTimestamp && (Date.now() - player.nonceTimestamp.getTime() > 10 * 60 * 1000)) {
      await PlayerAuth.updateOne({ address: lcAddress }, { $set: { nonce: null, nonceTimestamp: null } });
      return res.status(401).json({ error: 'nonce_expired' });
    }

    const [nonceFromToken, tsStr] = String(token).split(':');
    const ts = parseInt(tsStr, 10);
    if (!nonceFromToken || !ts || isNaN(ts)) return res.status(400).json({ error: 'invalid_token_format' });

    if (!crypto.timingSafeEqual(Buffer.from(nonceFromToken), Buffer.from(player.nonce))) {
      const newAttempts = (player.loginAttempts || 0) + 1;
      let updateData = { loginAttempts: newAttempts };
      if (newAttempts >= 5) updateData.loginBlockedUntil = new Date(Date.now() + 15 * 60 * 1000);
      await PlayerAuth.updateOne({ address: lcAddress }, { $set: updateData });
      return res.status(401).json({ error: 'authentication_failed' });
    }

    const now = Math.floor(Date.now() / 1000);
    const MAX_AGE = 60 * 5;
    if (Math.abs(now - ts) > MAX_AGE) return res.status(401).json({ error: 'token_expired' });

    if (!validateSignedMessage(message, token)) {
      console.warn(`❌ Validación de mensaje fallida para ${lcAddress.substring(0, 10)}...`);
      return res.status(401).json({ error: 'message_validation_failed' });
    }

    let recovered;
    try {
      const hash = ethers.hashMessage(message);
      recovered = ethers.recoverAddress(hash, signature);
    } catch (err) {
      console.warn(`❌ Error en verificación de firma: ${err.message}`);
      return res.status(401).json({ error: 'signature_verification_failed' });
    }

    if (!recovered || recovered.toLowerCase() !== lcAddress.toLowerCase()) {
      console.warn(`❌ Dirección no coincide para ${lcAddress.substring(0, 10)}...`);
      return res.status(401).json({ error: 'address_mismatch' });
    }

    // rotate nonce and create tokens
    const refreshTokenId = uuidv4();
    const rawRefresh = jwt.sign({ address: lcAddress, jti: refreshTokenId, type: 'refresh' }, JWT_SECRET, { expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d` });
    const refreshHash = await bcrypt.hash(rawRefresh, 12);
    const accessToken = jwt.sign({ address: lcAddress, type: 'access', jti: uuidv4() }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES });

    await PlayerAuth.findOneAndUpdate({ address: lcAddress }, { $set: { nonce: null, nonceTimestamp: null, refreshTokenHash: refreshHash, refreshTokenId, lastLogin: new Date(), loginAttempts: 0, loginBlockedUntil: null } }, { upsert: true });

    const accessCookieOpts = setCookieOptions(15 * 60);
    const refreshCookieOpts = setCookieOptions(REFRESH_TOKEN_TTL_DAYS * 24 * 3600);

    res.cookie('session', accessToken, accessCookieOpts);
    res.cookie('refresh', rawRefresh, refreshCookieOpts);

    const csrfToken = generateCSRFToken();
    res.cookie('csrf-token', csrfToken, setCookieOptions(3600, true));
    res.setHeader('X-CSRF-Token', csrfToken);

    const duration = Date.now() - startTime;
    console.log(`✅ Login exitoso para ${lcAddress.substring(0, 10)}... (${duration}ms)`);

    return res.json({ authenticated: true, address: lcAddress, csrfToken });
  } catch (err) {
    console.error('❌ Login error:', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// Refresh
app.post('/api/auth/refresh', csrfProtection, async (req, res) => {
  try {
    const raw = req.cookies && req.cookies.refresh;
    if (!raw) return res.status(401).json({ error: 'refresh_token_required' });

    let payload;
    try {
      payload = jwt.verify(raw, JWT_SECRET);
      if (payload.type !== 'refresh') throw new Error('Invalid token type');
    } catch (err) {
      res.clearCookie('session', setCookieOptions(0));
      res.clearCookie('refresh', setCookieOptions(0));
      res.clearCookie('csrf-token', setCookieOptions(0, true));
      return res.status(401).json({ error: 'invalid_refresh_token' });
    }

    const player = await PlayerAuth.findOne({ address: payload.address.toLowerCase(), refreshTokenId: payload.jti }).exec();
    if (!player) {
      res.clearCookie('session', setCookieOptions(0));
      res.clearCookie('refresh', setCookieOptions(0));
      res.clearCookie('csrf-token', setCookieOptions(0, true));
      return res.status(401).json({ error: 'invalid_refresh_token' });
    }

    const isValid = await bcrypt.compare(raw, player.refreshTokenHash);
    if (!isValid) {
      await PlayerAuth.updateOne({ address: player.address }, { $set: { refreshTokenHash: null, refreshTokenId: null } });
      res.clearCookie('session', setCookieOptions(0));
      res.clearCookie('refresh', setCookieOptions(0));
      res.clearCookie('csrf-token', setCookieOptions(0, true));
      return res.status(401).json({ error: 'token_revoked' });
    }

    const newRefreshTokenId = uuidv4();
    const newRawRefresh = jwt.sign({ address: player.address, jti: newRefreshTokenId, type: 'refresh' }, JWT_SECRET, { expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d` });
    const newRefreshHash = await bcrypt.hash(newRawRefresh, 12);
    const accessToken = jwt.sign({ address: player.address, type: 'access', jti: uuidv4() }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES });

    await PlayerAuth.updateOne({ address: player.address }, { $set: { refreshTokenHash: newRefreshHash, refreshTokenId: newRefreshTokenId } });

    const accessCookieOpts = setCookieOptions(15 * 60);
    const refreshCookieOpts = setCookieOptions(REFRESH_TOKEN_TTL_DAYS * 24 * 3600);

    res.cookie('session', accessToken, accessCookieOpts);
    res.cookie('refresh', newRawRefresh, refreshCookieOpts);

    const csrfToken = generateCSRFToken();
    res.cookie('csrf-token', csrfToken, setCookieOptions(3600, true));
    res.setHeader('X-CSRF-Token', csrfToken);

    console.log(`✅ Token refrescado para ${player.address.substring(0, 10)}...`);
    return res.json({ ok: true, csrfToken });
  } catch (err) {
    console.error('❌ Refresh error:', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// Auth middleware
function authMiddleware(req, res, next) {
  try {
    const token = req.cookies && req.cookies.session;
    if (!token) return res.status(401).json({ authenticated: false, error: 'authentication_required' });
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== 'access') throw new Error('Invalid token type');
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ authenticated: false, error: 'invalid_session' });
  }
}

// Get current user
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const address = (req.user && req.user.address) || null;
    const player = await PlayerAuth.findOne({ address }).lean().exec();
    return res.json({
      authenticated: true,
      address,
      playerData: player ? { address: player.address, playerName: player.playerName, createdAt: player.createdAt, lastLogin: player.lastLogin } : null
    });
  } catch (err) {
    console.error('❌ Me error:', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// Logout
app.post('/api/auth/logout', csrfProtection, async (req, res) => {
  try {
    const raw = req.cookies && req.cookies.refresh;
    if (raw) {
      try {
        const payload = jwt.verify(raw, JWT_SECRET);
        if (payload.type === 'refresh' && payload.address) {
          await PlayerAuth.updateOne({ address: payload.address.toLowerCase() }, { $set: { refreshTokenHash: null, refreshTokenId: null } });
        }
      } catch (err) {
        // ignore
      }
    }
    res.clearCookie('session', setCookieOptions(0));
    res.clearCookie('refresh', setCookieOptions(0));
    res.clearCookie('csrf-token', setCookieOptions(0, true));
    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Logout error:', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ----------------------
// SAVE / LOAD (secure)
// ----------------------

// Validation helper for items arrays
function validateItemsArray(arr) {
  if (!Array.isArray(arr)) return false;
  return arr.every(item => {
    if (!item) return false;
    const okId = (typeof item.id === 'number' && Number.isFinite(item.id));
    const okObj = (typeof item.objeto === 'string' && item.objeto.length > 0);
    const okCount = (typeof item.cantidad === 'number' && Number.isFinite(item.cantidad));
    return okId && okObj && okCount;
  });
}

// Save endpoint
app.post('/save/:playerName',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  param('playerName').isString().notEmpty(),
  body('inventory').optional().isArray(),
  body('chest').optional().isArray(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { playerName } = req.params;
    const address = req.user.address.toLowerCase();
    const { inventory, chest } = req.body;

    if (inventory !== undefined && !validateItemsArray(inventory)) return res.status(400).json({ error: 'invalid_inventory_format' });
    if (chest !== undefined && !validateItemsArray(chest)) return res.status(400).json({ error: 'invalid_chest_format' });

    try {
      const auth = await PlayerAuth.findOne({ address }).exec();
      if (!auth) return res.status(404).json({ error: 'user_not_found' });

      if (!auth.playerName) {
        auth.playerName = playerName;
        await auth.save();
      } else if (auth.playerName !== playerName) {
        return res.status(403).json({ error: 'not_authorized_for_player' });
      }

      const update = Object.assign({}, req.body, { address });
      const p = await GamePlayer.findOneAndUpdate(
        { playerName },
        { $set: update },
        { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
      );

      if (req.body.missionsData && typeof req.body.missionsData === 'object') {
        await MissionsPlayer.findOneAndUpdate(
          { playerName },
          { $set: req.body.missionsData },
          { upsert: true, new: true, runValidators: false }
        );
      }

      return res.json({ success: true });
    } catch (e) {
      console.error('Error en save:', e && e.message ? e.message : e);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }
);

// Load endpoint
app.get('/load/:playerName',
  apiLimiter,
  authMiddleware,
  param('playerName').isString().notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { playerName } = req.params;
    const address = req.user.address.toLowerCase();

    try {
      const auth = await PlayerAuth.findOne({ address }).exec();
      if (!auth) return res.status(404).json({ error: 'user_not_found' });

      if (!auth.playerName) {
        auth.playerName = playerName;
        await auth.save();
      } else if (auth.playerName !== playerName) {
        return res.status(403).json({ error: 'not_authorized_for_player' });
      }

      let p = await GamePlayer.findOne({ playerName }).lean().exec();
      if (!p) {
        p = await GamePlayer.create({ playerName, address });
      }

      let a = await Admin.findById('config').lean().exec();
      if (!a) {
        await Admin.create({ _id: 'config' });
        a = await Admin.findById('config').lean().exec();
      }

      let missionsData = await MissionsPlayer.findOne({ playerName }).lean().exec();
      if (!missionsData) {
        const created = await MissionsPlayer.create({ playerName });
        missionsData = created.toObject();
      }

      const response = Object.assign({}, p, { hora: a.hora, dia_noche: a.dia_noche, missionsData });
      return res.json(response);
    } catch (e) {
      console.error('Error en load:', e && e.message ? e.message : e);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }
);

// Limpieza periódica de nonces expirados (backup)
setInterval(async () => {
  try {
    const result = await PlayerAuth.updateMany(
      { nonce: { $ne: null }, nonceTimestamp: { $lt: new Date(Date.now() - 10 * 60 * 1000) } },
      { $set: { nonce: null, nonceTimestamp: null } }
    );
    if (result.modifiedCount > 0) console.log(`🧹 Limpiados ${result.modifiedCount} nonces expirados`);
  } catch (err) {
    console.error('Error en limpieza de nonces:', err && err.message ? err.message : err);
  }
}, 5 * 60 * 1000);

// Limpieza periódica de rate limits expirados
setInterval(async () => {
  try {
    const result = await RateLimit.deleteMany({ firstAttempt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    if (result.deletedCount > 0) console.log(`🧹 Limpiados ${result.deletedCount} rate limits expirados`);
  } catch (err) {
    console.error('Error en limpieza de rate limits:', err && err.message ? err.message : err);
  }
}, 30 * 60 * 1000);

// 404 handler
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'not_found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('❌ Error no manejado:', err && err.message ? err.message : err);
  res.status(500).json({ error: 'internal_server_error', message: NODE_ENV === 'development' ? (err && err.message ? err.message : '') : undefined });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`=================================`);
  console.log(`🚀 Auth server v2.0.0 (SECURE) corriendo en puerto ${PORT}`);
  console.log(`🌍 Entorno: ${NODE_ENV}`);
  console.log(`🔒 JWT_SECRET: ${JWT_SECRET ? '✅ Configurado' : '❌ NO CONFIGURADO'}`);
  console.log(`🔗 Orígenes permitidos: ${allowedOrigins.join(', ')}`);
  console.log(`🔗 MongoDB: ${MONGO.split('@').pop() || MONGO}`);
  console.log(`=================================`);
  if (NODE_ENV === 'production') {
    console.log('⚠️  VERIFICA: HTTPS, JWT_SECRET >=32 chars, COOKIE_DOMAIN, MONGO TLS, rate limiting');
  }
});

// Graceful shutdown (mongoose.close returns a Promise)
process.on('SIGTERM', () => {
  console.log('🛑 Recibido SIGTERM, cerrando servidor...');
  server.close(async () => {
    console.log('✅ Server closed (SIGTERM). Closing MongoDB connection...');
    try {
      await mongoose.connection.close(false);
      console.log('✅ Conexión MongoDB cerrada');
      process.exit(0);
    } catch (e) {
      console.error('❌ Error cerrando MongoDB:', e);
      process.exit(1);
    }
  });
});

process.on('SIGINT', () => {
  console.log('🛑 Recibido SIGINT, cerrando servidor...');
  server.close(async () => {
    console.log('✅ Server closed (SIGINT). Closing MongoDB connection...');
    try {
      await mongoose.connection.close(false);
      console.log('✅ Conexión MongoDB cerrada');
      process.exit(0);
    } catch (e) {
      console.error('❌ Error cerrando MongoDB:', e);
      process.exit(1);
    }
  });
});
