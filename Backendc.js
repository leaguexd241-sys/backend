// backend-completo.js
require('dotenv').config();
const cluster = require('cluster');
const os = require('os');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const { body, param, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const useragent = require('express-useragent');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const crypto = require('crypto');
const { ethers } = require('ethers');
const http = require("http");
const { Server } = require("socket.io");
const Web3 = require('web3');
const https = require('https');

// ─────────────────────────────────────────────────────────────────
// CONFIGURACIÓN INICIAL
// ─────────────────────────────────────────────────────────────────

const vetAgent = new https.Agent({ keepAlive: true, maxSockets: 10 });
const vetProvider = new Web3.providers.HttpProvider('https://api.roninchain.com/rpc', { agent: vetAgent });
const web3 = new Web3(vetProvider);
const vetContract = new web3.eth.Contract(
  [{ inputs: [], name: 'obtenerHoraVenezuelaString', outputs: [{ internalType: 'string', name: '', type: 'string' }], stateMutability: 'view', type: 'function' }],
  '0x148bfde77e6c51c1f5a4504ec38d87325baa2af2'
);
let vetDate = null;

// Configuración EIP-712
const EIP712_DOMAIN_BASE = {
  name: 'Grassland Forest',
  version: '1',
  chainId: 50312
};

const EIP712_TYPES_LOGIN = {
  Login: [{ name: 'text', type: 'string' }]
};

const MAX_TOKEN_AGE_SECONDS = Number(process.env.MAX_TOKEN_AGE_SECONDS || 10 * 60);
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://127.0.0.1:5500';
const NODE_ENV = process.env.NODE_ENV || 'development';

// ─────────────────────────────────────────────────────────────────
// MODELOS MONGOOSE
// ─────────────────────────────────────────────────────────────────

// Modelo User para autenticación EIP-712
const userSchema = new mongoose.Schema({
  address: { type: String, required: true, unique: true, lowercase: true },
  nonce: { type: String, required: true },
  playerName: { type: String, unique: true, sparse: true },
  lastLogin: { type: Date, default: Date.now },
  sessionValid: { type: Boolean, default: true }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// Modelo Admin para configuración
const adminSchema = new mongoose.Schema({
  _id: { type: String, default: 'config' },
  hora: { type: String, default: '00:00:00' },
  dia_noche: { type: String, default: 'dia' }
});
const Admin = mongoose.model('Admin', adminSchema);

// Modelo Player para el juego
const playerSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true },
  posicionplayerx: { type: Number, default: 2092 },
  posicionplayery: { type: Number, default: 2126 },
  vidaPorcentaje: { type: Number, default: 100 },
  aguaPorcentaje: { type: Number, default: 100 },
  comidaPorcentaje: { type: Number, default: 100 },
  speed: { type: Number, default: 2.7 },
  mundo: { type: Number, default: 1 },
  moneda: { type: Number, default: 0 },
  Username: { type: String, default: '---' },
  nivel: { type: Number, default: 0 },
  nivel_exp: { type: Number, default: 0 },
  sabiduria: { type: Number, default: 0 },
  sabiduria_exp: { type: Number, default: 0 },
  fuerza: { type: Number, default: 0 },
  fuerza_exp: { type: Number, default: 0 },
  agricultura: { type: Number, default: 0 },
  agricultura_exp: { type: Number, default: 0 },
  misiones: { type: Number, default: 0 },
  inventory: { type: Array, default: [] },
  chest: { type: Array, default: [] },
  address: { type: String, lowercase: true }
});
const Player = mongoose.model('Player', playerSchema);

// Modelo Listing para marketplace
const listingSchema = new mongoose.Schema({
  owner: { type: String, required: true },
  inventoryId: { type: String, required: true },
  name: { type: String, required: true },
  type: { type: String, required: true },
  qty: { type: Number, required: true, min: 1 },
  price: { type: Number, required: true, min: 0 },
  imageUrl: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});
const Listing = mongoose.model('Listing', listingSchema);

// Modelo Session para manejar sesiones activas
const sessionSchema = new mongoose.Schema({
  address: { type: String, required: true, index: true },
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  valid: { type: Boolean, default: true }
}, { timestamps: true });
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Session = mongoose.model('Session', sessionSchema);

// Modelo Activity para analytics
const activitySchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true, index: true },
  registeredAt: { type: Date, default: Date.now },
  loginCount: { type: Number, default: 0 },
  lastLogin: { type: Date },
  ip: { type: String },
  geo: {
    country: String,
    region: String,
    city: String,
    latitude: Number,
    longitude: Number,
    timezone: String,
    asn: Number,
    isp: String,
    proxy: Boolean,
    tor: Boolean
  },
  headers: {
    userAgent: String,
    acceptLang: String,
    secCHUA: String,
    secCHUAMobile: String,
    secCHUAPlatform: String,
    tlsFingerprint: String
  },
  fingerprint: {
    canvasHash: String,
    webglHash: String,
    audioHash: String,
    fonts: [String],
    screen: {
      width: Number,
      height: Number,
      colorDepth: Number
    },
    timezone: String
  },
  behavior: {
    avgLatency: Number,
    mouseSpeed: Number,
    focusChanges: Number
  },
  sessions: [{
    connectedAt: { type: Date, required: true },
    disconnectedAt: { type: Date }
  }]
}, { timestamps: true });
const UserActivity = mongoose.model('UserActivity', activitySchema);

const connectedSchema = new mongoose.Schema({ 
  playerName: String, 
  connectedAt: { type: Date, default: Date.now } 
});
const ConnectedUser = mongoose.model('ConnectedUser', connectedSchema);

// ─────────────────────────────────────────────────────────────────
// FUNCIONES AUXILIARES MEJORADAS
// ─────────────────────────────────────────────────────────────────

function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

function extractTlsFingerprint(socket) {
  try {
    const cert = socket.getPeerCertificate && socket.getPeerCertificate();
    if (cert && cert.fingerprint) return cert.fingerprint;
  } catch (e) {}
  return 'unknown';
}

async function sincronizarHoraVET() {
  try {
    const horaStr = await vetContract.methods.obtenerHoraVenezuelaString().call();
    const m = horaStr.match(/(\d{2})\/(\d{2})\/(\d{4}) - (\d{2}):(\d{2}):(\d{2})/);
    if (m) {
      const [, d, mth, y, h, min, s] = m;
      vetDate = new Date(Date.UTC(+y, +mth - 1, +d, +h + 4, +min, +s));
      console.log('⏱ Hora inicial VET:', horaStr);
    } else {
      console.warn('Formato hora VET inesperado:', horaStr);
    }
  } catch (e) {
    console.error('Error sincronizando VET:', e);
  }
}

function iniciarRelojVET() {
  if (!vetDate) return;
  setInterval(async () => {
    try {
      vetDate.setSeconds(vetDate.getSeconds() + 1);
      const hora = vetDate.toLocaleTimeString('es-VE', { hour12: false, timeZone: 'America/Caracas' });
      const hourNum = +hora.split(':')[0];
      const dia_noche = (hourNum >= 6 && hourNum < 18) ? 'day' : 'night';
      await Admin.findByIdAndUpdate('config', { hora, dia_noche }, { upsert: true });
    } catch (e) {
      console.error('Error en iniciarRelojVET loop:', e);
    }
  }, 1000);
}

async function validateAndRefreshSession(token, address) {
  try {
    // Verificar el token JWT primero
    const payload = jwt.verify(token, JWT_SECRET);
    
    // Buscar sesión en la base de datos
    const session = await Session.findOne({ 
      address: address.toLowerCase(), 
      token: crypto.createHash('sha256').update(token).digest('hex'),
      valid: true
    });
    
    if (!session) {
      console.log('Session not found in database');
      // Limpiar sesiones expiradas para este usuario
      await Session.deleteMany({ 
        address: address.toLowerCase(),
        expiresAt: { $lt: new Date() }
      });
      return null;
    }
    
    if (session.expiresAt < new Date()) {
      console.log('Session expired - cleaning up');
      await Session.deleteOne({ _id: session._id });
      return null;
    }
    
    // RENOVAR SESIÓN si está cerca de expirar (últimos 30 minutos)
    const thirtyMinutesFromNow = new Date(Date.now() + 30 * 60 * 1000);
    if (session.expiresAt < thirtyMinutesFromNow) {
      console.log('Refreshing session token');
      
      // Crear nuevo token
      const newExpiresAt = new Date();
      newExpiresAt.setDate(newExpiresAt.getDate() + (session.remember ? 30 : 1));
      
      const newTokenPayload = { 
        address: address.toLowerCase(),
        timestamp: Date.now()
      };
      
      const newJwtToken = jwt.sign(newTokenPayload, JWT_SECRET, { 
        expiresIn: session.remember ? '30d' : '1d' 
      });
      
      // Actualizar sesión
      session.token = crypto.createHash('sha256').update(newJwtToken).digest('hex');
      session.expiresAt = newExpiresAt;
      await session.save();
      
      // Devolver nuevo token en la respuesta
      payload.newToken = newJwtToken;
    }
    
    // Actualizar lastLogin del usuario
    await User.findOneAndUpdate(
      { address: address.toLowerCase() },
      { lastLogin: new Date(), sessionValid: true }
    );
    
    return payload;
  } catch (error) {
    console.log('Session validation failed:', error.message);
    
    // Limpiar sesiones expiradas para este usuario
    if (address) {
      await Session.deleteMany({ 
        address: address.toLowerCase(),
        expiresAt: { $lt: new Date() }
      });
    }
    
    return null;
  }
}

// Agrega esto después de las funciones auxiliares
async function cleanupExpiredSessions() {
  try {
    const result = await Session.deleteMany({
      $or: [
        { expiresAt: { $lt: new Date() } },
        { valid: false }
      ]
    });
    console.log(`🧹 Cleaned up ${result.deletedCount} expired sessions`);
  } catch (error) {
    console.error('Error cleaning expired sessions:', error);
  }
}

// Ejecutar limpieza cada hora
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// Ejecutar al iniciar
setTimeout(cleanupExpiredSessions, 5000);


async function createNewSession(address, remember = false) {
  const tokenPayload = { 
    address: address.toLowerCase(),
    timestamp: Date.now()
  };

  const expiresIn = remember ? '30d' : '1d';
  const jwtToken = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn });
  
  // Calcular fecha de expiración
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + (remember ? 30 : 1));
  
  // Guardar sesión en BD
  await Session.create({
    address: address.toLowerCase(),
    token: crypto.createHash('sha256').update(jwtToken).digest('hex'),
    expiresAt,
    valid: true,
    remember: remember
  });
  
  return { jwtToken, expiresAt };
}

async function invalidateAllSessions(address) {
  await Session.updateMany(
    { address: address.toLowerCase() },
    { $set: { valid: false } }
  );
}



// ─────────────────────────────────────────────────────────────────
// CONFIGURACIÓN EXPRESS Y SOCKET.IO MEJORADA
// ─────────────────────────────────────────────────────────────────

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = [
  'http://192.168.100.226:5500',
  'http://192.168.100.226:5501',
  'http://192.168.100.226:3000',
  'http://localhost:5500',
  'http://localhost:5501',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5501',
  'http://127.0.0.1:3000',
  'http://192.168.100.221:5500',
  'http://192.168.100.221:5501',
  'http://192.168.100.221:3000',
  'http://192.168.100.11:5500',
  'http://192.168.100.11:5501',
  'http://192.168.100.11:3000',
  'http://localhost:5173',
  'https://grasslandforest.xyz',
  FRONTEND_ORIGIN
].filter(Boolean);

// CORS mejorado - Sin errores en consola para origins no permitidos

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    if (NODE_ENV !== 'production') return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));


// Manejar preflight OPTIONS requests
app.options('*', cors());

app.set('trust proxy', 1);
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false
}));
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());
app.use(useragent.express());
app.use(requestIp.mw());


app.use((req, res, next) => {
  // Usa el origin de la petición si viene; si no viene, usa FRONTEND_ORIGIN como fallback
  const origin = req.headers.origin || FRONTEND_ORIGIN || 'http://localhost:3000';

  // Si el origin es de la lista o estamos en dev, permite y refleja el origin.
  if (allowedOrigins.indexOf(origin) !== -1 || NODE_ENV !== 'production') {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    // en producción, si no está permitido, no exponemos el origin
    // (esto ayuda a evitar cookies siendo enviadas a orígenes no permitidos)
  }

  // Obligatorio para que el navegador acepte Set-Cookie cross-site
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Preflight helpers
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With');
    return res.sendStatus(204);
  }

  next();
});

const server = http.createServer(app);
const io = new Server(server, {
  path: '/socket.io',
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  },
  allowEIO3: false
});

// ─────────────────────────────────────────────────────────────────
// SOCKET.IO HANDLERS
// ─────────────────────────────────────────────────────────────────

let players = {};
let chatHistory = [];
const MAX_HISTORY = 50;

function escapeHtml(text = '') {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

io.on("connection", (socket) => {
  console.log(`Jugador conectado: ${socket.id}`);

  players[socket.id] = { id: socket.id, x: 0, y: 0 };

  io.emit("currentPlayers", Object.values(players));
  io.emit("playerCount", Object.keys(players).length);

  socket.on("playerMove", (data) => {
    if (players[socket.id]) {
      players[socket.id].x = data.x;
      players[socket.id].y = data.y;
      players[socket.id].direction = data.direction;
      players[socket.id].directionx = data.directionx;
      players[socket.id].usernamex = data.usernamex;
      io.emit("playerMoved", players[socket.id]);
    }
  });

  socket.on("disconnect", () => {
    delete players[socket.id];
    io.emit("playerCount", Object.keys(players).length);
    io.emit("playerDisconnected", socket.id);
    io.emit("currentPlayers", Object.values(players));
  });

  socket.on('requestHistory', () => {
    try {
      socket.emit('chatHistory', chatHistory.slice(-MAX_HISTORY));
    } catch (e) {
      console.error('Error enviando chatHistory:', e);
    }
  });

  socket.on('chatMessage', (payload) => {
    try {
      const now = Date.now();
      if (now - (socket.chatLastSent || 0) < (socket.chatRateLimitMs || 1000)) {
        socket.emit('chatError', { msg: 'Demasiados mensajes. Espera un momento.' });
        return;
      }
      socket.chatLastSent = now;

      const playerName = escapeHtml(payload.usernamex || payload.playerName || (players[socket.id] && players[socket.id].usernamex) || '---');
      const text = escapeHtml(String(payload.text || '').trim()).slice(0, 500);
      if (!text) return;

      const message = {
        id: socket.id,
        playerName,
        text,
        ts: new Date().toISOString()
      };

      chatHistory.push(message);
      if (chatHistory.length > MAX_HISTORY) chatHistory.shift();

      io.emit('chatMessage', message);
    } catch (e) {
      console.error('chatMessage error:', e);
    }
  });
});

// ─────────────────────────────────────────────────────────────────
// CONEXIÓN MONGODB CON RECONEXIÓN MEJORADA
// ─────────────────────────────────────────────────────────────────

const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  retryWrites: true
};

mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://localhost:27017/grassland', mongooseOptions)
.then(async () => {
  console.log('✔️ Conexión a MongoDB exitosa');
  
  // Limpiar sesiones inválidas al iniciar
  try {
    await Session.deleteMany({ 
      $or: [
        { expiresAt: { $lt: new Date() } },
        { valid: false }
      ]
    });
    console.log('✔️ Sesiones inválidas limpiadas');
  } catch (e) {
    console.log('Error limpiando sesiones:', e);
  }
})
.catch(err => {
  console.error('❌ Error al conectar a MongoDB:', err);
  process.exit(1);
});

// Manejar eventos de conexión de MongoDB
mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB desconectado');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconectado');
});

// ─────────────────────────────────────────────────────────────────
// MIDDLEWARES PERSONALIZADOS
// ─────────────────────────────────────────────────────────────────

const apiLimiter = rateLimit({
  windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW) || 1) * 3600000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 10000,
  message: { error: 'Demasiadas peticiones' }
});
app.use(apiLimiter);

// Middleware de autenticación JWT para sistema de juego
function authenticateJWT(req, res, next) {
  let token = req.cookies.token;
  if (!token) {
    const auth = req.header('Authorization') || '';
    if (auth.startsWith('Bearer ')) token = auth.split(' ')[1];
  }
  if (!token) return res.status(401).json({ error: 'No autenticado' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = payload;
    next();
  });
}

// ─────────────────────────────────────────────────────────────────
// RUTAS DE AUTENTICACIÓN EIP-712 (Web3) MEJORADAS
// ─────────────────────────────────────────────────────────────────

// RUTA: Obtener nonce
app.get('/api/auth/nonce', async (req, res) => {
  try {
    const rawAddress = String(req.query.address || '').trim();
    if (!rawAddress) return res.status(400).json({ error: 'Falta address' });

    const address = rawAddress.toLowerCase();
    if (!ethers.isAddress(address)) {
      return res.status(400).json({ error: 'Address inválida' });
    }

    const nonce = generateNonce();
    await User.findOneAndUpdate(
      { address },
      { 
        address, 
        nonce,
        lastLogin: new Date(),
        sessionValid: true
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    return res.json({ nonce });
  } catch (err) {
    console.error('GET /api/auth/nonce error', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// RUTA: Login EIP-712 MEJORADO
app.post('/api/auth/login', async (req, res) => {
  try {
    const { address, signature, token, message, remember } = req.body || {};

    if (!address || !signature || !token || !message) {
      return res.status(400).json({ error: 'Faltan parámetros requeridos' });
    }

    const lcAddress = String(address).toLowerCase();
    if (!ethers.isAddress(lcAddress)) {
      return res.status(400).json({ error: 'Address inválida' });
    }

    const user = await User.findOne({ address: lcAddress });
    if (!user || !user.nonce) {
      return res.status(400).json({ error: 'Usuario no encontrado o nonce inválido' });
    }

    const tokenParts = String(token).split(':');
    if (tokenParts.length !== 2) {
      return res.status(400).json({ error: 'Token con formato inválido' });
    }
    const [tokenNonce, tokenTsStr] = tokenParts;
    const tokenTs = Number(tokenTsStr) || 0;

    if (!tokenNonce || tokenNonce !== user.nonce) {
      return res.status(400).json({ error: 'Nonce inválido o ya usado' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - tokenTs) > MAX_TOKEN_AGE_SECONDS) {
      return res.status(400).json({ error: 'Token expirado' });
    }

    const expectedTokenBase64 = Buffer.from(`${tokenNonce}:${tokenTs}`).toString('base64');
    const expectedMessage = `Signing in to Grassland Forest: ${expectedTokenBase64}`;
    
    if (message !== expectedMessage) {
      return res.status(400).json({ error: 'Mensaje firmado no coincide' });
    }

    const domain = {
      name: EIP712_DOMAIN_BASE.name,
      version: EIP712_DOMAIN_BASE.version,
      chainId: EIP712_DOMAIN_BASE.chainId
    };

    const types = EIP712_TYPES_LOGIN;
    const value = { text: message };

    let recovered;
    try {
      recovered = ethers.verifyTypedData(domain, types, value, signature);
    } catch (verErr) {
      console.error('Error verificando typedData:', verErr);
      return res.status(400).json({ error: 'Error verificando firma' });
    }

    if (!recovered || recovered.toLowerCase() !== lcAddress) {
      return res.status(401).json({ error: 'Firma inválida' });
    }

    // INVALIDAR SESIONES ANTERIORES Y CREAR NUEVA
    await invalidateAllSessions(lcAddress);

    // Buscar datos del jugador
    const playerData = await Player.findOne({ address: lcAddress });

    // Crear nueva sesión
    const { jwtToken, expiresAt } = await createNewSession(lcAddress, remember);

    // Actualizar usuario con nuevo nonce
    user.nonce = generateNonce();
    user.lastLogin = new Date();
    user.sessionValid = true;
    await user.save();

    const cookieOptions = {
      httpOnly: true,
      path: '/',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
      secure: NODE_ENV === 'production',
      expires: expiresAt
    };

    res.cookie('token', jwtToken, cookieOptions);

    console.log('LOGIN: set-cookie options:', cookieOptions);
    console.log('LOGIN: request origin:', req.headers.origin);
    console.log('LOGIN: request headers:', {
      cookie: req.headers.cookie,
      host: req.headers.host,
      referer: req.headers.referer,
      userAgent: req.headers['user-agent']
    });


    const respBody = {
      success: true,
      address: lcAddress,
      playerName: playerData ? playerData.playerName : null,
      message: 'Login exitoso',
      remember: remember
    };

    if (NODE_ENV !== 'production') {
      respBody.token = jwtToken;
    }

    return res.json(respBody);
  } catch (err) {
    console.error('POST /api/auth/login error', err);
    return res.status(500).json({ error: 'Error en autenticación' });
  }
});

// RUTA: me MEJORADA - Manejo robusto de sesiones
app.get('/api/auth/me', async (req, res) => {
  console.log('ME: cookies present:', req.cookies && Object.keys(req.cookies));
  console.log('ME: request origin:', req.headers.origin);
  console.log('ME: incoming cookies header:', req.headers.cookie);
  console.log('ME: parsed req.cookies keys:', req.cookies ? Object.keys(req.cookies) : []);

  try {
    let token = req.cookies?.token;

    // Si no hay cookie, buscar en header Authorization
    if (!token) {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }

    if (!token) {
      return res.status(200).json({
        authenticated: false,
        message: 'No token provided'
      });
    }

    // Decodificar token para obtener address
    let decoded;
    try {
      decoded = jwt.decode(token);
    } catch (e) {
      res.clearCookie('token', { path: '/' });
      return res.status(200).json({
        authenticated: false,
        message: 'Invalid token format'
      });
    }

    if (!decoded || !decoded.address) {
      res.clearCookie('token', { path: '/' });
      return res.status(200).json({
        authenticated: false,
        message: 'No address in token'
      });
    }

    // Validar sesión en base de datos
    const validPayload = await validateAndRefreshSession(token, decoded.address);

    if (!validPayload) {
      res.clearCookie('token', { path: '/' });
      await invalidateAllSessions(decoded.address);
      return res.status(200).json({
        authenticated: false,
        message: 'Session expired or invalid'
      });
    }

    // Si hay nuevo token, enviarlo en la respuesta
    if (validPayload.newToken) {
      const cookieOptions = {
        httpOnly: true,
        path: '/',
        sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
        secure: NODE_ENV === 'production',
        expires: new Date(Date.now() + (validPayload.remember ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000))
      };
      res.cookie('token', validPayload.newToken, cookieOptions);
    }

    // Sesión válida - obtener datos del usuario
    const user = await User.findOne({ address: validPayload.address });
    const playerData = await Player.findOne({ address: validPayload.address });

    if (!user || !user.sessionValid) {
      res.clearCookie('token', { path: '/' });
      return res.status(200).json({
        authenticated: false,
        message: 'User session invalidated'
      });
    }

    return res.json({
      authenticated: true,
      address: validPayload.address,
      playerName: playerData ? playerData.playerName : null,
      lastLogin: user.lastLogin,
      tokenRefreshed: !!validPayload.newToken
    });
  } catch (err) {
    console.error('Error in /api/auth/me:', err);
    res.clearCookie('token', { path: '/' });
    return res.status(200).json({
      authenticated: false,
      message: 'Authentication service error'
    });
  }
});

// RUTA: logout MEJORADO
app.post('/api/auth/logout', async (req, res) => {
  try {
    const token = req.cookies?.token;
    
    if (token) {
      try {
        const payload = jwt.decode(token);
        if (payload && payload.address) {
          await invalidateAllSessions(payload.address);
          
          await User.findOneAndUpdate(
            { address: payload.address },
            { sessionValid: false }
          );
        }
      } catch (e) {
        console.log('Error during logout cleanup:', e);
      }
    }
    
    res.clearCookie('token', { path: '/' });
    return res.json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (err) {
    console.error('Logout error:', err);
    res.clearCookie('token', { path: '/' });
    return res.json({ success: true });
  }
});

// RUTA: health check mejorado
app.get('/api/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    const healthData = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      database: dbStatus,
      version: process.env.npm_package_version || '1.0.0'
    };

    res.status(200).json(healthData);
  } catch (error) {
    console.error('Health check error:', error);
    res.status(503).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: 'Service unavailable'
    });
  }
});



// ─────────────────────────────────────────────────────────────────
// RUTAS DEL SISTEMA DE JUEGO
// ─────────────────────────────────────────────────────────────────

const api = express.Router();
app.use('/api', api);

// POST /api/auth → login + registro de datos (sistema tradicional)
api.post('/auth', 
  body('playerName').isString().notEmpty(), 
  async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { playerName } = req.body;
  const now = new Date();
  const ip = req.clientIp;
  const ua = req.useragent.source;

  const geo = geoip.lookup(ip) || {};
  const tlsFp = extractTlsFingerprint(req.socket);

  let doc = await UserActivity.findOne({ playerName });
  if (!doc) doc = new UserActivity({ playerName });

  doc.ip = ip;
  doc.geo = {
    country: geo.country,
    region: geo.region,
    city: geo.city,
    latitude: geo.ll?.[0],
    longitude: geo.ll?.[1],
    timezone: geo.timezone,
    asn: geo.asn,
    isp: geo.isp,
    proxy: geo.proxy,
    tor: geo.tor
  };
  doc.headers = {
    userAgent: ua,
    acceptLang: req.headers['accept-language'],
    secCHUA: req.headers['sec-ch-ua'],
    secCHUAMobile: req.headers['sec-ch-ua-mobile'],
    secCHUAPlatform: req.headers['sec-ch-ua-platform'],
    tlsFingerprint: tlsFp
  };
  doc.loginCount++;
  doc.lastLogin = now;
  doc.sessions.push({ connectedAt: now });

  await doc.save();
  await ConnectedUser.findOneAndUpdate({ playerName }, { connectedAt: now }, { upsert: true });

  const token = jwt.sign({ playerName }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 3600000
  });
  res.json({ success: true, token });
});

// POST /api/logout → cerrar sesión
api.post('/logout', authenticateJWT, async (req, res) => {
  const playerName = req.user.playerName;
  const now = new Date();

  await ConnectedUser.deleteOne({ playerName });
  await UserActivity.updateOne(
    { playerName, 'sessions.disconnectedAt': { $exists: false } },
    { $set: { 'sessions.$.disconnectedAt': now } }
  );

  res.clearCookie('token');
  res.json({ success: true });
});

// 💾 Guardar progreso
api.post('/save/:playerName', apiLimiter, authenticateJWT,
  param('playerName').isString().notEmpty(),
  body('inventory').isArray(),
  body('chest').isArray(),
  async (req, res) => {
    const { playerName } = req.params;
    if (req.user.playerName !== playerName)
      return res.status(403).json({ error: 'No autorizado' });

    const update = req.body;
    try {
      let p = await Player.findOne({ playerName });
      if (p) { Object.assign(p, update); await p.save(); }
      else { p = new Player({ playerName, ...update }); await p.save(); }
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: e.message });
    }
  }
);

// 📦 Cargar datos
api.get('/load/:playerName', apiLimiter, authenticateJWT,
  param('playerName').isString().notEmpty(),
  async (req, res) => {
    const { playerName } = req.params;
    if (req.user.playerName !== playerName)
      return res.status(403).json({ error: 'No autorizado' });

    try {
      let p = await Player.findOne({ playerName });
      if (!p) { p = new Player({ playerName }); await p.save(); }
      let a = await Admin.findById('config');
      if (!a) { a = new Admin(); await a.save(); }
      res.json({ ...p.toObject(), hora: a.hora, dia_noche: a.dia_noche });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: e.message });
    }
  }
);

// ─────────────────────────────────────────────────────────────────
// RUTAS MARKETPLACE
// ─────────────────────────────────────────────────────────────────

const commissionRates = {
  Semilla: 0.01,
  Regadera: 0.02,
  Tijeras: 0.015,
  default: 0.02
};

api.get('/listingsx/:id', apiLimiter, authenticateJWT, async (req, res) => {
  try {
    const listings = await Listing.find().sort({ price: 1, createdAt: -1 });
    return res.json(listings);
  } catch (err) {
    console.error('Error en GET /listings:', err);
    return res.status(500).json({ error: err.message });
  }
});

api.get('/listings/:id',
  apiLimiter,
  authenticateJWT,
  param('id').isMongoId(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const listingId = req.params.id;
    try {
      const listing = await Listing.findById(listingId).lean();
      if (!listing) {
        return res.status(404).json({ error: 'Listing no encontrado' });
      }
      if (listing.owner !== req.user.playerName) {
        return res.status(403).json({ error: 'No tienes permiso para ver este listing' });
      }
      return res.json({
        id: listing._id,
        inventoryId: listing.inventoryId,
        name: listing.name,
        type: listing.type,
        quantity: listing.qty,
        price: listing.price,
        imageUrl: listing.imageUrl,
        createdAt: listing.createdAt
      });
    } catch (e) {
      console.error('Error en GET /listings/:id:', e);
      return res.status(500).json({ error: 'Error interno al obtener listing' });
    }
  }
);

api.post(
  '/listingsx/:id',
  apiLimiter,
  authenticateJWT,
  [
    body('inventoryId').isString().notEmpty(),
    body('name').isString().notEmpty(),
    body('type').isString().notEmpty(),
    body('qty').isInt({ min: 1 }),
    body('price').isFloat({ min: 0 }),
    body('imageUrl').optional().isString()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const owner = req.user.playerName;
    const { inventoryId, name, type, qty, price, imageUrl } = req.body;

    try {
      const newListing = new Listing({
        owner,
        inventoryId,
        name,
        type,
        qty,
        price,
        imageUrl: imageUrl || ''
      });
      await newListing.save();
      return res.status(201).json(newListing);
    } catch (err) {
      console.error('Error en POST /listings:', err);
      return res.status(500).json({ error: err.message });
    }
  }
);

api.post(
  '/listings/:id/buy',
  apiLimiter,
  authenticateJWT,
  param('id').isMongoId(),
  body('quantity').isInt({ min: 1 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (errors.isEmpty && !errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const listingId = req.params.id;
    const quantity = parseInt(req.body.quantity, 10);

    try {
      const listing = await Listing.findById(listingId);
      if (!listing) {
        return res.status(404).json({ error: 'Listing no encontrado' });
      }
      if (listing.owner === req.user.playerName) {
        return res.status(400).json({ error: 'No puedes comprar tu propio listing' });
      }
      if (quantity > listing.qty) {
        return res.status(400).json({ error: `Cantidad solicitada (${quantity}) excede la disponible (${listing.qty})` });
      }
      const [buyer, seller] = await Promise.all([
        Player.findOne({ playerName: req.user.playerName }),
        Player.findOne({ playerName: listing.owner })
      ]);
      if (!buyer) return res.status(404).json({ error: 'Comprador no existe' });
      if (!seller) return res.status(404).json({ error: 'Vendedor no existe' });

      const total = listing.price * quantity;
      const rate = commissionRates[listing.type] ?? commissionRates.default;
      const comm = total * rate;
      if (buyer.moneda < total) return res.status(400).json({ error: 'Fondos insuficientes' });

      buyer.moneda -= total;
      seller.moneda += (total - comm);
      listing.qty -= quantity;
      const saveOps = [];
      saveOps.push(buyer.save());
      saveOps.push(seller.save());
      if (listing.qty <= 0) saveOps.push(Listing.findByIdAndDelete(listingId));
      else saveOps.push(listing.save());
      await Promise.all(saveOps);

      return res.json({
        success: true,
        totalCost: total,
        commission: comm,
        netToSeller: total - comm,
        commissionRate: rate,
        remainingQty: listing.qty
      });
    } catch (e) {
      console.error('Error en POST /listings/:id/buy →', e);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

api.delete(
  '/listings/:id',
  apiLimiter,
  authenticateJWT,
  param('id').isMongoId(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const listingId = req.params.id;
    try {
      const l = await Listing.findById(listingId);
      if (!l) return res.status(404).json({ error: 'Not found' });
      if (l.owner !== req.user.playerName) return res.status(403).json({ error: 'No autorizado' });
      await Listing.findByIdAndDelete(listingId);
      return res.json({ success: true });
    } catch (e) {
      console.error('DELETE /listings/:id error:', e);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

// ─────────────────────────────────────────────────────────────────
// MANEJO DE ERRORES Y INICIO DEL SERVIDOR
// ─────────────────────────────────────────────────────────────────

// 404 handler
app.use((req, res) => res.status(404).json({ error: `Ruta no encontrada: ${req.method} ${req.originalUrl}` }));

// Error handler
app.use((err, req, res, next) => {
  console.error('Error no manejado:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Graceful shutdown
process.on('SIGTERM', () => mongoose.disconnect().then(() => process.exit(0)));

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Backend MEJORADO activo en http://0.0.0.0:${PORT}`);
  console.log(`🔐 Autenticación EIP-712: MEJORADA con manejo de sesiones`);
  console.log(`🛡️  CORS: Configurado silenciosamente`);
  console.log(`💾 Sesiones: Persistidas en base de datos`);
});