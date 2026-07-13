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

const SimpleMessageLoggerArtifact = require('./models/SimpleMessageLogger.json');

// ─────────────────────────────────────────────────────────────────
// CONFIGURACIÓN DE SEGURIDAD Y BLOCKCHAIN
// ─────────────────────────────────────────────────────────────────

const networkname = "Somnia Testnet";
const nameurlexplorer = "https://shannon-explorer.somnia.network"

const SECURITY_CONFIG = {
    CHAIN_ID: 50312,
    RPC_URL: process.env.RPC_URL || "https://dream-rpc.somnia.network",
    MAX_MESSAGE_LENGTH: 200,
    MAX_TRANSACTIONS_PER_HOUR: 50,
    MIN_NONCE_INCREMENT: 1,
    ACCESS_TOKEN_EXPIRY: '24h',
    REFRESH_TOKEN_EXPIRY: '7d',
    RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000,
    RATE_LIMIT_MAX_REQUESTS: 100
};

const ALLOWED_CONTRACTS = {
    '0x52f269b242121ed0b80aed7d7a35f1db5b111c73': {
        name: "SimpleMessageLogger",
        functions: ['logMessage', 'getMessage', 'messageCount'],
        abi: SimpleMessageLoggerArtifact.abi
    }
};

const vetAgent = new https.Agent({ keepAlive: true, maxSockets: 10 });
const vetProvider = new ethers.JsonRpcProvider(SECURITY_CONFIG.RPC_URL);
const web3 = new Web3(new Web3.providers.HttpProvider(SECURITY_CONFIG.RPC_URL, { agent: vetAgent }));

const EIP712_DOMAIN_BASE = {
  name: 'Grassland Forest',
  version: '1',
  chainId: SECURITY_CONFIG.CHAIN_ID
};

const EIP712_TYPES_LOGIN = {
  Login: [{ name: 'text', type: 'string' }]
};

const MAX_TOKEN_AGE_SECONDS = Number(process.env.MAX_TOKEN_AGE_SECONDS || 10 * 60);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://grasslandforest.xyz/';
const NODE_ENV = process.env.NODE_ENV || 'development';

const JWT_CONFIG = {
  accessToken: {
    expiresIn: SECURITY_CONFIG.ACCESS_TOKEN_EXPIRY,
    type: 'access'
  },
  refreshToken: {
    expiresIn: SECURITY_CONFIG.REFRESH_TOKEN_EXPIRY,
    type: 'refresh'
  }
};

// ─────────────────────────────────────────────────────────────────
// CONFIGURACIÓN ETHERJS PARA TRANSACCIONES REALES
// ─────────────────────────────────────────────────────────────────

let relayerWallet = null;
let relayerAddress = null;

if (RELAYER_PRIVATE_KEY) {
    try {
        relayerWallet = new ethers.Wallet(RELAYER_PRIVATE_KEY, vetProvider);
        relayerAddress = relayerWallet.address;
        console.log(`✅ Relayer configurado: ${relayerAddress}`);
    } catch (error) {
        console.error('❌ Error configurando relayer:', error);
    }
} else {
    console.warn('⚠️  No hay RELAYER_PRIVATE_KEY - Las transacciones serán simuladas');
}

let simpleLoggerContract = null;
if (relayerWallet && ALLOWED_CONTRACTS['0x52f269b242121ed0b80aed7d7a35f1db5b111c73']) {
    try {
        simpleLoggerContract = new ethers.Contract(
            '0x52f269b242121ed0b80aed7d7a35f1db5b111c73',
            ALLOWED_CONTRACTS['0x52f269b242121ed0b80aed7d7a35f1db5b111c73'].abi,
            relayerWallet
        );
        console.log(`✅ Contrato SimpleMessageLogger inicializado: 0x52f269b242121ed0b80aed7d7a35f1db5b111c73`);
    } catch (error) {
        console.error('❌ Error inicializando contrato:', error);
    }
}

// ─────────────────────────────────────────────────────────────────
// MODELOS MONGOOSE
// ─────────────────────────────────────────────────────────────────

const userSchema = new mongoose.Schema({
  address: { type: String, required: true, unique: true, lowercase: true },
  nonce: { type: String, required: true },
  playerName: { type: String, unique: true, sparse: true },
  lastLogin: { type: Date, default: Date.now },
  transactionCount: { type: Number, default: 0 },
  lastTransaction: { type: Date }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

const transactionSchema = new mongoose.Schema({
    playerName: { type: String, required: true },
    address: { type: String, required: true, lowercase: true },
    action: { type: String, required: true },
    contract: { type: String, required: true },
    contractAddress: { type: String, required: true },
    details: { type: Object, required: true },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, default: 'completed' },
    txHash: { type: String },
    blockNumber: { type: Number },
    nonceUsed: { type: String },
    ip: { type: String },
    userAgent: { type: String },
    gasUsed: { type: String },
    gasPrice: { type: String },
    actualCost: { type: String }
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', transactionSchema);

const adminSchema = new mongoose.Schema({
  _id: { type: String, default: 'config' },
  hora: { type: String, default: '00:00:00' },
  dia_noche: { type: String, default: 'dia' }
});
const Admin = mongoose.model('Admin', adminSchema);

// ─────────────────────────────────────────────────────────────────
// ESQUEMA RECOLECCIÓN DE AGUA (NUEVO)
// ─────────────────────────────────────────────────────────────────

const waterCollectionSchema = new mongoose.Schema({
  playerName: { 
    type: String, 
    required: true, 
    unique: true,
    index: true 
  },
  collectionCount: { type: Number, default: 0 },
  lastCollectionTime: { type: Date, default: null },
  nextAvailableTime: { type: Date, default: null },
  dailyResetTime: { type: Date, default: null },
  collectionCycle: { type: Number, default: 0 },
  isDailyLimitReached: { type: Boolean, default: false },
  totalCollectionsToday: { type: Number, default: 0 }
}, { timestamps: true });

const WaterCollection = mongoose.model('WaterCollection', waterCollectionSchema);

// ─────────────────────────────────────────────────────────────────
// ESQUEMA MISSIONS PLAYER
// ─────────────────────────────────────────────────────────────────

const missionsPlayerSchema = new mongoose.Schema({
  playerName: { 
    type: String, 
    required: true, 
    unique: true,
    index: true 
  },
  misionesCompletadas: { type: Number, default: 0 },
  misionesEnProgreso: { type: Number, default: 0 },
  misionesFallidas: { type: Number, default: 0 },
  misiones_granjero: { type: Number, default: 0 },
  estadomision: { type: Number, default: 0 },
  misiones_guardian: { type: Number, default: 0 },
  estadomision1: { type: Number, default: 0 },
}, { timestamps: true });

const MissionsPlayer = mongoose.model('MissionsPlayer', missionsPlayerSchema);

const playerSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true },
  posicionplayerx: { type: Number, default: 2097 },
  posicionplayery: { type: Number, default: 2359 },
  vidaPorcentaje: { type: Number, default: 100 },
  aguaPorcentaje: { type: Number, default: 100 },
  comidaPorcentaje: { type: Number, default: 100 },
  speed: { type: Number, default: 3.6 },
  mundo: { type: Number, default: 1 },
  moneda: { type: Number, default: 0 },
  Username: { type: String, default: '---' },
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
  address: { type: String, lowercase: true }
});
const Player = mongoose.model('Player', playerSchema);

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

const refreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  address: { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true },
  userAgent: { type: String },
  ip: { type: String }
}, { timestamps: true });

refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);

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
  }
}, { timestamps: true });
const UserActivity = mongoose.model('UserActivity', activitySchema);

const connectedSchema = new mongoose.Schema({ 
  playerName: String, 
  connectedAt: { type: Date, default: Date.now } 
});
const ConnectedUser = mongoose.model('ConnectedUser', connectedSchema);

// ─────────────────────────────────────────────────────────────────
// CONTROLADOR DE RECOLECCIÓN DE AGUA (NUEVO)
// ─────────────────────────────────────────────────────────────────

class WaterCollectionController {
  constructor(io) {
    this.io = io;
    this.startDailyResetTimer();
  }

  startDailyResetTimer() {
    setInterval(async () => {
      const now = new Date();
      const currentHour = now.getHours();
      
      if (currentHour === 0) {
        await WaterCollection.updateMany(
          {},
          {
            collectionCount: 0,
            totalCollectionsToday: 0,
            isDailyLimitReached: false,
            dailyResetTime: now,
            collectionCycle: 0
          }
        );
        console.log('🔄 Reset diario de recolección de agua ejecutado');
      }
    }, 3600000);
  }

  async canCollectWater(playerName) {
    try {
      let record = await WaterCollection.findOne({ playerName });
      
      if (!record) {
        record = new WaterCollection({
          playerName,
          dailyResetTime: new Date()
        });
        await record.save();
      }

      const now = new Date();
      
      if (record.dailyResetTime) {
        const lastReset = new Date(record.dailyResetTime);
        const daysDiff = Math.floor((now - lastReset) / (1000 * 60 * 60 * 4));
        
        if (daysDiff >= 1) {
          record.collectionCount = 0;
          record.totalCollectionsToday = 0;
          record.isDailyLimitReached = false;
          record.collectionCycle = 0;
          record.dailyResetTime = now;
          await record.save();
        }
      }

      if (record.totalCollectionsToday >= 5) {
        return {
          canCollect: false,
          reason: 'Límite diario alcanzado.',
          nextAvailable: record.dailyResetTime ? 
            new Date(record.dailyResetTime.getTime() + 4 * 60 * 60 * 1000) : 
            new Date(now.getTime() + 4 * 60 * 60 * 1000),
          collectionCycle: record.collectionCycle,
          collectionsToday: record.totalCollectionsToday
        };
      }

      if (record.nextAvailableTime && now < record.nextAvailableTime) {
        const remainingMs = record.nextAvailableTime - now;
        const remainingMinutes = Math.ceil(remainingMs / (1000 * 60));
        
        return {
          canCollect: false,
          reason: `Debes esperar ${remainingMinutes} minutos para la siguiente recolección`,
          nextAvailable: record.nextAvailableTime,
          collectionCycle: record.collectionCycle,
          collectionsToday: record.totalCollectionsToday
        };
      }

      return {
        canCollect: true,
        reason: 'Puedes recolectar agua',
        collectionCycle: record.collectionCycle,
        collectionsToday: record.totalCollectionsToday
      };
    } catch (error) {
      throw error;
    }
  }

  async collectWater(playerName) {
    try {
      const check = await this.canCollectWater(playerName);
      
      if (!check.canCollect) {
        throw new Error(check.reason);
      }

      let record = await WaterCollection.findOne({ playerName });
      if (!record) {
        record = new WaterCollection({ playerName });
      }

      const now = new Date();
      const nextCollection = new Date(now.getTime() + 10 * 60 * 1000);
      
      record.collectionCount += 1;
      record.totalCollectionsToday += 1;
      record.lastCollectionTime = now;
      record.nextAvailableTime = nextCollection;
      record.collectionCycle = (record.collectionCycle + 1) % 5;
      
      if (record.totalCollectionsToday >= 5) {
        record.isDailyLimitReached = true;
        record.nextAvailableTime = new Date(now.getTime() + 4 * 60 * 60 * 1000);
      }
      
      await record.save();

      this.io.emit('waterCollected', {
        playerName,
        collectionCycle: record.collectionCycle,
        collectionsToday: record.totalCollectionsToday,
        nextAvailableTime: record.nextAvailableTime,
        isDailyLimitReached: record.isDailyLimitReached,
        timestamp: now
      });

      return {
        success: true,
        message: 'Agua recolectada exitosamente',
        collectionCycle: record.collectionCycle,
        collectionsToday: record.totalCollectionsToday,
        nextAvailableTime: record.nextAvailableTime,
        isDailyLimitReached: record.isDailyLimitReached,
        waterAmount: 10
      };
    } catch (error) {
      throw error;
    }
  }

  async getWaterCollectionStatus(playerName) {
    try {
      let record = await WaterCollection.findOne({ playerName });
      
      if (!record) {
        record = new WaterCollection({
          playerName,
          dailyResetTime: new Date()
        });
        await record.save();
      }

      const now = new Date();
      let nextAvailable = record.nextAvailableTime;
      let remainingMinutes = 0;
      
      if (nextAvailable && now < nextAvailable) {
        remainingMinutes = Math.ceil((nextAvailable - now) / (1000 * 60));
      }

      return {
        playerName,
        collectionCycle: record.collectionCycle,
        collectionsToday: record.totalCollectionsToday,
        lastCollectionTime: record.lastCollectionTime,
        nextAvailableTime: record.nextAvailableTime,
        isDailyLimitReached: record.isDailyLimitReached,
        dailyResetTime: record.dailyResetTime,
        remainingMinutes: remainingMinutes,
        canCollect: !record.isDailyLimitReached && (!nextAvailable || now >= nextAvailable)
      };
    } catch (error) {
      throw error;
    }
  }
}

// Inicializar controlador
let waterCollectionController = null;

// ─────────────────────────────────────────────────────────────────
// FUNCIONES AUXILIARES MEJORADAS - SISTEMA DE TOKENS
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

function generateAccessToken(address) {
  return jwt.sign(
    { 
      address: address.toLowerCase(),
      type: JWT_CONFIG.accessToken.type,
      timestamp: Date.now()
    },
    JWT_SECRET,
    { expiresIn: JWT_CONFIG.accessToken.expiresIn }
  );
}

function generateRefreshToken(address) {
  return jwt.sign(
    { 
      address: address.toLowerCase(),
      type: JWT_CONFIG.refreshToken.type,
      timestamp: Date.now()
    },
    JWT_SECRET,
    { expiresIn: JWT_CONFIG.refreshToken.expiresIn }
  );
}

async function saveRefreshToken(token, address, req) {
  const decoded = jwt.decode(token);
  const expiresAt = new Date(decoded.exp * 1000);
  
  await RefreshToken.create({
    token: crypto.createHash('sha256').update(token).digest('hex'),
    address: address.toLowerCase(),
    expiresAt,
    userAgent: req.headers['user-agent'],
    ip: req.clientIp
  });
}

async function verifyAndRotateRefreshToken(token, address, req) {
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    
    if (payload.type !== JWT_CONFIG.refreshToken.type) {
      throw new Error('Invalid token type');
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const storedToken = await RefreshToken.findOne({ 
      token: tokenHash,
      address: address.toLowerCase()
    });

    if (!storedToken) {
      throw new Error('Refresh token not found');
    }

    if (storedToken.expiresAt < new Date()) {
      await RefreshToken.deleteOne({ _id: storedToken._id });
      throw new Error('Refresh token expired');
    }

    await RefreshToken.deleteOne({ _id: storedToken._id });
    
    const newRefreshToken = generateRefreshToken(address);
    await saveRefreshToken(newRefreshToken, address, req);
    
    const newAccessToken = generateAccessToken(address);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      payload
    };
  } catch (error) {
    await RefreshToken.deleteMany({ 
      address: address.toLowerCase(),
      expiresAt: { $lt: new Date() }
    });
    throw error;
  }
}

async function validateAccessToken(token) {
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    
    if (payload.type !== JWT_CONFIG.accessToken.type) {
      throw new Error('Invalid token type');
    }

    return payload;
  } catch (error) {
    throw error;
  }
}

async function invalidateAllRefreshTokens(address) {
  await RefreshToken.deleteMany({ address: address.toLowerCase() });
}

async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const payload = await validateAccessToken(token);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired access token' });
  }
}

async function authenticateTokenWithPlayer(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const payload = await validateAccessToken(token);
    req.user = payload;
    
    const user = await User.findOne({ address: payload.address });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    req.user.playerName = user.playerName;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired access token' });
  }
}

// ─────────────────────────────────────────────────────────────────
// MIDDLEWARES DE SEGURIDAD MEJORADOS - CORREGIDOS
// ─────────────────────────────────────────────────────────────────

const strictLimiter = rateLimit({
    windowMs: SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS,
    max: SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS,
    message: { error: 'Demasiadas peticiones. Por favor espera.' },
    standardHeaders: true,
    legacyHeaders: false
});

const transactionLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: SECURITY_CONFIG.MAX_TRANSACTIONS_PER_HOUR,
    message: { error: 'Límite de transacciones por hora excedido' },
    keyGenerator: (req) => {
        if (req.user && req.user.address) {
            return `user_${req.user.address}`;
        }
        if (typeof rateLimit.ipKeyGenerator === 'function') {
            return rateLimit.ipKeyGenerator(req);
        }
        return req.ip;
    }
});

function validateContract(contractAddress, action) {
    const addressLower = contractAddress.toLowerCase();
    const contract = ALLOWED_CONTRACTS[addressLower];
    
    if (!contract) {
        throw new Error(`Tipo de contrato no soportado: ${contractAddress}`);
    }
    
    if (!contract.functions.includes(action)) {
        throw new Error(`Acción no permitida para este contrato: ${action}`);
    }
    
    return contract;
}

function normHexNoPrefix(h) {
  if (!h) return '';
  return String(h).toLowerCase().replace(/^0x/, '');
}

function validateNonce(userNonce, storedNonce) {
  try {
    const u = normHexNoPrefix(userNonce);
    const s = normHexNoPrefix(storedNonce);
    
    console.log(`🔍 Validando nonce - Usuario: ${u}, Almacenado: ${s}`);

    if (u !== s) {
      throw new Error(`Nonce incorrecto. Se esperaba: ${s}, se recibió: ${u}`);
    }
    
    return true;
  } catch (error) {
    throw new Error(`Nonce inválido: ${error.message}`);
  }
}

// ─────────────────────────────────────────────────────────────────
// CONFIGURACIÓN EXPRESS Y SOCKET.IO - CORREGIDA
// ─────────────────────────────────────────────────────────────────

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = [
  'https://grasslandforest.xyz',
  FRONTEND_ORIGIN
].filter(Boolean);

// SOLUCIÓN AL ERROR CORS: Configuración mejorada de CORS
app.use(cors({
  origin: function (origin, callback) {
    // Permitir solicitudes sin origen (como aplicaciones móviles o curl)
    if (!origin) {
      console.log('🔓 Solicitud sin origen permitida (app móvil/curl)');
      return callback(null, true);
    }
    
    // En desarrollo, permitir cualquier origen
    if (NODE_ENV !== 'production') {
      console.log(`🟢 Desarrollo: Origen permitido - ${origin}`);
      return callback(null, true);
    }
    
    // En producción, verificar contra la lista blanca
    if (allowedOrigins.indexOf(origin) !== -1) {
      console.log(`🟢 Producción: Origen permitido - ${origin}`);
      return callback(null, true);
    }
    
    // Si el origen no está en la lista, registrar para análisis
    console.warn(`🚨 Origen bloqueado por CORS: ${origin}`);
    console.warn(`📋 Orígenes permitidos: ${allowedOrigins.join(', ')}`);
    
    // En producción, rechazar el origen no permitido
    return callback(new Error('Not allowed by CORS'), false);
  },
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
}));

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

app.options('*', cors());

const server = http.createServer(app);

// ✅ CONFIGURACIÓN CORRECTA DE SOCKET.IO - CORRECCIÓN CRÍTICA
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000
});

// ✅ SERVIR EL CLIENTE DE SOCKET.IO MANUALMENTE
app.get('/socket.io/socket.io.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.sendFile(require.resolve('socket.io-client/dist/socket.io.js'));
});

app.get('/socket.io/socket.io.js.map', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.sendFile(require.resolve('socket.io-client/dist/socket.io.js.map'));
});

global.io = io;

// Variable para rastrear conexiones
const connectedSockets = new Map();

// Inicializar controlador de recolección de agua
waterCollectionController = new WaterCollectionController(io);

// ─────────────────────────────────────────────────────────────────
// SOCKET.IO HANDLERS MEJORADOS - CORREGIDOS
// ─────────────────────────────────────────────────────────────────

let players = {};
let chatHistory = [];
const MAX_HISTORY = 50;

// Estructura para manejar múltiples salas
const rooms = {
  'game': {},
  'tienda': {}
};

function escapeHtml(text = '') {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

io.on("connection", (socket) => {
  console.log(`🔗 Nueva conexión Socket.io: ${socket.id}`);
  connectedSockets.set(socket.id, socket);

  // Enviar evento de bienvenida
  socket.emit("connected", {
    message: "Conectado al servidor de juego",
    socketId: socket.id,
    timestamp: Date.now()
  });

  socket.playerData = {
    id: socket.id,
    room: null,
    username: '---',
    lastScene: null
  };

  // Eventos de recolección de agua
  socket.on('collectWater', async (data) => {
    try {
      const { playerName } = data;
      const result = await waterCollectionController.collectWater(playerName);
      socket.emit('collectWaterSuccess', result);
    } catch (error) {
      socket.emit('collectWaterError', { error: error.message });
    }
  });

  socket.on('getWaterCollectionStatus', async (data) => {
    try {
      const { playerName } = data;
      const status = await waterCollectionController.getWaterCollectionStatus(playerName);
      socket.emit('waterCollectionStatus', status);
    } catch (error) {
      socket.emit('waterStatusError', { error: error.message });
    }
  });

  socket.on("joinRoom", (data) => {
    const { room, username, lastScene } = data;
    
    console.log(`🔵 joinRoom solicitado: ${socket.id} -> ${room}, último escena: ${lastScene}`);
    
    if (!room || !username) {
      socket.emit("error", { message: "Datos de sala inválidos" });
      return;
    }

    // Si ya está en una sala y no está cambiando de escena, ignorar
    if (socket.playerData.room === room && socket.playerData.lastScene === lastScene) {
      console.log(`🟡 ${socket.id} ya está en ${room}, ignorando join duplicado`);
      return;
    }

    // Salir de la sala anterior si existe
    if (socket.playerData.room && socket.playerData.room !== room) {
      console.log(`🔄 ${socket.id} saliendo de ${socket.playerData.room}`);
      
      if (rooms[socket.playerData.room]) {
        delete rooms[socket.playerData.room][socket.id];
        socket.leave(socket.playerData.room);
        
        if (Object.keys(rooms[socket.playerData.room]).length > 0) {
          io.to(socket.playerData.room).emit("playerLeft", { 
            id: socket.id,
            reason: 'changed_scene'
          });
        }
        
        io.to(socket.playerData.room).emit("playerCount", 
          Object.keys(rooms[socket.playerData.room]).length
        );
      }
    }
    
    // Actualizar datos del jugador
    socket.playerData.room = room;
    socket.playerData.username = username || '---';
    socket.playerData.lastScene = lastScene || 'unknown';
    
    // Inicializar sala si no existe
    if (!rooms[room]) {
      rooms[room] = {};
    }
    
    // Agregar jugador a la nueva sala
    rooms[room][socket.id] = {
      id: socket.id,
      x: 0,
      y: 0,
      username: username || '---',
      direction: 'right',
      directionx: 'stop_right',
      lastUpdate: Date.now()
    };
    
    socket.join(room);
    console.log(`✅ ${socket.id} unido a ${room} como ${username} (desde: ${lastScene})`);
    
    // Enviar jugadores actuales (excluyendo al propio jugador)
    const otherPlayers = Object.values(rooms[room]).filter(p => p.id !== socket.id);
    socket.emit("currentPlayers", otherPlayers);
    
    // Notificar a otros jugadores en la sala
    socket.to(room).emit("newPlayer", rooms[room][socket.id]);
    
    // Enviar contador actualizado
    io.to(room).emit("playerCount", Object.keys(rooms[room]).length);
    
    // Enviar jugadores de la sala
    const roomSockets = io.sockets.adapter.rooms.get(room);
    if (roomSockets) {
      const playersList = Array.from(roomSockets).map(socketId => {
        const s = connectedSockets.get(socketId);
        return {
          id: socketId,
          username: s?.playerData?.username || "Unknown"
        };
      });
      socket.emit("roomPlayers", { players: playersList });
    }
  });

  // EVENTO: Movimiento del jugador
  socket.on("playerMove", (data) => {
    const room = socket.playerData.room;
    if (!room || !rooms[room] || !rooms[room][socket.id]) return;
    
    rooms[room][socket.id] = {
      ...rooms[room][socket.id],
      ...data,
      isMoving: data.isMoving || false,
      lastUpdate: Date.now()
    };
    
    socket.to(room).emit("playerMoved", rooms[room][socket.id]);
  });

  // EVENTO: Chat
  socket.on('chatMessage', (payload) => {
    try {
      const room = socket.playerData.room;
      if (!room) return;
      
      const now = Date.now();
      if (now - (socket.chatLastSent || 0) < (socket.chatRateLimitMs || 1000)) {
        socket.emit('chatError', { msg: 'Demasiados mensajes. Espera un momento.' });
        return;
      }
      socket.chatLastSent = now;

      const playerName = escapeHtml(payload.usernamex || socket.playerData.username || '---');
      const text = escapeHtml(String(payload.text || '').trim()).slice(0, 500);
      if (!text) return;

      const message = {
        id: socket.id,
        playerName,
        text,
        ts: new Date().toISOString(),
        room: room
      };

      chatHistory.push(message);
      if (chatHistory.length > MAX_HISTORY) chatHistory.shift();

      io.to(room).emit('chatMessage', message);
    } catch (e) {
      console.error('chatMessage error:', e);
    }
  });

  // EVENTO: Solicitar historial
  socket.on('requestHistory', () => {
    try {
      socket.emit('chatHistory', chatHistory.slice(-MAX_HISTORY));
    } catch (e) {
      console.error('Error enviando chatHistory:', e);
    }
  });

  // Ping/Pong para mantener conexión
  socket.on("ping", (data) => {
    socket.emit("pong", {
      timestamp: Date.now(),
      serverTime: new Date().toISOString()
    });
  });

  // EVENTO: Desconexión
  socket.on("disconnect", () => {
    const room = socket.playerData.room;
    
    if (room && rooms[room]) {
      delete rooms[room][socket.id];
      
      io.to(room).emit("playerDisconnected", socket.id);
      io.to(room).emit("playerCount", Object.keys(rooms[room]).length);
      
      console.log(`❌ ${socket.id} desconectado de la sala: ${room}`);
    }
    
    connectedSockets.delete(socket.id);
  });

  // Error handling
  socket.on("error", (error) => {
    console.error(`❌ Error en socket ${socket.id}:`, error);
  });
});

// Middleware para verificar conexiones activas
app.get("/api/socket/status", (req, res) => {
  res.json({
    connectedSockets: connectedSockets.size,
    activeRooms: Array.from(io.sockets.adapter.rooms.keys()).filter(room => room !== ''),
    timestamp: Date.now()
  });
});

// ─────────────────────────────────────────────────────────────────
// CONEXIÓN MONGODB
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
  
  try {
    await RefreshToken.deleteMany({ expiresAt: { $lt: new Date() } });
    console.log('✔️ Tokens de refresco expirados limpiados');
  } catch (e) {
    console.log('Error limpiando tokens:', e);
  }
})
.catch(err => {
  console.error('❌ Error al conectar a MongoDB:', err);
  process.exit(1);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB desconectado');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconectado');
});

const apiLimiter = rateLimit({
  windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW) || 1) * 3600000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 10000,
  message: { error: 'Demasiadas peticiones' }
});
app.use(apiLimiter);

// ─────────────────────────────────────────────────────────────────
// FUNCIONES DE BLOCKCHAIN MEJORADAS
// ─────────────────────────────────────────────────────────────────

async function sendRealTransaction(userAddress, message, userNonceBigInt) {
    if (!relayerWallet || !simpleLoggerContract) {
        throw new Error('Sistema de blockchain no configurado correctamente');
    }

    try {
        console.log(`🔄 Enviando transacción real para: ${userAddress}`);

        const balance = await vetProvider.getBalance(relayerAddress);
        console.log(`💰 Saldo del relayer: ${ethers.formatEther(balance)} SON`);

        const gasEstimate = await simpleLoggerContract.logMessage.estimateGas(message, userNonceBigInt);
        const feeData = await vetProvider.getFeeData();

        const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas || 2n * 10n**9n;
        const maxFeePerGas = feeData.maxFeePerGas || (maxPriorityFeePerGas + 30n * 10n**9n);

        const gasLimit = gasEstimate + 20000n;

        if (balance < gasLimit * maxFeePerGas) {
            throw new Error('Relayer sin fondos suficientes para cubrir la transacción');
        }

        const tx = await simpleLoggerContract.logMessage(message, userNonceBigInt, {
            type: 2,
            gasLimit,
            maxPriorityFeePerGas,
            maxFeePerGas
        });

        console.log(`📤 Transacción enviada: ${tx.hash}`);

        const receipt = await tx.wait();
        console.log(`✅ Transacción confirmada en bloque: ${receipt.blockNumber}`);
        console.log(`🪙 Gas usado: ${receipt.gasUsed.toString()}`);

        let messageId = 0;
        for (const log of receipt.logs) {
            try {
                const parsedLog = simpleLoggerContract.interface.parseLog(log);
                if (parsedLog.name === 'MessageLogged') {
                    messageId = parsedLog.args.messageId.toString();
                    break;
                }
            } catch {}
        }

        return {
            success: true,
            txHash: tx.hash,
            blockNumber: receipt.blockNumber,
            gasUsed: receipt.gasUsed.toString(),
            messageId,
            actualCost: ethers.formatEther(receipt.gasUsed * (tx.maxFeePerGas || 0n))
        };
    } catch (error) {
        console.error('❌ Error en transacción real:', error);
        let msg = error.message || 'Error desconocido';
        if (error.code === 'INSUFFICIENT_FUNDS') msg = 'Relayer sin fondos suficientes';
        if (error.code === 'NETWORK_ERROR') msg = 'Error de conexión con la blockchain';
        throw new Error(msg);
    }
}

async function verifyTransaction(txHash) {
    try {
        const receipt = await vetProvider.getTransactionReceipt(txHash);
        
        if (!receipt) {
            return { status: 'pending', confirmations: 0 };
        }
        
        const currentBlock = await vetProvider.getBlockNumber();
        const confirmations = currentBlock - receipt.blockNumber;
        
        return {
            status: receipt.status === 1 ? 'confirmed' : 'failed',
            blockNumber: receipt.blockNumber,
            confirmations: confirmations,
            gasUsed: receipt.gasUsed.toString()
        };
    } catch (error) {
        console.error('Error verificando transacción:', error);
        return { status: 'unknown', error: error.message };
    }
}

// ─────────────────────────────────────────────────────────────────
// RUTAS DE AUTENTICACIÓN EIP-712 MEJORADAS
// ─────────────────────────────────────────────────────────────────

app.get('/api/auth/nonce', strictLimiter, async (req, res) => {
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
        lastLogin: new Date()
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    return res.json({ nonce });
  } catch (err) {
    console.error('GET /api/auth/nonce error', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/auth/login', strictLimiter, async (req, res) => {
  try {
    const { address, signature, token, message } = req.body || {};

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

    await invalidateAllRefreshTokens(lcAddress);

    const accessToken = generateAccessToken(lcAddress);
    const refreshToken = generateRefreshToken(lcAddress);
    
    await saveRefreshToken(refreshToken, lcAddress, req);

    const playerData = await Player.findOne({ address: lcAddress });

    const newNonce = (BigInt('0x' + user.nonce) + 1n).toString(16);
    user.nonce = newNonce;
    user.lastLogin = new Date();
    
    if (playerData && playerData.playerName && !user.playerName) {
      user.playerName = playerData.playerName;
      console.log(`🔄 Sincronizado playerName desde Player: ${playerData.playerName}`);
    }
    
    await user.save();

    return res.json({
      success: true,
      address: lcAddress,
      playerName: user.playerName || (playerData ? playerData.playerName : null),
      accessToken,
      refreshToken,
      newNonce: newNonce,
      message: 'Login exitoso'
    });
  } catch (err) {
    console.error('POST /api/auth/login error', err);
    return res.status(500).json({ error: 'Error en autenticación' });
  }
});

app.post('/api/auth/refresh', strictLimiter, async (req, res) => {
  try {
    const { refreshToken, address } = req.body;

    if (!refreshToken || !address) {
      return res.status(400).json({ error: 'Refresh token y address requeridos' });
    }

    const result = await verifyAndRotateRefreshToken(refreshToken, address, req);
    
    return res.json({
      success: true,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    });
  } catch (error) {
    console.error('Error refreshing token:', error);
    return res.status(403).json({ error: 'Invalid refresh token' });
  }
});

app.get('/api/auth/me', authenticateToken, strictLimiter, async (req, res) => {
  try {
    const user = await User.findOne({ address: req.user.address });
    const playerData = await Player.findOne({ address: req.user.address });

    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    if (playerData && playerData.playerName && !user.playerName) {
      user.playerName = playerData.playerName;
      await user.save();
      console.log(`🔄 Sincronizado playerName desde Player: ${playerData.playerName}`);
    }

    return res.json({
      authenticated: true,
      address: req.user.address,
      playerName: user.playerName || (playerData ? playerData.playerName : null),
      lastLogin: user.lastLogin,
      nonce: user.nonce
    });
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/auth/sync-playerName', authenticateToken, strictLimiter, async (req, res) => {
  try {
    const user = await User.findOne({ address: req.user.address });
    const playerData = await Player.findOne({ address: req.user.address });

    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    let updated = false;
    
    if (playerData && playerData.playerName && !user.playerName) {
      user.playerName = playerData.playerName;
      await user.save();
      updated = true;
      console.log(`🔄 Sincronizado playerName desde Player: ${playerData.playerName}`);
    }
    else if (user.playerName && (!playerData || !playerData.playerName)) {
      if (!playerData) {
        const newPlayer = new Player({
          playerName: user.playerName,
          address: req.user.address
        });
        await newPlayer.save();
      } else {
        playerData.playerName = user.playerName;
        await playerData.save();
      }
      updated = true;
      console.log(`🔄 Sincronizado playerName desde User: ${user.playerName}`);
    }

    return res.json({
      success: true,
      updated: updated,
      userPlayerName: user.playerName,
      playerPlayerName: playerData ? playerData.playerName : null,
      message: updated ? 'PlayerName sincronizado exitosamente' : 'No se requirió sincronización'
    });
  } catch (error) {
    console.error('Error sincronizando playerName:', error);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/auth/set-playerName', authenticateToken, strictLimiter, [
  body('playerName').isString().isLength({ min: 1, max: 50 })
], async (req, res) => {
  try {
    const validationErrors = validationResult(req);
    if (!validationErrors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validación fallida', 
        details: validationErrors.array() 
      });
    }

    const { playerName } = req.body;
    const user = await User.findOne({ address: req.user.address });
    
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const existingUser = await User.findOne({ 
      playerName: playerName,
      address: { $ne: req.user.address }
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'PlayerName ya está en uso por otro usuario' });
    }

    const existingPlayer = await Player.findOne({ 
      playerName: playerName,
      address: { $ne: req.user.address }
    });
    
    if (existingPlayer) {
      return res.status(400).json({ error: 'PlayerName ya está en uso en el juego por otro jugador' });
    }

    user.playerName = playerName;
    await user.save();

    let playerData = await Player.findOne({ address: req.user.address });
    if (playerData) {
      playerData.playerName = playerName;
      await playerData.save();
    } else {
      playerData = new Player({
        playerName: playerName,
        address: req.user.address
      });
      await playerData.save();
    }

    return res.json({
      success: true,
      playerName: playerName,
      message: 'PlayerName asignado exitosamente'
    });
  } catch (error) {
    console.error('Error asignando playerName:', error);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/auth/logout', strictLimiter, async (req, res) => {
  try {
    const { address } = req.body;
    
    if (address) {
      await invalidateAllRefreshTokens(address);
    }
    
    return res.json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/api/health', strictLimiter, async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    let blockchainStatus = 'disconnected';
    let relayerBalance = '0';
    
    try {
      await vetProvider.getBlockNumber();
      blockchainStatus = 'connected';
      
      if (relayerAddress) {
        const balance = await vetProvider.getBalance(relayerAddress);
        relayerBalance = ethers.formatEther(balance);
      }
    } catch (error) {
      blockchainStatus = 'error';
    }

    const healthData = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      database: dbStatus,
      blockchain: {
        status: blockchainStatus,
        network: networkname,
        chainId: SECURITY_CONFIG.CHAIN_ID,
        relayer: relayerAddress,
        relayerBalance: relayerBalance
      },
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

app.get('/api/transaction/status/:txHash', strictLimiter, async (req, res) => {
  try {
    const { txHash } = req.params;
    
    if (!txHash || !txHash.startsWith('0x')) {
      return res.status(400).json({ error: 'Hash de transacción inválido' });
    }

    const status = await verifyTransaction(txHash);
    
    return res.json({
      txHash,
      ...status
    });
  } catch (error) {
    console.error('Error verificando transacción:', error);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// ─────────────────────────────────────────────────────────────────
// RUTAS DE TRANSACCIONES SEGURAS - MEJORADAS CON BLOCKCHAIN REAL
// ─────────────────────────────────────────────────────────────────

app.get('/api/user/data', authenticateToken, strictLimiter, async (req, res) => {
    try {
        const user = await User.findOne({ address: req.user.address });
        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.json({
            address: req.user.address,
            playerName: user.playerName,
            nonce: user.nonce,
            lastLogin: user.lastLogin,
            transactionCount: user.transactionCount
        });
    } catch (error) {
        console.error('Error obteniendo datos usuario:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/contracts/allowed', authenticateToken, strictLimiter, (req, res) => {
    try {
        const contractsInfo = {};
        
        Object.keys(ALLOWED_CONTRACTS).forEach(key => {
            contractsInfo[key] = {
                name: ALLOWED_CONTRACTS[key].name,
                address: key,
                functions: ALLOWED_CONTRACTS[key].functions
            };
        });

        res.json({
            success: true,
            contracts: contractsInfo,
            chainId: SECURITY_CONFIG.CHAIN_ID,
            relayer: relayerAddress,
            network: networkname
        });
    } catch (error) {
        console.error('Error obteniendo contratos:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/config', strictLimiter, (req, res) => {
  res.json({
    onchainContractAddress: '0x52f269B242121ED0B80aed7d7A35f1db5B111C73',
    rpcUrl: SECURITY_CONFIG.RPC_URL,
    chainId: SECURITY_CONFIG.CHAIN_ID,
    maxMessageLength: SECURITY_CONFIG.MAX_MESSAGE_LENGTH,
    relayer: relayerAddress,
    network: networkname,
    explorer: nameurlexplorer,
    allowedContracts: Object.keys(ALLOWED_CONTRACTS).reduce((acc, key) => {
      acc[key] = {
        name: ALLOWED_CONTRACTS[key].name,
        address: key,
        functions: ALLOWED_CONTRACTS[key].functions
      };
      return acc;
    }, {})
  });
});

async function validateSimpleLoggerTransaction(parameters) {
    const { message } = parameters;
    
    if (!message || typeof message !== 'string') {
        return { valid: false, error: 'Mensaje requerido' };
    }
    
    if (message.length > SECURITY_CONFIG.MAX_MESSAGE_LENGTH) {
        return { 
            valid: false, 
            error: `Mensaje demasiado largo (máximo ${SECURITY_CONFIG.MAX_MESSAGE_LENGTH} caracteres)` 
        };
    }
    
    const dangerousPatterns = /[<>{}[\]]/;
    if (dangerousPatterns.test(message)) {
        return { valid: false, error: 'Mensaje contiene caracteres no permitidos' };
    }
    
    return { valid: true };
}

async function processSimpleLoggerTransaction(user, parameters) {
    const { message } = parameters;
    
    if (!relayerWallet || !simpleLoggerContract) {
        console.warn('⚠️  Modo simulación - No hay configuración de blockchain');
        return {
            message: message,
            length: message.length,
            timestamp: new Date().toISOString(),
            simulated: true,
            warning: 'Transacción simulada - Configurar RELAYER_PRIVATE_KEY',
            processedMessage: `Mensaje simulado: "${message.substring(0, 30)}${message.length > 30 ? '...' : ''}"`
        };
    }

    try {
        const userNonceHex = user.nonce;
        const userNonceBigInt = BigInt('0x' + userNonceHex);
        
        console.log(`🔄 Enviando transacción real para usuario: ${user.address}`);
        console.log(`📝 Mensaje: ${message}`);
        console.log(`🔢 Nonce (hex): ${userNonceHex}`);
        console.log(`🔢 Nonce (decimal): ${userNonceBigInt.toString()}`);
        
        const result = await sendRealTransaction(user.address, message, userNonceBigInt);
        
        if (!result.success) {
            throw new Error(result.error || 'Error desconocido en transacción');
        }

        return {
            message: message,
            length: message.length,
            timestamp: new Date().toISOString(),
            simulated: false,
            txHash: result.txHash,
            blockNumber: result.blockNumber,
            messageId: result.messageId,
            gasUsed: result.gasUsed,
            actualCost: result.actualCost,
            processedMessage: `Mensaje registrado en blockchain: "${message.substring(0, 30)}${message.length > 30 ? '...' : ''}" (ID: ${result.messageId})`,
            explorerUrl: `${nameurlexplorer}/tx/${result.txHash}`
        };
    } catch (error) {
        console.error('❌ Error en transacción real:', error);
        
        let errorMessage = error.message;
        if (error.info && error.info.error) {
            errorMessage = error.info.error.message || JSON.stringify(error.info.error);
        } else if (error.reason) {
            errorMessage = error.reason;
        }
        
        return {
            message: message,
            length: message.length,
            timestamp: new Date().toISOString(),
            simulated: true,
            error: errorMessage,
            processedMessage: `Mensaje simulado por error: "${message.substring(0, 30)}${message.length > 30 ? '...' : ''}"`
        };
    }
}

// CORRECCIÓN CRÍTICA: Ruta principal de transacciones - Validación de nonce corregida
app.post('/api/transaction/execute', 
    authenticateToken,
    transactionLimiter,
    [
        body('contractAddress').isEthereumAddress(),
        body('action').isString().isLength({ min: 1, max: 50 }),
        body('parameters').isObject(),
        body('playerName').isString().isLength({ min: 1, max: 50 }),
        body('userNonce').isHexadecimal().isLength({ min: 1, max: 64 })
    ],
    async (req, res) => {
        try {
            const validationErrors = validationResult(req);
            if (!validationErrors.isEmpty()) {
                return res.status(400).json({ 
                    error: 'Validación fallida', 
                    details: validationErrors.array() 
                });
            }

            const { contractAddress, action, parameters, playerName, userNonce } = req.body;
            const address = req.user.address;

            // 1. Buscar usuario
            const user = await User.findOne({ address });
            if (!user) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }

            // 2. Validación de playerName
            if (!user.playerName) {
                user.playerName = playerName;
                await user.save();
                console.log(`🔄 Asignado playerName automáticamente: ${playerName}`);
            }
            else if (user.playerName !== playerName) {
                const existingUser = await User.findOne({ 
                    playerName: playerName,
                    address: { $ne: address }
                });
                
                if (existingUser) {
                    return res.status(403).json({ error: 'PlayerName no autorizado - ya está en uso por otro usuario' });
                }
                
                user.playerName = playerName;
                await user.save();
                console.log(`🔄 Actualizado playerName: ${playerName}`);
            }

            // 3. CORRECCIÓN CRÍTICA: Validar nonce - debe ser EXACTAMENTE IGUAL al almacenado
            console.log(`🔍 Validando nonce - Enviado: ${userNonce}, Almacenado: ${user.nonce}`);
            validateNonce(userNonce, user.nonce);

            // 4. Validar contrato y acción permitida
            const contract = validateContract(contractAddress, action);

            // 5. Validaciones específicas por contrato
            let contractValidation;
            switch (contract.name) {
                case 'SimpleMessageLogger':
                    contractValidation = await validateSimpleLoggerTransaction(parameters);
                    break;
                default:
                    return res.status(400).json({ error: 'Tipo de contrato no soportado' });
            }

            if (!contractValidation.valid) {
                return res.status(400).json({ error: contractValidation.error });
            }

            // 6. Emitir evento de transacción pendiente
            if (global.io) {
                global.io.emit('tx_pending', {
                    playerName: playerName,
                    fromAddress: address,
                    message: parameters.message,
                    ts: new Date()
                });
            }

            // 7. Procesar la transacción
            let processingResult;
            switch (contract.name) {
                case 'SimpleMessageLogger':
                    processingResult = await processSimpleLoggerTransaction(user, parameters);
                    break;
                default:
                    return res.status(400).json({ error: 'Procesamiento no implementado' });
            }

            // 8. Registrar transacción en base de datos
            const transaction = new Transaction({
                playerName,
                address,
                action,
                contract: contract.name,
                contractAddress,
                details: { ...parameters, ...processingResult },
                txHash: processingResult.txHash || null,
                blockNumber: processingResult.blockNumber || null,
                nonceUsed: userNonce,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                gasUsed: processingResult.gasUsed,
                actualCost: processingResult.actualCost,
                status: processingResult.simulated ? 'simulated' : 'completed'
            });
            await transaction.save();

            // 9. CORRECCIÓN: Actualizar usuario (incrementar nonce para la próxima transacción)
            const newNonce = (BigInt('0x' + user.nonce) + 1n).toString(16);
            user.nonce = newNonce;
            user.transactionCount += 1;
            user.lastTransaction = new Date();
            await user.save();

            // 10. Emitir eventos Socket.IO
            if (global.io) {
                if (processingResult.simulated) {
                    global.io.emit('tx_simulated', {
                        playerName: playerName,
                        message: parameters.message,
                        reason: processingResult.error || 'Modo simulación',
                        ts: new Date()
                    });
                } else {
                    global.io.emit('tx_confirmed', {
                        txHash: processingResult.txHash,
                        blockNumber: processingResult.blockNumber,
                        playerName: playerName,
                        messageId: processingResult.messageId,
                        explorerUrl: processingResult.explorerUrl
                    });
                    
                    global.io.emit('transactionCompleted', {
                        playerName,
                        action,
                        contract: contract.name,
                        details: processingResult,
                        timestamp: new Date(),
                        transactionId: transaction._id,
                        txHash: processingResult.txHash
                    });
                }
            }

            return res.json({
                success: true,
                message: processingResult.simulated ? 
                    'Transacción simulada (configurar RELAYER_PRIVATE_KEY)' : 
                    'Transacción ejecutada exitosamente en blockchain',
                transactionId: transaction._id,
                txHash: processingResult.txHash,
                blockNumber: processingResult.blockNumber,
                nonceUsed: userNonce,
                newNonce: newNonce,
                simulated: processingResult.simulated,
                result: processingResult
            });

        } catch (error) {
            console.error('Error en transacción:', error);
            
            if (global.io) {
                global.io.emit('tx_failed', {
                    playerName: req.body.playerName,
                    error: error.message,
                    ts: new Date()
                });
            }
            
            return res.status(500).json({ error: error.message });
        }
    }
);

app.get('/api/transactions/history', 
    authenticateToken,
    strictLimiter,
    async (req, res) => {
        try {
            const { limit = 10, page = 1 } = req.query;
            const address = req.user.address;

            const transactions = await Transaction.find({ 
                address: address.toLowerCase() 
            })
            .sort({ timestamp: -1 })
            .limit(parseInt(limit))
            .skip((parseInt(page) - 1) * parseInt(limit));

            const total = await Transaction.countDocuments({ 
                address: address.toLowerCase() 
            });

            return res.json({
                success: true,
                transactions,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            });

        } catch (error) {
            console.error('Error obteniendo historial:', error);
            return res.status(500).json({ error: 'Error interno' });
        }
    }
);

// ─────────────────────────────────────────────────────────────────
// RUTAS DE MIGRACIÓN RÁPIDA
// ─────────────────────────────────────────────────────────────────

app.post('/api/migrate/sync-all-users', strictLimiter, async (req, res) => {
  try {
    if (NODE_ENV === 'production' && req.headers['admin-key'] !== process.env.ADMIN_MIGRATION_KEY) {
      return res.status(403).json({ error: 'No autorizado para migraciones en producción' });
    }

    console.log('🔄 Iniciando migración masiva de usuarios...');
    
    const users = await User.find({});
    let updatedCount = 0;
    let errors = [];

    for (const user of users) {
      try {
        const playerData = await Player.findOne({ address: user.address });
        
        if (!user.playerName && playerData && playerData.playerName) {
          user.playerName = playerData.playerName;
          await user.save();
          updatedCount++;
          console.log(`✅ Migrado: ${user.address} -> ${playerData.playerName}`);
        }
        else if (user.playerName && (!playerData || playerData.playerName !== user.playerName)) {
          if (!playerData) {
            const newPlayer = new Player({
              playerName: user.playerName,
              address: user.address
            });
            await newPlayer.save();
          } else {
            playerData.playerName = user.playerName;
            await playerData.save();
          }
          updatedCount++;
          console.log(`✅ Sincronizado Player: ${user.address} -> ${user.playerName}`);
        }
      } catch (error) {
        errors.push({
          address: user.address,
          error: error.message
        });
        console.error(`❌ Error migrando ${user.address}:`, error.message);
      }
    }

    return res.json({
      success: true,
      message: `Migración completada. ${updatedCount} usuarios actualizados.`,
      updatedCount,
      errors: errors.length > 0 ? errors : undefined
    });

  } catch (error) {
    console.error('Error en migración masiva:', error);
    return res.status(500).json({ error: 'Error interno en migración' });
  }
});

app.post('/api/migrate/sync-user', authenticateToken, strictLimiter, async (req, res) => {
  try {
    const user = await User.findOne({ address: req.user.address });
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const playerData = await Player.findOne({ address: req.user.address });
    let action = 'none';

    if (!user.playerName && playerData && playerData.playerName) {
      user.playerName = playerData.playerName;
      await user.save();
      action = 'user_updated_from_player';
    }
    else if (user.playerName && !playerData) {
      const newPlayer = new Player({
        playerName: user.playerName,
        address: req.user.address
      });
      await newPlayer.save();
      action = 'player_created_from_user';
    }
    else if (user.playerName && playerData && user.playerName !== playerData.playerName) {
      const existingPlayer = await Player.findOne({ 
        playerName: user.playerName,
        address: { $ne: req.user.address }
      });
      
      if (!existingPlayer) {
        playerData.playerName = user.playerName;
        await playerData.save();
        action = 'player_updated_from_user';
      } else {
        user.playerName = playerData.playerName;
        await user.save();
        action = 'user_updated_from_player_forced';
      }
    }

    return res.json({
      success: true,
      action: action,
      userPlayerName: user.playerName,
      playerPlayerName: playerData ? playerData.playerName : null,
      message: getMigrationMessage(action)
    });

  } catch (error) {
    console.error('Error en sincronización de usuario:', error);
    return res.status(500).json({ error: 'Error interno' });
  }
});

function getMigrationMessage(action) {
  const messages = {
    'none': 'No se requirió sincronización',
    'user_updated_from_player': 'User actualizado desde Player',
    'player_created_from_user': 'Player creado desde User',
    'player_updated_from_user': 'Player actualizado desde User',
    'user_updated_from_player_forced': 'User actualizado desde Player (forzado)'
  };
  return messages[action] || 'Acción desconocida';
}

// ─────────────────────────────────────────────────────────────────
// ESQUEMAS DE CULTIVOS
// ─────────────────────────────────────────────────────────────────

const UserCropSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  plotId: { type: String, required: true },
  cropType: { type: String, required: true },
  seedType: { type: String, required: true },
  growthStage: { type: Number, default: 1 },
  plantedAt: { type: Date, default: Date.now },
  growthDuration: { type: Number, required: true },
  currentGrowthTime: { type: Number, default: 0 },
  isWatered: { type: Boolean, default: false },
  isCompleted: { type: Boolean, default: false },
  isHarvested: { type: Boolean, default: false },
  successChance: { type: Number, default: 100 },
  isDead: { type: Boolean, default: false },
  rewards: {
    item: String,
    quantity: Number,
    progress_reward: String,
    progress_quantity: Number,
    deadReward: String,
    deadQuantity: Number
  }
});

const CropHistorySchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  plotId: { type: String, required: true },
  cropType: { type: String, required: true },
  seedType: { type: String, required: true },
  plantedAt: { type: Date, default: Date.now },
  harvestedAt: { type: Date },
  growthDuration: { type: Number, required: true },
  wasCompleted: { type: Boolean, default: false },
  wasDead: { type: Boolean, default: false },
  rewards: {
    item: String,
    quantity: Number,
    progress_reward: String,
    progress_quantity: Number,
    deadReward: String,
    deadQuantity: Number
  }
});

const UserCrop = mongoose.model('UserCrop', UserCropSchema);
const CropHistory = mongoose.model('CropHistory', CropHistorySchema);

class CropController {
  constructor(io) {
    this.io = io;
    
    this.clearHistoryOnStartup();
    
    this.cropTypes = {
      Semillax: {
        id: 'Semillax',
        name: 'Zanahoria',
        type: 'semilla',
        growthStages: 4,
        growthTime: 60,
        waterRequired: true,
        waterCost: 1,
        foodCost: 0.2,
        wateringCost: 0.5,
        agricultureReq: 0,
        strengthReq: 0,
        levelReq: 2,
        images: {
          stage1: 'tierra_seca_plant',
          stage2: 'tierra_mojada_plant', 
          stage3: 'tierra_mojada_plant2',
          stage4: 'tierra_mojada_plant3',
          stage5: 'tierra_muerta_plant4'
        },
        rewards: {
          item: 'zanahoria_buena',
          quantity: 1,
          progress_reward: 'zanahoria_corta',
          progress_quantity: 1,
          deadReward: 'zanahoria_mala',
          deadQuantity: 1
        }
      },
      Semillax1: {
        id: 'Semillax1',
        name: 'Tomates',
        type: 'semilla1',
        growthStages: 4,
        growthTime: 300,
        waterRequired: true,
        waterCost: 1,
        foodCost: 0.2,
        wateringCost: 0.5,
        agricultureReq: 0,
        strengthReq: 0,
        levelReq: 2,
        images: {
          stage1: 'tierra_seca_plant_tomate',
          stage2: 'tierra_mojada_plant_tomate',
          stage3: 'tierra_mojada_plant2_tomate',
          stage4: 'tierra_mojada_plant3_tomate',
          stage5: 'tierra_muerta_plant4_tomate'
        },
        rewards: {
          item: 'tomate_buena',
          quantity: 1,
          progress_reward: 'tomate_corta',
          progress_quantity: 1,
          deadReward: 'tomate_mala',
          deadQuantity: 1
        }
      },
    };
    
    this.startGrowthTimers();
  }

  async clearHistoryOnStartup() {
    try {
      await CropHistory.deleteMany({});
      console.log('🗑️ Historial de cultivos limpiado al iniciar el backend');
    } catch (error) {
      console.error('Error al limpiar historial:', error);
    }
  }

async plantSeed(userId, plotId, seedType, userStats, successChance) {
  try {
    const existingCrop = await UserCrop.findOne({ userId, plotId, isHarvested: false });
    if (existingCrop) {
      throw new Error('Este cuadro ya tiene un cultivo');
    }

    const cropConfig = this.cropTypes[seedType];
    if (!cropConfig) {
      throw new Error('Tipo de semilla no válido');
    }

    let adjustedChance;
    
    if (typeof successChance === 'string' || typeof successChance === 'number') {
      adjustedChance = parseFloat(successChance);
    } else {
      console.warn(`⚠️  Tipo de successChance inválido para ${userId}: ${typeof successChance}. Se establece 50% por defecto.`);
      adjustedChance = 50;
    }
    
    if (isNaN(adjustedChance) || !isFinite(adjustedChance)) {
      console.warn(`⚠️  Probabilidad inválida recibida para ${userId}: ${successChance}. Se establece 50% por defecto.`);
      adjustedChance = 50;
    }
    
    if (adjustedChance >= 100) {
      adjustedChance = 95;
      console.log(`🎯 Probabilidad ajustada de 100% a 95% para ${userId}`);
    }
    
    adjustedChance = Math.max(1, Math.min(100, adjustedChance));
    
    console.log(`📊 Probabilidad procesada para ${userId}: ${adjustedChance}% (original: ${successChance})`);

    const newCrop = new UserCrop({
      userId,
      plotId,
      cropType: seedType,
      seedType,
      growthDuration: cropConfig.growthTime,
      rewards: cropConfig.rewards,
      isWatered: false,
      growthStage: 1,
      successChance: adjustedChance,
      isDead: false
    });

    await newCrop.save();

    const cropWithConfig = {
      ...newCrop.toObject(),
      cropConfig: cropConfig,
      successChance: adjustedChance
    };

    this.io.emit('cropPlanted', {
      userId,
      plotId,
      crop: cropWithConfig,
      successChance: adjustedChance
    });

    console.log(`🌱 ${userId} plantó ${cropConfig.name} en ${plotId} - Posibilidad: ${adjustedChance}%`);
    
    return cropWithConfig;
    
  } catch (error) {
    console.error(`❌ Error en plantSeed para ${userId} en ${plotId}:`, error.message);
    throw error;
  }
}

  async waterCrop(userId, plotId) {
    try {
      const crop = await UserCrop.findOne({ userId, plotId, isHarvested: false });
      if (!crop) {
        throw new Error('Cultivo no encontrado');
      }

      if (crop.isWatered) {
        throw new Error('Este cultivo ya está regado');
      }

      crop.isWatered = true;
      await crop.save();

      const cropConfig = this.cropTypes[crop.cropType];
      const cropWithConfig = {
        ...crop.toObject(),
        cropConfig: cropConfig
      };

      this.io.emit('cropWatered', {
        userId,
        plotId,
        crop: cropWithConfig
      });

      console.log(`💧 ${userId} regó ${plotId}`);
      return cropWithConfig;
    } catch (error) {
      throw error;
    }
  }

  async harvestCrop(userId, plotId) {
    try {
      const crop = await UserCrop.findOne({ userId, plotId, isHarvested: false });
      if (!crop) {
        throw new Error('Cultivo no encontrado');
      }

      if (!crop.isCompleted) {
        throw new Error('El cultivo no está listo para cosechar');
      }

      if (crop.isDead) {
        throw new Error('No puedes cosechar un árbol muerto');
      }

      const history = new CropHistory({
        userId: crop.userId,
        plotId: crop.plotId,
        cropType: crop.cropType,
        seedType: crop.seedType,
        plantedAt: crop.plantedAt,
        harvestedAt: new Date(),
        growthDuration: crop.growthDuration,
        wasCompleted: crop.isCompleted,
        wasDead: crop.isDead,
        rewards: crop.rewards
      });
      await history.save();

      await UserCrop.deleteOne({ _id: crop._id });

      this.io.emit('cropHarvested', {
        userId,
        plotId,
        rewards: {
          item: crop.rewards.item,
          quantity: crop.rewards.quantity
        },
        history
      });

      console.log(`🎉 ${userId} cosechó ${plotId} - Recompensa: ${crop.rewards.quantity} ${crop.rewards.item}`);
      console.log(`🗑️ Cultivo eliminado de UserCrops: ${plotId}`);
      
      return { 
        rewards: {
          item: crop.rewards.item,
          quantity: crop.rewards.quantity
        }, 
        crop 
      };
    } catch (error) {
      throw error;
    }
  }

  async cutCrop(userId, plotId) {
    try {
      const crop = await UserCrop.findOne({ userId, plotId, isHarvested: false });
      if (!crop) {
        throw new Error('Cultivo no encontrado');
      }

      const cropConfig = this.cropTypes[crop.cropType];
      let rewards;

      console.log(`🔍 Información del cultivo al cortar:`, {
        cropType: crop.cropType,
        isDead: crop.isDead,
        isCompleted: crop.isCompleted,
        rewards: crop.rewards
      });

      if (crop.isDead) {
        rewards = {
          item: crop.rewards.deadReward || 'Madera_podrida',
          quantity: crop.rewards.deadQuantity || 1
        };
        console.log(`💀 Cortando árbol muerto - Recompensa muerta: ${rewards.quantity} ${rewards.item}`);
      } else if (!crop.isCompleted) {
        rewards = {
          item: crop.rewards.progress_reward || 'palo_de_madera',
          quantity: crop.rewards.progress_quantity || 1
        };
        console.log(`✂️ Cortando árbol en progreso - Recompensa: ${rewards.quantity} ${rewards.item}`);
      } else {
        rewards = { item: 'Madera', quantity: 1 };
        console.log(`⚠️ Caso inesperado - Recompensa por defecto: ${rewards.quantity} ${rewards.item}`);
      }

      if (!rewards.item || !rewards.quantity) {
        console.error('❌ ERROR: Recompensas undefined, usando valores por defecto');
        rewards = { item: 'Madera', quantity: 1 };
      }

      const history = new CropHistory({
        userId: crop.userId,
        plotId: crop.plotId,
        cropType: crop.cropType,
        seedType: crop.seedType,
        plantedAt: crop.plantedAt,
        harvestedAt: new Date(),
        growthDuration: crop.growthDuration,
        wasCompleted: false,
        wasDead: crop.isDead,
        rewards: rewards
      });
      await history.save();

      await UserCrop.deleteOne({ _id: crop._id });

      this.io.emit('cropCut', {
        userId,
        plotId,
        rewards: rewards,
        isDead: crop.isDead,
        wasInProgress: !crop.isCompleted && !crop.isDead
      });

      console.log(`✂️ ${userId} cortó ${plotId} - Recompensa: ${rewards.quantity} ${rewards.item}`);
      console.log(`🗑️ Cultivo eliminado de UserCrops: ${plotId}`);
      
      return { rewards: rewards, crop };
    } catch (error) {
      throw error;
    }
  }

  async getUserCrops(userId) {
    const crops = await UserCrop.find({ userId, isHarvested: false });
    return crops.map(crop => {
      const cropConfig = this.cropTypes[crop.cropType];
      return {
        ...crop.toObject(),
        cropConfig: cropConfig
      };
    });
  }

  async startGrowthTimers() {
    setInterval(async () => {
      try {
        const activeCrops = await UserCrop.find({ 
          isWatered: true, 
          isCompleted: false, 
          isHarvested: false,
          isDead: false
        });

        for (const crop of activeCrops) {
          const cropConfig = this.cropTypes[crop.cropType];
          if (!cropConfig) continue;

          crop.currentGrowthTime += 1;
          
          const growthPerStage = cropConfig.growthTime / cropConfig.growthStages;
          
          let newStage = 1;
          if (crop.currentGrowthTime >= growthPerStage * 3) {
            newStage = 4;
          } else if (crop.currentGrowthTime >= growthPerStage * 2) {
            newStage = 3;
          } else if (crop.currentGrowthTime >= growthPerStage) {
            newStage = 2;
          } else {
            newStage = 1;
          }

          const wasHalfway = crop.currentGrowthTime - 1 < cropConfig.growthTime / 2 && 
                           crop.currentGrowthTime >= cropConfig.growthTime / 2;
          const isNowCompleted = crop.currentGrowthTime >= cropConfig.growthTime;

          let isDead = false;
          if (isNowCompleted && !crop.isCompleted) {
            const random = Math.random() * 100;
            isDead = random > crop.successChance;
            
            if (isDead) {
              crop.isDead = true;
              console.log(`💀 ÁRBOL MUERTO: ${crop.userId} - ${crop.plotId} (${random.toFixed(2)}% > ${crop.successChance}%)`);
            } else {
              crop.isCompleted = true;
              console.log(`✅ COMPLETADO: ${crop.userId} - ${crop.plotId} está listo para cosechar`);
            }
          }

          this.io.emit('cropGrowth', {
            userId: crop.userId,
            plotId: crop.plotId,
            growthStage: newStage,
            currentGrowthTime: crop.currentGrowthTime,
            isHalfway: wasHalfway,
            isCompleted: crop.isCompleted,
            isDead: crop.isDead,
            timeRemaining: Math.max(0, cropConfig.growthTime - crop.currentGrowthTime),
            cropConfig: cropConfig
          });

          if (newStage !== crop.growthStage) {
            crop.growthStage = newStage;
            console.log(`🌱 ${crop.userId} - ${crop.plotId}: Etapa ${newStage}`);
          }

          if (wasHalfway) {
            console.log(`⏰ MITAD: ${crop.userId} - ${crop.plotId} llegó a la mitad`);
          }
          
          await crop.save();
        }
      } catch (error) {
        console.error('Error en timer de crecimiento:', error);
      }
    }, 1000);
  }

  getCropConfig() {
    return this.cropTypes;
  }
}

const cropController = new CropController(io);

// ─────────────────────────────────────────────────────────────────
// SOCKET.IO EVENTOS DE CULTIVOS
// ─────────────────────────────────────────────────────────────────

io.on('connection', (socket) => {
  console.log('Usuario conectado:', socket.id);

  socket.emit('cropConfig', cropController.getCropConfig());

  socket.on('plantSeed', async (data) => {
    try {
      const { userId, plotId, seedType, userStats, successChance } = data;
      const crop = await cropController.plantSeed(userId, plotId, seedType, userStats, successChance);
      socket.emit('plantSuccess', { plotId, crop });
    } catch (error) {
      socket.emit('plantError', { error: error.message });
    }
  });

  socket.on('waterCrop', async (data) => {
    try {
      const { userId, plotId } = data;
      const crop = await cropController.waterCrop(userId, plotId);
      socket.emit('waterSuccess', { plotId, crop });
    } catch (error) {
      socket.emit('waterError', { error: error.message });
    }
  });

  socket.on('harvestCrop', async (data) => {
    try {
      const { userId, plotId } = data;
      const result = await cropController.harvestCrop(userId, plotId);
      socket.emit('harvestSuccess', { plotId, rewards: result.rewards });
    } catch (error) {
      socket.emit('harvestError', { error: error.message });
    }
  });

  socket.on('cutCrop', async (data) => {
    try {
      const { userId, plotId } = data;
      const result = await cropController.cutCrop(userId, plotId);
      socket.emit('cutSuccess', { 
        plotId, 
        rewards: result.rewards,
        isDead: result.crop.isDead,
        wasInProgress: !result.crop.isCompleted && !result.crop.isDead
      });
    } catch (error) {
      socket.emit('cutError', { error: error.message });
    }
  });

  socket.on('getUserCrops', async (data) => {
    try {
      const { userId } = data;
      const crops = await cropController.getUserCrops(userId);
      socket.emit('userCropsData', { crops });
    } catch (error) {
      socket.emit('cropsError', { error: error.message });
    }
  });

  socket.on('getCropConfig', () => {
    socket.emit('cropConfig', cropController.getCropConfig());
  });
});

// ─────────────────────────────────────────────────────────────────
// RUTAS DEL SISTEMA DE JUEGO (PROTEGIDAS)
// ─────────────────────────────────────────────────────────────────

const api = express.Router();
app.use('/api', api);

api.post('/auth', 
  authenticateToken,
  [
    body('playerName').isString().notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { playerName } = req.body;
    const now = new Date();
    const ip = req.clientIp;
    const ua = req.useragent.source;

    const user = await User.findOne({ address: req.user.address });
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    if (!user.playerName) {
      user.playerName = playerName;
      await user.save();
    } else if (user.playerName !== playerName) {
      const existingUser = await User.findOne({ 
        playerName: playerName,
        address: { $ne: req.user.address }
      });
      
      if (existingUser) {
        return res.status(403).json({ error: 'PlayerName no coincide con el usuario autenticado' });
      }
      
      user.playerName = playerName;
      await user.save();
    }

    const geo = geoip.lookup(ip) || {};
    const tlsFp = extractTlsFingerprint(req.socket);

    let doc = await UserActivity.findOne({ playerName });
    if (!doc) {
      doc = new UserActivity({ 
        playerName,
        sessions: []
      });
    }

    if (!doc.sessions) {
      doc.sessions = [];
    }

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

    res.json({ 
      success: true, 
      message: 'Actividad registrada exitosamente',
      playerName 
    });
  }
);

api.post('/logout', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ address: req.user.address });
    if (!user || !user.playerName) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const playerName = user.playerName;
    const now = new Date();

    await ConnectedUser.deleteOne({ playerName });
    await UserActivity.updateOne(
      { playerName, 'sessions.disconnectedAt': { $exists: false } },
      { $set: { 'sessions.$.disconnectedAt': now } }
    );

    await invalidateAllRefreshTokens(req.user.address);

    res.json({ 
      success: true, 
      message: 'Sesión cerrada exitosamente' 
    });
  } catch (error) {
    console.error('Error en logout:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ─────────────────────────────────────────────────────────────────
// RUTAS DE RECOLECCIÓN DE AGUA
// ─────────────────────────────────────────────────────────────────

api.get('/water/status/:playerName',
  apiLimiter,
  authenticateToken,
  [
    param('playerName').isString().notEmpty()
  ],
  async (req, res) => {
    try {
      const { playerName } = req.params;
      
      const user = await User.findOne({ address: req.user.address });
      if (!user || user.playerName !== playerName) {
        return res.status(403).json({ error: 'No autorizado' });
      }
      
      const status = await waterCollectionController.getWaterCollectionStatus(playerName);
      res.json(status);
    } catch (error) {
      console.error('Error obteniendo estado de agua:', error);
      res.status(500).json({ error: 'Error interno' });
    }
  }
);

api.post('/water/collect',
  apiLimiter,
  authenticateToken,
  [
    body('playerName').isString().notEmpty(),
    body('timestamp').isISO8601()
  ],
  async (req, res) => {
    try {
      const { playerName } = req.body;
      
      const user = await User.findOne({ address: req.user.address });
      if (!user || user.playerName !== playerName) {
        return res.status(403).json({ error: 'No autorizado' });
      }
      
      const result = await waterCollectionController.collectWater(playerName);
      res.json(result);
    } catch (error) {
      console.error('Error recolectando agua:', error);
      res.status(400).json({ 
        success: false, 
        error: error.message 
      });
    }
  }
);

api.post('/save/:playerName', 
  apiLimiter, 
  authenticateToken,
  [
    param('playerName').isString().notEmpty(),
    body('inventory').isArray(),
    body('chest').isArray(),
    body('missionsData').optional().isObject()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { playerName } = req.params;
    
    try {
      const user = await User.findOne({ address: req.user.address });
      if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      if (!user.playerName) {
        user.playerName = playerName;
        await user.save();
      } else if (user.playerName !== playerName) {
        return res.status(403).json({ error: 'No autorizado' });
      }

      const update = req.body;
      let p = await Player.findOne({ playerName });
      
      if (p) { 
        Object.assign(p, update); 
        await p.save(); 
      } else { 
        p = new Player({ 
          playerName, 
          ...update,
          address: req.user.address
        }); 
        await p.save(); 
      }

      if (update.missionsData) {
        await MissionsPlayer.findOneAndUpdate(
          { playerName },
          { ...update.missionsData },
          { upsert: true, new: true }
        );
      }
      
      res.json({ success: true });
    } catch (e) {
      console.error('Error en save:', e);
      res.status(500).json({ error: e.message });
    }
  }
);

api.get('/load/:playerName', 
  apiLimiter, 
  authenticateToken,
  [
    param('playerName').isString().notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { playerName } = req.params;
    
    try {
      const user = await User.findOne({ address: req.user.address });
      if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      if (!user.playerName) {
        user.playerName = playerName;
        await user.save();
      } else if (user.playerName !== playerName) {
        return res.status(403).json({ error: 'No autorizado' });
      }

      let p = await Player.findOne({ playerName });
      if (!p) { 
        p = new Player({ 
          playerName,
          address: req.user.address
        }); 
        await p.save(); 
      }
      
      let a = await Admin.findById('config');
      if (!a) { a = new Admin(); await a.save(); }

      let missionsData = await MissionsPlayer.findOne({ playerName });
      if (!missionsData) {
        missionsData = new MissionsPlayer({ playerName });
        await missionsData.save();
      }
      
      res.json({ 
        ...p.toObject(), 
        hora: a.hora, 
        dia_noche: a.dia_noche,
        missionsData: missionsData.toObject()
      });
    } catch (e) {
      console.error('Error en load:', e);
      res.status(500).json({ error: e.message });
    }
  }
);

// ─────────────────────────────────────────────────────────────────
// RUTAS ESPECÍFICAS PARA MISSIONS PLAYER
// ─────────────────────────────────────────────────────────────────

api.get('/missions/:playerName',
  apiLimiter,
  authenticateToken,
  [
    param('playerName').isString().notEmpty()
  ],
  async (req, res) => {
    try {
      const { playerName } = req.params;
      
      const user = await User.findOne({ address: req.user.address });
      if (!user || user.playerName !== playerName) {
        return res.status(403).json({ error: 'No autorizado para acceder a estos datos' });
      }
      
      const missionsData = await MissionsPlayer.findOne({ playerName });
      if (!missionsData) {
        const newMissions = new MissionsPlayer({ playerName });
        await newMissions.save();
        return res.json(newMissions);
      }
      
      res.json(missionsData);
    } catch (error) {
      console.error('Error obteniendo datos de misiones:', error);
      res.status(500).json({ error: 'Error interno' });
    }
  }
);

api.post('/missions/:playerName/update',
  apiLimiter,
  authenticateToken,
  [
    param('playerName').isString().notEmpty(),
    body().isObject()
  ],
  async (req, res) => {
    try {
      const { playerName } = req.params;
      const updateData = req.body;
      
      const user = await User.findOne({ address: req.user.address });
      if (!user || user.playerName !== playerName) {
        return res.status(403).json({ error: 'No autorizado para actualizar estos datos' });
      }
      
      const missionsData = await MissionsPlayer.findOneAndUpdate(
        { playerName },
        { $set: updateData },
        { upsert: true, new: true, runValidators: true }
      );
      
      res.json({
        success: true,
        missionsData
      });
    } catch (error) {
      console.error('Error actualizando datos de misiones:', error);
      res.status(500).json({ error: 'Error interno' });
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

api.get('/listingsx/:id', apiLimiter, authenticateTokenWithPlayer, async (req, res) => {
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
  authenticateTokenWithPlayer,
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

api.post('/listingsx/:playerName',
  apiLimiter,
  authenticateTokenWithPlayer,
  [
    param('playerName').isString().notEmpty(),
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

    const playerName = req.params.playerName;
    const { inventoryId, name, type, qty, price, imageUrl } = req.body;

    const user = await User.findOne({ address: req.user.address });
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    if (!user.playerName) {
      user.playerName = playerName;
      await user.save();
    } else if (user.playerName !== playerName) {
      return res.status(403).json({ error: 'No autorizado para este playerName' });
    }

    try {
      const newListing = new Listing({
        owner: playerName,
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
      console.error('Error en POST /listingsx/:playerName:', err);
      return res.status(500).json({ error: err.message });
    }
  }
);

api.post(
  '/listings/:id/buy',
  apiLimiter,
  authenticateTokenWithPlayer,
  param('id').isMongoId(),
  body('quantity').isInt({ min: 1 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

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
  authenticateTokenWithPlayer,
  param('id').isMongoId(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: validationErrors.array() });
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

app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.ip} - ${req.method} ${req.path}`);
    next();
});

app.use((req, res) => res.status(404).json({ error: `Ruta no encontrada: ${req.method} ${req.originalUrl}` }));

app.use((err, req, res, next) => {
  console.error('Error no manejado:', err);
  
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Error interno del servidor' });
  } else {
    res.status(500).json({ 
      error: 'Error interno del servidor',
      stack: err.stack 
    });
  }
});

process.on('SIGTERM', () => {
  console.log('🛑 Apagando servidor...');
  mongoose.disconnect().then(() => {
    console.log('✅ MongoDB desconectado');
    process.exit(0);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Backend MEJORADO Y SEGURO activo en http://0.0.0.0:${PORT}`);
  console.log(`🔐 Autenticación EIP-712: Sistema de tokens JWT mejorado`);
  console.log(`💧 Sistema de recolección de agua implementado`);
  console.log(`⛓️  Blockchain: ${relayerWallet ? `MODO REAL - Transacciones en ${networkname}` : 'MODO SIMULACIÓN - Configurar RELAYER_PRIVATE_KEY'}`);
  console.log(`💰 Relayer: ${relayerAddress || 'No configurado'}`);
  console.log(`📊 Sistema de transacciones ${relayerWallet ? 'REALES' : 'SIMULADAS'} activo`);
  console.log(`🔗 Contrato: 0x52f269B242121ED0B80aed7d7A35f1db5B111C73`);
  console.log(`🌐 Explorer: ${nameurlexplorer}`);
  console.log(`🔌 Socket.io: Configuración CORREGIDA - Cliente servido en /socket.io/socket.io.js`);
});