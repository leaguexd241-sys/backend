// server.js - VERSIÓN COMPLETA CORREGIDA CON SOPORTE PARA KEYSTORE CIFRADO
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
const useragent = require('express-useragent');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const fs = require('fs');
const path = require('path');
const Web3 = require('web3');
const http = require("http");
const { Server } = require("socket.io");
const https = require('https');
const compression = require('compression');

// --- Módulo de gestión de keystore (cifrado) ---
const keystore = require('./keystore');

// --- Configuración Principal ---
const PORT = parseInt(process.env.PORT || '3000', 10);
const MONGO = process.env.MONGO_URL || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/grassland';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ACCESS_TOKEN_EXPIRES = process.env.ACCESS_EXPIRES || '15m';
const REFRESH_TOKEN_TTL_DAYS = parseInt(process.env.REFRESH_TTL_DAYS || '7', 10);
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;
const FRONTEND_ORIGINS_RAW = process.env.FRONTEND_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5501,http://127.0.0.1:5501,http://localhost:8080,http://127.0.0.1:8080,https://grasslandforest.com,https://www.grasslandforest.com,https://app.grasslandforest.com';
const APP_NAME = process.env.APP_NAME || 'Grassland Forest';
const NODE_ENV = process.env.NODE_ENV || 'development';

// IMPORTANTE: En desarrollo, escuchar en 127.0.0.1 para consistencia
const HOST = NODE_ENV === 'development' ? '127.0.0.1' : '0.0.0.0';

// --- Configuración de Blockchain y Relay ---
const RPC_URL = process.env.RPC_URL || "https://dream-rpc.somnia.network";
const CHAIN_ID = 50312;
const NETWORK_NAME = "Somnia Testnet";
const EXPLORER_URL = "https://shannon-explorer.somnia.network";

// SISTEMA SEGURO DE GESTIÓN DE CLAVES PRIVADAS
const KEY_MANAGEMENT_TYPE = process.env.KEY_MANAGEMENT_TYPE || 'ENV_VARS';

// --- NUEVA VARIABLE PARA FIJAR GAS PRICE ---
const FIXED_GAS_PRICE_GWEI = process.env.FIXED_GAS_PRICE_GWEI ? parseInt(process.env.FIXED_GAS_PRICE_GWEI, 10) : null;
const MIN_GAS_PRICE_GWEI = process.env.MIN_GAS_PRICE_GWEI || "5";
const FALLBACK_GAS_PRICE_GWEI = process.env.FALLBACK_GAS_PRICE_GWEI || "50";
const GAS_PRICE_MULTIPLIER = Number(process.env.GAS_PRICE_MULTIPLIER || "1.0");

// WALLET DEL RELAYER - Sistema seguro de rotación + keystore cifrado
let relayerWallet;
let RELAYER_PRIVATE_KEY = null;

// Función para rotación de claves (ejemplo básico)
async function rotateRelayerKey() {
  try {
    if (process.env.KEY_ROTATION_ENABLED === 'true') {
      const newKey = ethers.Wallet.createRandom().privateKey;
      console.log('🔄 Rotando clave del relayer...');
      RELAYER_PRIVATE_KEY = newKey;
      if (provider) {
        relayerWallet = new ethers.Wallet(RELAYER_PRIVATE_KEY, provider);
        console.log(`🔄 Nueva dirección: ${relayerWallet.address}`);
      }
    }
  } catch (error) {
    console.error('❌ Error rotando clave:', error);
  }
}

// Configuración de Provider
// ── Suprimir spam de ethers.js cuando la red RPC está caída ─────────────────
// ethers.js escribe directamente a process.stderr, no usa console.error,
// por eso hay que interceptar a nivel de stream.
let _rpcDownSince = null;
let _rpcLastWarn  = 0;
const RPC_WARN_MS = 60_000;

const _RPC_NOISE = [
  'JsonRpcProvider failed to detect network',
  'retry in 1s',
  'perhaps the URL is wrong',
];
const _RPC_ERROR_NOISE = [
  '502 Bad Gateway',
  'SERVER_ERROR',
  'shortMessage',
  'responseStatus',
  'requestUrl',
  'responseBody',
  'at makeError',
  'at assert',
  'at FetchResponse',
  'at JsonRpcProvider',
  'at process.processTicks',
  'node_modules/ethers',
  'Error obteniendo nonce',
  'Error verificando saldo',
];

function _isRpcNoise(chunk) {
  const s = chunk.toString();
  return _RPC_NOISE.some(p => s.includes(p)) || _RPC_ERROR_NOISE.some(p => s.includes(p));
}

const _origStderrWrite = process.stderr.write.bind(process.stderr);
const _origStdoutWrite = process.stdout.write.bind(process.stdout);

function _filteredWrite(orig, chunk, encoding, cb) {
  if (_isRpcNoise(chunk)) {
    const now = Date.now();
    if (!_rpcDownSince) _rpcDownSince = now;
    if (now - _rpcLastWarn >= RPC_WARN_MS) {
      _rpcLastWarn = now;
      const mins = Math.floor((now - _rpcDownSince) / 60000);
      _origStderrWrite('⚠️  [RPC] Red Somnia no disponible' + (mins > 0 ? ' (' + mins + 'm)' : '') + '. Reintentando cada 60s...\n');
    }
    if (typeof cb === 'function') cb();
    return true;
  }
  // Red vuelve: si el chunk tiene algo exitoso y estábamos caídos, avisar
  const s = chunk.toString();
  if (_rpcDownSince && (s.includes('✅') || s.includes('Relay Manager'))) {
    _origStderrWrite('✅ [RPC] Conexión con Somnia restablecida.\n');
    _rpcDownSince = null;
    _rpcLastWarn  = 0;
  }
  return orig(chunk, encoding, cb);
}

process.stderr.write = (chunk, encoding, cb) => _filteredWrite(_origStderrWrite, chunk, encoding, cb);
process.stdout.write = (chunk, encoding, cb) => _filteredWrite(_origStdoutWrite, chunk, encoding, cb);

// También filtrar console.error/warn por si acaso
const _origCE = console.error.bind(console);
const _origCW = console.warn.bind(console);
console.error = (...a) => { const m = a.map(String).join(' '); if (_isRpcNoise(m)) return; _origCE(...a); };
console.warn  = (...a) => { const m = a.map(String).join(' '); if (_isRpcNoise(m)) return; _origCW(...a); };
// ─────────────────────────────────────────────────────────────────────────────

const provider = new ethers.JsonRpcProvider(RPC_URL);

// ========== GESTIÓN DE CLAVES SEGÚN TIPO ==========
if (KEY_MANAGEMENT_TYPE === 'ENV_VARS') {
  // Método 1: Variables de entorno (básico pero funcional)
  RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY;
  
  if (!RELAYER_PRIVATE_KEY && NODE_ENV === 'production') {
    console.error('❌ ERROR CRÍTICO: RELAYER_PRIVATE_KEY no configurada');
    process.exit(1);
  }
  
  if (RELAYER_PRIVATE_KEY && NODE_ENV === 'development') {
    console.log(`🔐 Clave relayer (desarrollo): ${RELAYER_PRIVATE_KEY.substring(0, 10)}...`);
  }
  
} else if (KEY_MANAGEMENT_TYPE === 'ROTATION') {
  // Método 2: Rotación automática (implementación básica)
  const rotationInterval = parseInt(process.env.KEY_ROTATION_INTERVAL_HOURS || '24', 10) * 60 * 60 * 1000;
  rotateRelayerKey();
  setInterval(rotateRelayerKey, rotationInterval);
  
} else if (KEY_MANAGEMENT_TYPE === 'ENCRYPTED_KEYSTORE') {
  // Método 3: Keystore cifrado con AES-256-GCM + PBKDF2
  const keystorePath = process.env.KEYSTORE_PATH || './relayer.key.enc';
  const password = process.env.KEYSTORE_PASSWORD;

  if (!password) {
    console.error('❌ ERROR CRÍTICO: KEYSTORE_PASSWORD no está definida en el entorno');
    console.error('   Debes exportar la variable antes de ejecutar:');
    console.error('   export KEYSTORE_PASSWORD="tu_contraseña"');
    process.exit(1);
  }

  try {
    console.log(`🔐 Cargando keystore desde ${keystorePath}...`);
    // Verificar que el archivo existe
    if (!fs.existsSync(keystorePath)) {
      throw new Error(`Archivo de keystore no encontrado: ${keystorePath}`);
    }
    // Cargar y descifrar usando el módulo keystore.js
    RELAYER_PRIVATE_KEY = keystore.loadEncryptedKey(password, keystorePath);
    console.log(`✅ Keystore descifrado correctamente`);
  } catch (error) {
    console.error(`❌ ERROR CRÍTICO descifrando keystore:`, error.message);
    process.exit(1);
  }
}

// Crear wallet del relayer si tenemos clave
// Crear wallet del relayer si tenemos clave y provider es válido
if (RELAYER_PRIVATE_KEY && provider) {
    try {
        relayerWallet = new ethers.Wallet(RELAYER_PRIVATE_KEY, provider);
        console.log(`✅ Relayer configurado: ${relayerWallet.address.substring(0, 10)}...`);
    } catch (error) {
        console.error('❌ Error al crear la wallet del relayer:', error.message);
        relayerWallet = null;
    }
} else {
    console.warn('⚠️  Relayer no configurado. El sistema de relay estará desactivado.');
}

// Verificar saldo del relayer al inicio
async function checkRelayerBalance() {
    if (!relayerWallet || !provider) {
        console.log('ℹ️ Relayer no disponible, omitiendo verificación de saldo');
        return 0n;
    }
  
  try {
    const balance = await provider.getBalance(relayerWallet.address);
    const balanceInEth = ethers.formatEther(balance);
    console.log(`💰 Relayer balance (${relayerWallet.address.substring(0, 10)}...): ${balanceInEth} STT`);
    
    if (balance < ethers.parseEther("0.01")) {
      console.warn('⚠️  ADVERTENCIA: Saldo del relayer muy bajo. Puede fallar en enviar transacciones.');
    }
    return balance;
  } catch (error) {
    console.error('❌ Error verificando saldo del relayer:', error);
    return 0n;
  }
}

// --- SISTEMA DE MULTISIG / TIME-LOCKS (ESQUELETO PARA FUTURA IMPLEMENTACIÓN) ---
class MultiSigManager {
  constructor() {
    this.signers = [];
    this.requiredSignatures = 2; // Mínimo 2 firmas
    this.timeLockDelay = 3600; // 1 hora en segundos
  }
  
  async initialize() {
    if (process.env.MULTISIG_ENABLED === 'true') {
      console.log('🛡️  Sistema MultiSig configurado');
      // Implementar lógica de múltiples firmantes
    }
  }
  
  async requireTimeLock(transaction, delay = null) {
    const waitTime = delay || this.timeLockDelay;
    console.log(`⏰ Time-lock aplicado: ${waitTime} segundos`);
    return new Promise(resolve => setTimeout(resolve, waitTime * 1000));
  }
}

const multiSigManager = new MultiSigManager();

// --- CARGAR ABIs DESDE ARCHIVOS ---
function loadContractABI(contractName) {
  try {
    const abiPath = path.join(__dirname, 'abis', `${contractName}.json`);
    
    if (fs.existsSync(abiPath)) {
      const abiContent = fs.readFileSync(abiPath, 'utf8');
      const abi = JSON.parse(abiContent);
      console.log(`✅ ABI cargado: ${contractName} (${abi.length} funciones)`);
      return abi;
    } else {
      console.warn(`⚠️  ABI no encontrado: ${contractName}`);
      return [];
    }
  } catch (error) {
    console.error(`❌ Error cargando ABI ${contractName}:`, error);
    return [];
  }
}

// --- CONFIGURACIÓN DE MÚLTIPLES CONTRATOS CON ABIs EXTERNOS ---
const CONTRACTS = {
  SIMPLE_MESSAGE_LOGGER: {
    address: process.env.SIMPLE_MESSAGE_LOGGER_ADDRESS || '0x5b52665d600a48452a84C3B3E2ed02435b489ED9',
    name: 'SecureMessageLogger',
    description: 'Contrato seguro para registrar mensajes en la blockchain',
    abi: loadContractABI('SecureMessageLogger')
  },
  ITEMS_CONTRACT: {
    address: process.env.ITEM_CONTRACT_ADDRESS || '0x4356Eb1A19ed6302d1a9582A5d684bF76cafd97e',
    name: 'ItemContract',
    description: 'Contrato para manejar items del juego',
    abi: loadContractABI('ItemContract')
  },
};

// Crear carpeta abis si no existe
const abisDir = path.join(__dirname, 'abis');
if (!fs.existsSync(abisDir)) {
  fs.mkdirSync(abisDir, { recursive: true });
  console.log('📁 Carpeta abis creada');
}

// Mapa de contratos por dirección (para búsqueda rápida)
const CONTRACT_BY_ADDRESS = {};
Object.values(CONTRACTS).forEach(contract => {
  if (contract.address && contract.address !== '0x...') {
    CONTRACT_BY_ADDRESS[contract.address.toLowerCase()] = contract;
  }
});

// --- Sistema de Nonce del Relayer (Thread-safe) ---
class RelayerNonceManager {
  constructor() {
    this.currentNonce = null;
    this.lock = false;
    this.queue = [];
    if (relayerWallet) {
      this.init();
    }
  }
  async init() {
    if (!relayerWallet) return;
    try {
      this.currentNonce = await provider.getTransactionCount(relayerWallet.address, 'pending');
      console.log(`🔢 Initial relayer nonce: ${this.currentNonce}`);
    } catch (error) {
      console.error('❌ Error obteniendo nonce inicial:', error);
      this.currentNonce = 0;
    }
  }
  async getNextNonce() {
    if (!relayerWallet) return 0;
    return new Promise(async (resolve) => {
      const requestId = uuidv4();
      const processQueue = async () => {
        if (this.lock) {
          setTimeout(processQueue, 10);
          return;
        }
        this.lock = true;
        try {
          const networkNonce = await provider.getTransactionCount(relayerWallet.address, 'pending');
          if (this.currentNonce === null || networkNonce > this.currentNonce) {
            this.currentNonce = networkNonce;
          }
          const nonceToUse = this.currentNonce;
          this.currentNonce++;
          resolve(nonceToUse);
        } catch (error) {
          console.error('❌ Error obteniendo nonce:', error);
          if (this.currentNonce === null) this.currentNonce = 0;
          const nonceToUse = this.currentNonce;
          this.currentNonce++;
          resolve(nonceToUse);
        } finally {
          this.lock = false;
          if (this.queue.length > 0) {
            setTimeout(processQueue, 0);
          }
        }
      };
      processQueue();
    });
  }
  async resetNonce() {
    if (!relayerWallet) return;
    try {
      this.currentNonce = await provider.getTransactionCount(relayerWallet.address, 'pending');
      console.log(`🔄 Nonce del relayer reseteado a: ${this.currentNonce}`);
    } catch (error) {
      console.error('❌ Error reseteando nonce:', error);
    }
  }
}
const relayerNonceManager = new RelayerNonceManager();

// --- Configuración de Seguridad Avanzada ---
const SECURITY_CONFIG = {
  MAX_MESSAGE_LENGTH: 200,
  MAX_TRANSACTIONS_PER_HOUR: 50,
  MAX_FAILED_ATTEMPTS: 5,
  BLOCK_DURATION_MINUTES: 60,
  AUTO_BLOCK_SUSPICIOUS: true,
  BLACKLISTED_SUBNETS: process.env.NODE_ENV === 'production' ? [
    '66.132.153.126',
    '62.60.131.239'
  ] : [],
  SUSPICIOUS_PATHS: [
    '/..', '/../', '/../../',
    '/.env', '/.git', '/.git/config',
    '/etc/passwd', '/etc/shadow',
    '/wp-admin', '/wp-login',
    '/admin', '/administrator',
    '/phpmyadmin', '/mysql',
    '/config', '/backup',
    '/shell', '/cmd',
    '/api/v1/users/search',
    'favicon.ico'
  ],
  SUSPICIOUS_USER_AGENTS: [
    'nmap', 'nikto', 'sqlmap', 'hydra', 'metasploit',
    'dirb', 'gobuster', 'wpscan', 'nessus', 'openvas',
    'curl', 'wget', 'python-requests', 'python-urllib',
    'zgrab', 'masscan', 'skipfish', 'arachni', 'w3af'
  ],
  THRESHOLDS: {
    MAX_REQUESTS_PER_MINUTE: 500,
    MAX_SUSPICIOUS_PATHS_PER_HOUR: 20,
    MAX_RELAY_CALLS_PER_MINUTE: 30,
    MIN_GAS_PRICE_MULTIPLIER: 0.1,
    MAX_GAS_LIMIT: 10000000,
    MAX_GAS_PRICE_GWEI: 10000,
    MIN_VALUE_PER_GAS: 0.000001
  }
};

// --- Configuración de Orígenes ---
const allowedOrigins = FRONTEND_ORIGINS_RAW.split(',').map(s => s.trim()).filter(Boolean);
console.log('🌐 Orígenes configurados:', allowedOrigins);

// --- Esquemas Mongoose ---

// PlayerAuth para autenticación - CORREGIDO: REMOVER TTL INDEX
const playerAuthSchema = new mongoose.Schema({
  address: { type: String, required: true, unique: true, index: true },
  playerName: { type: String, default: null },
  nonce: { type: String, default: null },
  nonceTimestamp: { type: Date, default: null },
  refreshTokenHash: { type: String, default: null },
  refreshTokenId: { type: String, default: null, index: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: null },
  loginAttempts: { type: Number, default: 0 },
  loginBlockedUntil: { type: Date, default: null },
  transactionCount: { type: Number, default: 0 },
  lastTransaction: { type: Date, default: null }
});

// SOLUCIÓN: REMOVER ESTE ÍNDICE TTL QUE BORRA LOS NONCES
// playerAuthSchema.index({ nonceTimestamp: 1 }, { expireAfterSeconds: 600 });

playerAuthSchema.index({ refreshTokenId: 1 });
// Mantener solo el índice de refreshTokenId

const PlayerAuth = mongoose.model('PlayerAuth', playerAuthSchema);

// Rate Limit tracking
const rateLimitSchema = new mongoose.Schema({
  ip: { type: String, required: true, index: true },
  endpoint: { type: String, required: true },
  count: { type: Number, default: 1 },
  firstAttempt: { type: Date, default: Date.now },
  lastAttempt: { type: Date, default: Date.now },
  blockedUntil: { type: Date, default: null }
});
const RateLimit = mongoose.model('RateLimit', rateLimitSchema);

// Game data model (Player)
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
  moneda_plata: { type: Number, default: 100000 },
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

// Admin config
const adminSchema = new mongoose.Schema({
  _id: { type: String, default: 'config' },
  hora: { type: String, default: '00:00:00' },
  dia_noche: { type: String, default: 'dia' }
}, { versionKey: false });
const Admin = mongoose.model('Admin', adminSchema);

// MissionsPlayer
const missionsPlayerSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true },
  misionesCompletadas: { type: Number, default: 0 },
  misionesEnProgreso: { type: Number, default: 0 },
  misionesFallidas: { type: Number, default: 0 },
  misiones_granjero: { type: Number, default: 0 },
  estadomision: { type: Number, default: 0 },
  misiones_guardian: { type: Number, default: 0 },
  estadomision1: { type: Number, default: 0 },
}, { timestamps: true });
const MissionsPlayer = mongoose.model('MissionsPlayer', missionsPlayerSchema);

// --- ESQUEMAS DE SEGURIDAD (IP Blocking) ---
const blockedIPSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true, index: true, trim: true },
  subnet: { type: String, index: true },
  reason: { 
    type: String, 
    required: true,
    enum: [
      'failed_attempts',
      'suspicious_activity',
      'malicious_paths',
      'manual_block',
      'dos_attack',
      'brute_force',
      'scanner_detected',
      'geo_block',
      'blacklisted_subnet',
      'auto_block_5_attempts'
    ]
  },
  details: { type: Object, default: {} },
  blockedAt: { type: Date, default: Date.now },
  blockedUntil: { type: Date },
  isPermanent: { type: Boolean, default: false },
  attemptsCount: { type: Number, default: 0 },
  lastAttempt: { type: Date },
  userAgent: { type: String },
  country: { type: String },
  asn: { type: String },
  isp: { type: String }
}, { timestamps: true });

blockedIPSchema.index({ blockedUntil: 1 });
blockedIPSchema.index({ isPermanent: 1 });
blockedIPSchema.index({ blockedAt: -1 });

const BlockedIP = mongoose.model('BlockedIP', blockedIPSchema);

const ipActivitySchema = new mongoose.Schema({
  ip: { type: String, required: true, index: true, trim: true },
  userAgent: { type: String, index: true },
  country: { type: String },
  city: { type: String },
  asn: { type: String },
  isp: { type: String },
  isProxy: { type: Boolean, default: false },
  isTor: { type: Boolean, default: false },
  totalRequests: { type: Number, default: 0 },
  failedRequests: { type: Number, default: 0 },
  successfulRequests: { type: Number, default: 0 },
  suspiciousPaths: { type: [String], default: [] },
  suspiciousCount: { type: Number, default: 0 },
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  requestsLastMinute: { type: Number, default: 0 },
  requestsLastHour: { type: Number, default: 0 },
  failedLastMinute: { type: Number, default: 0 },
  headers: { type: Object, default: {} },
  threatScore: { type: Number, default: 0, min: 0, max: 100 },
  failedAttempts: { type: [Date], default: [] },
  lastFailedAttempt: { type: Date }
}, { timestamps: true });

ipActivitySchema.index({ threatScore: -1 });
ipActivitySchema.index({ lastSeen: -1 });
ipActivitySchema.index({ lastFailedAttempt: -1 });

const IPActivity = mongoose.model('IPActivity', ipActivitySchema);

const securityIncidentSchema = new mongoose.Schema({
  ip: { type: String, required: true, index: true },
  type: { 
    type: String, 
    required: true,
    enum: [
      'brute_force',
      'dos_attempt',
      'path_scanning',
      'sql_injection',
      'xss_attempt',
      'credential_stuffing',
      'api_abuse',
      'scanner_detected',
      'malicious_bot',
      'geo_anomaly',
      'auto_block_triggered'
    ]
  },
  severity: { 
    type: String, 
    required: true,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  details: { type: Object, required: true },
  detectedAt: { type: Date, default: Date.now },
  actionTaken: { 
    type: String,
    enum: ['logged', 'rate_limited', 'blocked_temp', 'blocked_perm', 'notified']
  },
  resolved: { type: Boolean, default: false },
  resolvedAt: { type: Date }
}, { timestamps: true });
const SecurityIncident = mongoose.model('SecurityIncident', securityIncidentSchema);

// Después de la definición del esquema (línea ~1209)
const transactionLogSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  playerName: { type: String, required: true, index: true },
  address: { type: String, lowercase: true },
  category: { type: String, enum: ['interaction', 'items'], required: true },
  name: String,
  quantity: Number,
  hash: { type: String, index: true },
  status: { type: String, enum: ['pending', 'confirmed', 'reverted'], default: 'pending' },
  hiddenData: { type: Object },
  timestamp: Date
}, { timestamps: true });

// AÑADE ESTA LÍNEA:
const TransactionLog = mongoose.model('TransactionLog', transactionLogSchema);

// --- NUEVO ESQUEMA: Relayed Transactions ---
const relayedTransactionSchema = new mongoose.Schema({
  // Identificación
  transactionId: { type: String, required: true, unique: true, index: true },
  internalId: { type: String, required: true, index: true },
  
  // Información del usuario
  playerName: { type: String, required: true, index: true },
  playerAddress: { type: String, required: true, lowercase: true, index: true },
  
  // Información del contrato
  contractName: { type: String, required: true },
  contractAddress: { type: String, required: true, lowercase: true },
  functionName: { type: String, required: true },
  
  // Parámetros
  parameters: { type: Object, required: true },
  decodedParameters: { type: Object, default: {} },
  
  // Estado de la transacción
  status: { 
    type: String, 
    required: true,
    enum: ['pending', 'processing', 'signed', 'broadcasted', 'confirmed', 'failed', 'reverted'],
    default: 'pending',
    index: true
  },
  
  // Información de blockchain
  txHash: { type: String, index: true },
  nonce: { type: Number },
  gasLimit: { type: String },
  gasPrice: { type: String },
  gasUsed: { type: String },
  effectiveGasPrice: { type: String },
  blockNumber: { type: Number, index: true },
  blockHash: { type: String },
  transactionIndex: { type: Number },
  
  // Fechas
  createdAt: { type: Date, default: Date.now, index: true },
  signedAt: { type: Date },
  broadcastedAt: { type: Date },
  confirmedAt: { type: Date },
  
  // Costos
  relayerCost: { type: String }, // Costo en wei para el relayer
  estimatedCost: { type: String },
  actualCost: { type: String },
  
  // Información de red
  chainId: { type: Number, default: CHAIN_ID },
  network: { type: String, default: NETWORK_NAME },
  
  // Metadata
  ip: { type: String },
  userAgent: { type: String },
  sessionId: { type: String },
  
  // Resultados y errores
  result: { type: Object },
  error: { type: String },
  revertReason: { type: String },
  logs: { type: Array, default: [] },
  
  // Verificaciones de seguridad
  signatureValidated: { type: Boolean, default: false },
  riskScore: { type: Number, default: 0, min: 0, max: 100 },
  securityFlags: { type: [String], default: [] },
  
  // Indexación
  indexed: { type: Boolean, default: false }
}, { 
  timestamps: true,
  versionKey: false,
  indexes: [
    { playerAddress: 1, status: 1 },
    { createdAt: -1 },
    { contractAddress: 1, functionName: 1 },
    { txHash: 1 },
    { status: 1, createdAt: 1 }
  ]
});

relayedTransactionSchema.index({ 
  playerAddress: 1, 
  contractAddress: 1, 
  functionName: 1,
  createdAt: -1 
});

const RelayedTransaction = mongoose.model('RelayedTransaction', relayedTransactionSchema);

// --- NUEVO ESQUEMA: Contract Whitelist ---
const contractWhitelistSchema = new mongoose.Schema({
  contractAddress: { type: String, required: true, unique: true, lowercase: true, index: true },
  contractName: { type: String, required: true },
  description: { type: String },
  abi: { type: Object, required: true },
  enabled: { type: Boolean, default: true, index: true },
  createdBy: { type: String, default: 'system' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  
  // Configuración de seguridad por contrato
  securityConfig: {
    maxCallsPerHour: { type: Number, default: 100 },
    maxCallsPerDay: { type: Number, default: 1000 },
    requirePlayerOwnership: { type: Boolean, default: false },
    allowedFunctions: { type: [String], default: [] },
    minGasPriceMultiplier: { type: Number, default: 1.2 },
    maxGasLimit: { type: Number, default: 10000000 }
  },
  
  // Estadísticas
  stats: {
    totalCalls: { type: Number, default: 0 },
    successfulCalls: { type: Number, default: 0 },
    failedCalls: { type: Number, default: 0 },
    totalGasUsed: { type: String, default: "0" },
    lastCall: { type: Date }
  }
}, { timestamps: true });

const ContractWhitelist = mongoose.model('ContractWhitelist', contractWhitelistSchema);

// --- NUEVO ESQUEMA: Player Transaction Limits ---
const playerLimitSchema = new mongoose.Schema({
  playerAddress: { type: String, required: true, unique: true, lowercase: true, index: true },
  playerName: { type: String, index: true },
  
  // Límites por período
  limits: {
    hourly: {
      calls: { type: Number, default: 0 },
      maxCalls: { type: Number, default: 30 },
      resetAt: { type: Date }
    },
    daily: {
      calls: { type: Number, default: 0 },
      maxCalls: { type: Number, default: 200 },
      resetAt: { type: Date }
    },
    weekly: {
      calls: { type: Number, default: 0 },
      maxCalls: { type: Number, default: 1000 },
      resetAt: { type: Date }
    }
  },
  
  // Costos acumulados
  totalRelayerCost: { type: String, default: "0" },
  totalGasUsed: { type: String, default: "0" },
  
  // Historial
  lastTransaction: { type: Date },
  firstTransaction: { type: Date },
  
  // Flags de seguridad
  isSuspended: { type: Boolean, default: false },
  suspensionReason: { type: String },
  suspensionUntil: { type: Date },
  
  // Metadata
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const PlayerLimit = mongoose.model('PlayerLimit', playerLimitSchema);

// --- ESQUEMAS ADICIONALES EXISTENTES ---

// Water Collection
const waterCollectionSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true, index: true },
  collectionCount: { type: Number, default: 0 },
  lastCollectionTime: { type: Date, default: null },
  nextAvailableTime: { type: Date, default: null },
  dailyResetTime: { type: Date, default: null },
  collectionCycle: { type: Number, default: 0 },
  isDailyLimitReached: { type: Boolean, default: false },
  totalCollectionsToday: { type: Number, default: 0 }
}, { timestamps: true });
const WaterCollection = mongoose.model('WaterCollection', waterCollectionSchema);

// Transactions
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

// User Activity
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

// Connected Users
const connectedSchema = new mongoose.Schema({ 
  playerName: String, 
  connectedAt: { type: Date, default: Date.now } 
});
const ConnectedUser = mongoose.model('ConnectedUser', connectedSchema);


// ==================== MODELOS PARA EL SISTEMA DE ÁRBOLES ====================

// Porcentaje de deforestación por tipo de árbol
const deforestationSchema = new mongoose.Schema({
  treeType: { 
    type: String, 
    enum: ['pinos', 'arbustos', 'arbolx'], 
    required: true, 
    unique: true 
  },
  percent: { type: Number, default: 0, min: 0, max: 100 }
}, { timestamps: true });
const Deforestation = mongoose.model('Deforestation', deforestationSchema);

// Bloqueo individual de cada árbol (por clave del sprite)
const treeLockSchema = new mongoose.Schema({
  treeKey: { type: String, required: true, unique: true }, // ej. 'sprite_pinos1'
  treeType: { 
    type: String, 
    enum: ['pinos', 'arbustos', 'arbolx'], 
    required: true 
  },
  lockedUntil: { type: Date, default: null } // null = no bloqueado
}, { timestamps: true });
const TreeLock = mongoose.model('TreeLock', treeLockSchema);

// Usos de herramientas (desgaste)
const toolUsesSchema = new mongoose.Schema({
  invoiceId: { type: Number, required: true, unique: true }, // ID de la factura en el contrato
  usos: { type: Number, required: true, min: 0 },
  maxUsos: { type: Number, required: true },
  rota: { type: Boolean, default: false }
}, { timestamps: true });
const ToolUses = mongoose.model('ToolUses', toolUsesSchema);

// Cooldown de merge entre pares de facturas (anti-abuse)
const mergeCooldownSchema = new mongoose.Schema({
  pairKey: { type: String, required: true, unique: true }, // "idA_idB" ordenado
  cooldownUntil: { type: Date, required: true }
}, { timestamps: true });
mergeCooldownSchema.index({ cooldownUntil: 1 });
const MergeCooldown = mongoose.model('MergeCooldown', mergeCooldownSchema);

// Marketplace Listings (P2P market — ver marketplace-routes.js)
const listingSchema = new mongoose.Schema({
  owner: { type: String, required: true, lowercase: true, index: true },   // wallet address del vendedor
  ownerName: { type: String, required: true },                             // playerName del vendedor
  itemId: { type: String, required: true, index: true },                   // clave del catálogo (ej. "mineral_hierro")
  name: { type: String, required: true },                                  // nombre para mostrar
  category: { type: String, required: true, default: 'otros', index: true },
  qty: { type: Number, required: true, min: 1 },
  pricePerUnit: { type: Number, required: true, min: 0.0001 },
  currency: { type: String, enum: ['oro', 'plata'], required: true },
  imageUrl: { type: String, default: '' }
}, { timestamps: true });
listingSchema.index({ category: 1, createdAt: -1 });
const Listing = mongoose.model('Listing', listingSchema);

// Daily Missions
const dailyMissionSchema = new mongoose.Schema({
  npcId: { 
    type: String, 
    required: true,
    enum: ['granjero', 'guardian'],
    index: true 
  },
  day: { 
    type: String, 
    required: true, 
    index: true,
    match: /^\d{4}-\d{2}-\d{2}$/
  },
  missions: [{
    missionId: { type: String, required: true },
    itemId: { type: String, required: true },
    requiredAmount: { type: Number, required: true, min: 1 },
    expReward: { type: Number, required: true, min: 0 },
    rewardItemId: { type: String },
    rewardAmount: { type: Number, min: 1 },
    texts: {
      'en-US': {
        title: String,
        description: String,
        itemName: String,
        rewardName: String
      },
      'en-PH': {
        title: String,
        description: String,
        itemName: String,
        rewardName: String
      },
      'es-419': {
        title: String,
        description: String,
        itemName: String,
        rewardName: String
      },
      'pt-BR': {
        title: String,
        description: String,
        itemName: String,
        rewardName: String
      },
      'zh-CN': {
        title: String,
        description: String,
        itemName: String,
        rewardName: String
      },
      'ko-KR': {
        title: String,
        description: String,
        itemName: String,
        rewardName: String
      }
    }
  }],
  dailyResetHour: { 
    type: Number, 
    default: 0,
    min: 0,
    max: 23
  }
}, { timestamps: true });
const DailyMission = mongoose.model('DailyMission', dailyMissionSchema);

const userDailyProgressSchema = new mongoose.Schema({
  playerName: { type: String, required: true, index: true },
  npcId: { 
    type: String, 
    required: true,
    enum: ['granjero', 'guardian'],
    index: true 
  },
  day: { type: String, required: true, index: true },
  completedMissions: [{
    missionId: String,
    completedAt: { type: Date, default: Date.now },
    claimedReward: Boolean
  }],
  completedCount: { type: Number, default: 0 },
  lastInteraction: { type: Date, default: Date.now }
}, { 
  timestamps: true,
  indexes: [
    { playerName: 1, npcId: 1, day: 1 }
  ]
});
const UserDailyProgress = mongoose.model('UserDailyProgress', userDailyProgressSchema);


 
const mineLockSchema = new mongoose.Schema(
  {
    mineKey:     { type: String, required: true, unique: true, index: true },
    mineralType: {
      type: String,
      required: true,
      enum: ['piedra', 'cobre', 'hierro', 'carbon']
    },
    lockedUntil: { type: Date, required: true, index: true }
  },
  { timestamps: true }
);
const MineLock = mongoose.model('MineLock', mineLockSchema);
 
// ----------
 
const mineDepletionSchema = new mongoose.Schema(
  {
    mineralType: {
      type: String,
      required: true,
      unique: true,
      enum: ['piedra', 'cobre', 'hierro', 'carbon']
    },
    percent: { type: Number, required: true, default: 0, min: 0, max: 100 }
  },
  { timestamps: true }
);
const MineDepletion = mongoose.model('MineDepletion', mineDepletionSchema);



// Error Reports
const errorReportSchema = new mongoose.Schema({
  errorId: { type: String, required: true, unique: true, index: true },
  type: { type: String, required: true },
  message: { type: String, required: true },
  playerName: { type: String, default: 'unknown' },
  timestamp: { type: Date, default: Date.now },
  url: { type: String },
  scene: { type: String },
  userAgent: { type: String },
  phaserVersion: { type: String },
  line: { type: String },
  column: { type: String },
  file: { type: String },
  stack: { type: String },
  count: { type: Number, default: 1 },
  lastSeen: { type: Date, default: Date.now }
}, { timestamps: true });
const ErrorReport = mongoose.model('ErrorReport', errorReportSchema);
// FIX: ERROR_PASSWORD desde variable de entorno — nunca hardcodeada.
// Configura en .env: ERROR_REPORTER_PASSWORD=tu_clave_segura
const ERROR_PASSWORD = process.env.ERROR_REPORTER_PASSWORD;
if (!ERROR_PASSWORD) {
  console.error('❌ ERROR_REPORTER_PASSWORD no configurada en .env — /api/report-error estará desactivado');
}

// Crops System
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
const UserCrop = mongoose.model('UserCrop', UserCropSchema);

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
const CropHistory = mongoose.model('CropHistory', CropHistorySchema);

// Refresh Tokens
const refreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  address: { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true },
  userAgent: { type: String },
  ip: { type: String }
}, { timestamps: true });
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);

// --- CONTROLADOR DE SEGURIDAD CORREGIDO ---
class SecurityController {
  constructor() {
    this.blockedIPs = new Set();
    this.suspiciousIPs = new Map();
    this.failedAttempts = new Map();
    this.geoCache = new Map();
    this.geoCacheTimeout = 3600000;
    
    this.loadBlockedIPs();
    this.startCleanupTimer();
    this.startMonitoring();
    this.startFailedAttemptsCleanup();
    
    console.log('🛡️  Sistema de seguridad avanzado inicializado');
    console.log(`🔧 Modo: ${NODE_ENV} - IPs locales ${NODE_ENV === 'development' ? 'PERMITIDAS' : 'BLOQUEADAS'}`);
  }

  async loadBlockedIPs() {
    try {
      const blocked = await BlockedIP.find({
        $or: [
          { isPermanent: true },
          { blockedUntil: { $gt: new Date() } }
        ]
      });
      
      this.blockedIPs.clear();
      blocked.forEach(record => this.blockedIPs.add(record.ip));
      
      console.log(`🛡️  Cargadas ${blocked.length} IPs bloqueadas`);
    } catch (error) {
      console.error('❌ Error cargando IPs bloqueadas:', error);
    }
  }

  async getGeoInfo(ip) {
    if (!ip || ip === 'undefined' || ip === '0.0.0.0' || ip === '::1' || ip === '::ffff:127.0.0.1') {
      return {
        country: 'Local',
        region: 'Local',
        city: 'Local',
        latitude: null,
        longitude: null,
        timezone: null,
        asn: null,
        isp: 'Local Network',
        proxy: false,
        tor: false
      };
    }
    
    if (this.geoCache.has(ip)) {
      const cached = this.geoCache.get(ip);
      if (Date.now() - cached.timestamp < this.geoCacheTimeout) {
        return cached.data;
      }
    }
    
    const geo = geoip.lookup(ip) || {};
    const geoInfo = {
      country: geo.country || 'Unknown',
      region: geo.region || 'Unknown',
      city: geo.city || 'Unknown',
      latitude: geo.ll?.[0] || null,
      longitude: geo.ll?.[1] || null,
      timezone: geo.timezone || null,
      asn: geo.asn || null,
      isp: geo.isp || 'Unknown',
      proxy: geo.proxy || false,
      tor: geo.tor || false
    };
    
    this.geoCache.set(ip, { data: geoInfo, timestamp: Date.now() });
    return geoInfo;
  }

  isIPInSubnet(ip, subnet) {
    try {
      if (!ip || ip === 'undefined' || ip === '::1' || ip === '::ffff:127.0.0.1') return false;
      
      // En desarrollo, permitir todas las IPs locales
      if (NODE_ENV === 'development') {
        if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
            ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
          return false;
        }
      }
      
      if (subnet.includes('/')) {
        const [subnetIP, mask] = subnet.split('/');
        const subnetBits = parseInt(mask);
        
        const ipToBinary = (ip) => {
          return ip.split('.').reduce((acc, octet) => {
            return acc + parseInt(octet).toString(2).padStart(8, '0');
          }, '');
        };
        
        const ipBinary = ipToBinary(ip);
        const subnetBinary = ipToBinary(subnetIP);
        
        return ipBinary.substring(0, subnetBits) === subnetBinary.substring(0, subnetBits);
      }
      
      return ip === subnet;
    } catch (error) {
      return false;
    }
  }

  isIPBlacklisted(ip) {
    if (!ip || ip === 'undefined' || ip === '::1' || ip === '::ffff:127.0.0.1') return false;
    
    // En desarrollo, NUNCA bloquear IPs locales
    if (NODE_ENV === 'development') {
      if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
          ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        console.log(`✅ IP local permitida en desarrollo: ${ip}`);
        return false;
      }
    }
    
    for (const subnet of SECURITY_CONFIG.BLACKLISTED_SUBNETS) {
      if (this.isIPInSubnet(ip, subnet)) {
        console.log(`🚫 IP ${ip} detectada en subred bloqueada: ${subnet}`);
        return true;
      }
    }
    
    return false;
  }

  async checkAndBlockIP(ip, reason, details = {}) {
    try {
      if (!ip || ip === 'undefined' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        console.warn('⚠️  Intento de bloquear IP inválida o local:', ip);
        return false;
      }

      // En desarrollo, no bloquear IPs locales
      if (NODE_ENV === 'development') {
        if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
            ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
          console.log(`✅ IP local ${ip} protegida de bloqueo en desarrollo`);
          return false;
        }
      }

      const existingBlock = await BlockedIP.findOne({ ip });
      
      if (existingBlock) {
        existingBlock.attemptsCount += 1;
        existingBlock.lastAttempt = new Date();
        existingBlock.details = { ...existingBlock.details, ...details };
        await existingBlock.save();
        
        this.blockedIPs.add(ip);
        return true;
      }
      
      const geoInfo = await this.getGeoInfo(ip);
      
      let blockedUntil = null;
      let isPermanent = false;
      
      switch (reason) {
        case 'blacklisted_subnet':
        case 'dos_attack':
          isPermanent = true;
          break;
        case 'auto_block_5_attempts':
          blockedUntil = new Date(Date.now() + SECURITY_CONFIG.BLOCK_DURATION_MINUTES * 60 * 1000);
          break;
        default:
          blockedUntil = new Date(Date.now() + SECURITY_CONFIG.BLOCK_DURATION_MINUTES * 60 * 1000);
      }
      
      const blockedIP = new BlockedIP({
        ip,
        subnet: this.getSubnetFromIP(ip),
        reason,
        details,
        blockedAt: new Date(),
        blockedUntil,
        isPermanent,
        attemptsCount: 1,
        lastAttempt: new Date(),
        userAgent: details.userAgent,
        country: geoInfo.country,
        asn: geoInfo.asn,
        isp: geoInfo.isp
      });
      
      await blockedIP.save();
      this.blockedIPs.add(ip);
      
      await this.logSecurityIncident(ip, 'api_abuse', 'high', {
        reason,
        details,
        action: 'blocked',
        blockedUntil,
        isPermanent
      });
      
      console.log(`🚫 IP ${ip} bloqueada - Razón: ${reason}`);
      
      if (global.io) {
        global.io.emit('ip_blocked', {
          ip,
          reason,
          blockedUntil,
          details,
          timestamp: new Date()
        });
      }
      
      return true;
      
    } catch (error) {
      console.error('❌ Error bloqueando IP:', error);
      return false;
    }
  }

  getSubnetFromIP(ip) {
    try {
      if (!ip || ip === 'undefined') return ip || '0.0.0.0';
      
      const parts = ip.split('.');
      if (parts.length === 4) {
        return `${parts[0]}.${parts[1]}.0.0/16`;
      }
      return ip;
    } catch (error) {
      return ip;
    }
  }

  async isIPBlocked(ip) {
    if (!ip || ip === 'undefined' || ip === '::1' || ip === '::ffff:127.0.0.1') {
      console.warn('⚠️  IP inválida o local para verificación de bloqueo:', ip);
      return false;
    }
    
    // En desarrollo, no bloquear IPs locales
    if (NODE_ENV === 'development') {
      if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
          ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        return false;
      }
    }
    
    if (this.blockedIPs.has(ip)) {
      return true;
    }
    
    if (this.isIPBlacklisted(ip)) {
      if (!this.blockedIPs.has(ip)) {
        await this.checkAndBlockIP(ip, 'blacklisted_subnet', {
          detectedAt: new Date(),
          autoBlocked: true
        });
      }
      
      return true;
    }
    
    try {
      // FIX: Se eliminó { blockedUntil: null } del $or porque causaba
      // falsos positivos: cualquier registro BlockedIP con blockedUntil=null
      // (registros mal formados o sin expiración definida) bloqueaba la IP
      // aunque no debería estar activa. Ahora solo bloquea IPs que son
      // explícitamente permanentes O cuyo tiempo de bloqueo es futuro.
      const blocked = await BlockedIP.findOne({
        ip,
        $or: [
          { isPermanent: true },
          { blockedUntil: { $gt: new Date() } }
        ]
      });
      
      if (blocked) {
        this.blockedIPs.add(ip);
        return true;
      }

      // Si llegamos aquí, la IP no está bloqueada. Asegurarse de que
      // no esté en el cache en memoria por un bloqueo anterior ya expirado.
      this.blockedIPs.delete(ip);
      return false;
    } catch (error) {
      console.error('❌ Error verificando IP bloqueada:', error);
      return false;
    }
  }

  async trackFailedAttempt(ip, type = 'suspicious_path') {
    try {
      if (!ip || ip === 'undefined' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        console.warn('⚠️  Intento fallido con IP inválida o local:', ip);
        return false;
      }
      
      // En desarrollo, no contar intentos fallidos para IPs locales
      if (NODE_ENV === 'development') {
        if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
            ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
          return false;
        }
      }
      
      const now = new Date();
      const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
      
      if (!this.failedAttempts.has(ip)) {
        this.failedAttempts.set(ip, {
          attempts: [],
          lastAttempt: now
        });
      }
      
      const ipData = this.failedAttempts.get(ip);
      ipData.attempts.push({ timestamp: now, type });
      ipData.lastAttempt = now;
      
      ipData.attempts = ipData.attempts.filter(attempt => 
        attempt.timestamp > fiveMinutesAgo
      );
      
      await IPActivity.findOneAndUpdate(
        { ip },
        { 
          $push: { failedAttempts: now },
          $set: { lastFailedAttempt: now },
          $inc: {
            failedRequests: 1,
            suspiciousCount: type === 'suspicious_path' ? 1 : 0
          }
        },
        { upsert: true, new: true }
      );
      
      if (ipData.attempts.length >= SECURITY_CONFIG.MAX_FAILED_ATTEMPTS) {
        console.log(`🚨 IP ${ip} ha alcanzado ${ipData.attempts.length} intentos fallidos en 5 minutos - BLOQUEANDO`);
        
        await this.checkAndBlockIP(ip, 'auto_block_5_attempts', {
          attempts: ipData.attempts.length,
          attemptsDetails: ipData.attempts,
          window: '5 minutes',
          type: type
        });
        
        await this.logSecurityIncident(ip, 'auto_block_triggered', 'high', {
          attempts: ipData.attempts.length,
          attemptsDetails: ipData.attempts,
          window: '5 minutos',
          type: type,
          action: 'auto_blocked'
        });
        
        this.failedAttempts.delete(ip);
        return true;
      }
      
      return false;
      
    } catch (error) {
      console.error('❌ Error rastreando intento fallido:', error);
      return false;
    }
  }

  async logIPActivity(req, isSuspicious = false, suspiciousPath = null) {
    try {
      const ip = req.clientIp || req.ip;
      
      if (!ip || ip === 'undefined' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        return;
      }
      
      // En desarrollo, no registrar actividad de IPs locales
      if (NODE_ENV === 'development') {
        if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
            ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
          return;
        }
      }
      
      const userAgent = req.headers['user-agent'] || 'unknown';
      const geoInfo = await this.getGeoInfo(ip);
      
      let activity = await IPActivity.findOne({ ip });
      
      if (!activity) {
        activity = new IPActivity({
          ip,
          userAgent,
          country: geoInfo.country,
          city: geoInfo.city,
          asn: geoInfo.asn,
          isp: geoInfo.isp,
          isProxy: geoInfo.proxy,
          isTor: geoInfo.tor,
          firstSeen: new Date()
        });
      }
      
      activity.totalRequests += 1;
      activity.lastSeen = new Date();
      activity.headers = req.headers;
      
      const now = new Date();
      const oneMinuteAgo = new Date(now.getTime() - 60000);
      const oneHourAgo = new Date(now.getTime() - 3600000);
      
      if (activity.lastSeen > oneMinuteAgo) {
        activity.requestsLastMinute += 1;
      } else {
        activity.requestsLastMinute = 1;
      }
      
      if (activity.lastSeen > oneHourAgo) {
        activity.requestsLastHour += 1;
      } else {
        activity.requestsLastHour = 1;
      }
      
      if (isSuspicious) {
        if (suspiciousPath && !activity.suspiciousPaths.includes(suspiciousPath)) {
          activity.suspiciousPaths.push(suspiciousPath);
        }
        activity.suspiciousCount += 1;
        activity.failedRequests += 1;
        activity.failedLastMinute += 1;
      } else {
        activity.successfulRequests += 1;
      }
      
      let threatScore = 0;
      threatScore += Math.min(activity.failedRequests * 2, 30);
      threatScore += Math.min(activity.suspiciousCount * 5, 25);
      
      if (activity.requestsLastMinute > SECURITY_CONFIG.THRESHOLDS.MAX_REQUESTS_PER_MINUTE) {
        threatScore += 20;
      }
      
      if (activity.isProxy) threatScore += 10;
      if (activity.isTor) threatScore += 15;
      
      if (this.isIPBlacklisted(ip)) {
        threatScore += 50;
      }
      
      if (activity.failedAttempts && activity.failedAttempts.length > 0) {
        const recentFailures = activity.failedAttempts.filter(d => 
          new Date(d) > new Date(now.getTime() - 5 * 60 * 1000)
        ).length;
        threatScore += Math.min(recentFailures * 10, 30);
      }
      
      activity.threatScore = Math.min(threatScore, 100);
      await activity.save();
      
    } catch (error) {
      console.error('❌ Error registrando actividad de IP:', error);
    }
  }

  async logSecurityIncident(ip, type, severity, details) {
    try {
      if (!ip || ip === 'undefined' || ip === '::1' || ip === '::ffff:127.0.0.1') return;
      
      // En desarrollo, no registrar incidentes de IPs locales
      if (NODE_ENV === 'development') {
        if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
            ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
          return;
        }
      }
      
      const incident = new SecurityIncident({
        ip,
        type,
        severity,
        details,
        detectedAt: new Date(),
        actionTaken: 'blocked_temp'
      });
      
      await incident.save();
      
      if (severity === 'critical' || severity === 'high') {
        this.sendSecurityAlert(ip, type, details);
      }
      
    } catch (error) {
      console.error('❌ Error registrando incidente de seguridad:', error);
    }
  }

  sendSecurityAlert(ip, type, details) {
    console.log(`🚨 ALERTA DE SEGURIDAD: ${type} desde ${ip}`, details);
    
    if (global.io) {
      global.io.emit('security_alert', {
        ip,
        type,
        severity: 'high',
        details,
        timestamp: new Date(),
        message: `🚨 Alerta de seguridad: ${type} detectado desde ${ip}`
      });
    }
  }

  async analyzeRequest(req, res, next) {
    const ip = req.clientIp || req.ip;
    const path = req.path;
    const userAgent = req.headers['user-agent'] || '';
    
    if (!ip || ip === 'undefined' || ip === '::1' || ip === '::ffff:127.0.0.1') {
      return next();
    }
    
    // En desarrollo, permitir todo a IPs locales
    if (NODE_ENV === 'development') {
      if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
          ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        console.log(`✅ IP local ${ip} permitida sin verificación`);
        return next();
      }
    }
    
    if (this.isIPBlacklisted(ip)) {
      console.log(`🚫 IP ${ip} BLOQUEADA por estar en BLACKLIST`);
      
      await this.checkAndBlockIP(ip, 'blacklisted_subnet', {
        userAgent,
        path,
        method: req.method,
        autoBlocked: true
      });
      
      return res.status(403).json({ 
        error: 'Acceso denegado',
        code: 'BLACKLISTED_IP',
        message: 'Tu dirección IP está en la lista de bloqueadas por seguridad.'
      });
    }
    
    if (await this.isIPBlocked(ip)) {
      console.log(`🚫 IP ${ip} bloqueada en base de datos`);
      await this.logIPActivity(req, true, 'blocked_ip_access');
      return res.status(403).json({ 
        error: 'Acceso denegado',
        code: 'IP_BLOCKED',
        message: 'Tu dirección IP ha sido bloqueada.'
      });
    }
    
    const isSuspiciousPath = this.isSuspiciousPath(path);
    if (isSuspiciousPath) {
      console.log(`⚠️  Ruta sospechosa detectada: ${path} desde ${ip}`);
      await this.logIPActivity(req, true, path);
      await this.logSecurityIncident(ip, 'path_scanning', 'medium', {
        path,
        userAgent,
        method: req.method,
        reason: 'Ruta sospechosa detectada'
      });
      
      const blocked = await this.trackFailedAttempt(ip, 'suspicious_path');
      if (blocked) {
        return res.status(403).json({ 
          error: 'Acceso denegado',
          code: 'AUTO_BLOCKED',
          message: 'Tu dirección IP ha sido bloqueada automáticamente por actividad sospechosa repetida.'
        });
      }
      
      return next();
    }
    
    if (this.isSuspiciousUserAgent(userAgent)) {
      console.log(`⚠️  User agent sospechoso: ${userAgent} desde ${ip}`);
      await this.logIPActivity(req, true, 'suspicious_user_agent');
      await this.logSecurityIncident(ip, 'scanner_detected', 'low', {
        userAgent,
        path,
        method: req.method,
        reason: 'User agent de scanner detectado'
      });
      
      await this.trackFailedAttempt(ip, 'suspicious_user_agent');
    }
    
    await this.logIPActivity(req, false);
    next();
  }

  isSuspiciousPath(path) {
    const normalizedPath = path.toLowerCase();
    
    for (const pattern of SECURITY_CONFIG.SUSPICIOUS_PATHS) {
      if (normalizedPath.includes(pattern.toLowerCase())) {
        return true;
      }
    }
    
    if (normalizedPath.includes('..') || normalizedPath.includes('%2e%2e')) {
      return true;
    }
    
    const dangerousExtensions = ['.php', '.asp', '.aspx', '.jsp', '.pl', '.cgi', '.sh'];
    for (const ext of dangerousExtensions) {
      if (normalizedPath.endsWith(ext)) {
        return true;
      }
    }
    
    return false;
  }

  isSuspiciousUserAgent(userAgent) {
    const ua = userAgent.toLowerCase();
    
    for (const suspicious of SECURITY_CONFIG.SUSPICIOUS_USER_AGENTS) {
      if (ua.includes(suspicious.toLowerCase())) {
        return true;
      }
    }
    
    return false;
  }

  async startCleanupTimer() {
    setInterval(async () => {
      try {
        const result = await BlockedIP.deleteMany({
          isPermanent: false,
          blockedUntil: { $lt: new Date() }
        });
        
        if (result.deletedCount > 0) {
          console.log(`🧹 Limpiadas ${result.deletedCount} IPs bloqueadas expiradas`);
          await this.loadBlockedIPs();
        }
        
        const now = Date.now();
        for (const [ip, data] of this.geoCache.entries()) {
          if (now - data.timestamp > this.geoCacheTimeout) {
            this.geoCache.delete(ip);
          }
        }
        
      } catch (error) {
        console.error('❌ Error en limpieza de seguridad:', error);
      }
    }, 300000);
  }

  startFailedAttemptsCleanup() {
    setInterval(() => {
      const now = new Date();
      const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
      
      for (const [ip, data] of this.failedAttempts.entries()) {
        data.attempts = data.attempts.filter(attempt => 
          attempt.timestamp > fiveMinutesAgo
        );
        
        if (data.attempts.length === 0) {
          this.failedAttempts.delete(ip);
        }
      }
    }, 60000);
  }

  async startMonitoring() {
    setInterval(async () => {
      try {
        const suspiciousIPs = await IPActivity.find({
          threatScore: { $gte: 60 },
          lastSeen: { $gte: new Date(Date.now() - 300000) }
        }).limit(10);
        
        for (const activity of suspiciousIPs) {
          console.log(`⚠️  IP con alta actividad sospechosa: ${activity.ip} - Score: ${activity.threatScore}`);
        }
      } catch (error) {
        console.error('❌ Error en monitoreo de seguridad:', error);
      }
    }, 60000);
  }

  async getBlockedIPs(page = 1, limit = 20) {
    try {
      const skip = (page - 1) * limit;
      
      const [ips, total] = await Promise.all([
        BlockedIP.find()
          .sort({ blockedAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        BlockedIP.countDocuments()
      ]);
      
      return {
        ips,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      throw error;
    }
  }

  async getIPActivity(ip, page = 1, limit = 50) {
    try {
      const skip = (page - 1) * limit;
      
      const [activity, incidents] = await Promise.all([
        IPActivity.findOne({ ip }).lean(),
        SecurityIncident.find({ ip })
          .sort({ detectedAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean()
      ]);
      
      return {
        activity,
        incidents
      };
    } catch (error) {
      throw error;
    }
  }

  async unblockIP(ip) {
    try {
      const result = await BlockedIP.deleteMany({ ip });
      
      if (result.deletedCount > 0) {
        this.blockedIPs.delete(ip);
        this.failedAttempts.delete(ip);
        console.log(`✅ IP ${ip} desbloqueada`);
        return true;
      }
      
      return false;
    } catch (error) {
      throw error;
    }
  }

  async blockIPManual(ip, reason, durationMinutes = 60, details = {}) {
    try {
      const blockedUntil = durationMinutes > 0 
        ? new Date(Date.now() + durationMinutes * 60 * 1000)
        : null;
      
      const isPermanent = durationMinutes === 0;
      
      return await this.checkAndBlockIP(ip, 'manual_block', {
        ...details,
        blockedUntil,
        permanent: isPermanent,
        manual: true
      });
    } catch (error) {
      throw error;
    }
  }

  async getFailedAttemptsInfo(ip) {
    if (this.failedAttempts.has(ip)) {
      const data = this.failedAttempts.get(ip);
      const now = new Date();
      const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
      
      const recentAttempts = data.attempts.filter(a => a.timestamp > fiveMinutesAgo);
      
      return {
        ip,
        attempts: recentAttempts.length,
        totalAttempts: data.attempts.length,
        lastAttempt: data.lastAttempt,
        recentAttempts: recentAttempts
      };
    }
    
    return {
      ip,
      attempts: 0,
      totalAttempts: 0,
      lastAttempt: null,
      recentAttempts: []
    };
  }
}

const securityController = new SecurityController();

// --- NUEVO: Sistema de Relay Manager MEJORADO ---
class RelayManager {
  constructor() {
    this.pendingTransactions = new Map();
    this.confirmationListeners = new Map();
    this.isProcessing = false;
    this.transactionQueue = [];
    this.processingLock = false;
    this.stats = {
      totalRelayed: 0,
      successful: 0,
      failed: 0,
      totalGasUsed: 0n,
      totalCost: 0n
    };
    
    if (relayerWallet) {
      this.init();
    } else {
      console.warn('⚠️  Relay Manager desactivado - No hay wallet de relayer configurada');
    }
  }
  
  async init() {
    if (!relayerWallet) return;
    
    try {
      // Inicializar whitelist con contratos predefinidos
      await this.initializeWhitelist();
      
      // Iniciar procesador de cola
      this.startQueueProcessor();
      
      // Iniciar limpieza de transacciones viejas
      this.startCleanupInterval();
      
      // Verificar transacciones pendientes al inicio
      await this.recoverPendingTransactions();
      
      console.log('✅ Relay Manager inicializado');
    } catch (error) {
      console.error('❌ Error inicializando Relay Manager:', error);
    }
  }
  
  async initializeWhitelist() {
    console.log('🔄 Inicializando whitelist de contratos con validación mejorada...');

    // Usar los valores globales configurables vía .env
    const DEFAULT_MIN_GAS_PRICE_GWEI = process.env.DEFAULT_MIN_GAS_PRICE_GWEI || "5";
    const DEFAULT_FALLBACK_GAS_PRICE_GWEI = process.env.DEFAULT_FALLBACK_GAS_PRICE_GWEI || "50";
    const DEFAULT_GAS_PRICE_MULTIPLIER = Number(process.env.DEFAULT_GAS_PRICE_MULTIPLIER || "1.0");

    let agregados = 0;
    let omitidos = 0;

    for (const [key, contract] of Object.entries(CONTRACTS)) {
      console.log(`📝 Procesando contrato: ${key} - ${contract.name} - Dirección: ${contract.address}`);

      const isValidAddress = contract.address &&
                             contract.address !== '0x...' &&
                             /^0x[a-fA-F0-9]{40}$/.test(contract.address);

      if (!isValidAddress) {
        console.warn(`⚠️  Contrato ${contract.name} (${key}) no tiene una dirección válida (${contract.address}). Se omite.`);
        omitidos++;
        continue;
      }

      if (!contract.abi || contract.abi.length === 0) {
        console.warn(`⚠️  Contrato ${contract.name} (${key}) tiene ABI vacío. Se agregará pero puede no funcionar correctamente.`);
      }

      const envPrefix = contract.name.toString().toUpperCase().replace(/[^A-Z0-9]+/g, '_');
      const contractMinGasPriceGwei = Number(process.env[`${envPrefix}_MIN_GAS_PRICE_GWEI`] || DEFAULT_MIN_GAS_PRICE_GWEI);
      const contractFallbackGasPriceGwei = Number(process.env[`${envPrefix}_FALLBACK_GAS_PRICE_GWEI`] || DEFAULT_FALLBACK_GAS_PRICE_GWEI);
      const contractGasPriceMultiplier = Number(process.env[`${envPrefix}_GAS_PRICE_MULTIPLIER`] || DEFAULT_GAS_PRICE_MULTIPLIER);

      let securityConfig = {
        maxCallsPerHour: 100,
        maxCallsPerDay: 1000,
        requirePlayerOwnership: false,
        allowedFunctions: [],
        minGasPriceMultiplier: 1.0,      // 🔥 Cambiado de 3.0 a 1.0 (configurable por contrato si se desea)
        maxGasLimit: 10000000,
        minGasPriceGwei: contractMinGasPriceGwei,
        fallbackGasPriceGwei: contractFallbackGasPriceGwei,
        gasPriceMultiplier: contractGasPriceMultiplier
      };

      // Configuraciones específicas por nombre de contrato (ya sin valores fijos agresivos)
      switch (contract.name) {
        case 'SecureMessageLogger':
          securityConfig = {
            maxCallsPerHour: 100,
            maxCallsPerDay: 1000,
            requirePlayerOwnership: false,
            allowedFunctions: ['logMessage', 'getMessage', 'messageCount'],
            minGasPriceMultiplier: 1.0,   // 🔥 Ahora 1.0 por defecto
            maxGasLimit: 2500000,
            minGasPriceGwei: Number(process.env['SECUREMESSAGELOGGER_MIN_GAS_PRICE_GWEI'] || DEFAULT_MIN_GAS_PRICE_GWEI),
            fallbackGasPriceGwei: Number(process.env['SECUREMESSAGELOGGER_FALLBACK_GAS_PRICE_GWEI'] || DEFAULT_FALLBACK_GAS_PRICE_GWEI),
            gasPriceMultiplier: Number(process.env['SECUREMESSAGELOGGER_GAS_PRICE_MULTIPLIER'] || DEFAULT_GAS_PRICE_MULTIPLIER)
          };
          console.log(`🔧 Configuración especial aplicada para ${contract.name}`);
          break;

        case 'ItemContract':
          securityConfig = {
            maxCallsPerHour: 50,
            maxCallsPerDay: 500,
            requirePlayerOwnership: true,
            allowedFunctions: [
              'createInvoice',
              'setLimit',
              'increaseInvoiceQuantity',
              'decreaseInvoiceQuantity',
              'deleteInvoice',
              'deprecateTipo',
              'transferInvoice',
              'transferQuantityBetweenInvoices',
              'getInvoice',
              'getInvoiceByManualId',
              'getTipoStats',
              'getUserInventorySnapshot',
              'getActiveInvoiceIds'
            ],
            minGasPriceMultiplier: 1.0,
            maxGasLimit: 10000000,
            minGasPriceGwei: Number(process.env['ITEMCONTRACT_MIN_GAS_PRICE_GWEI'] || DEFAULT_MIN_GAS_PRICE_GWEI),
            fallbackGasPriceGwei: Number(process.env['ITEMCONTRACT_FALLBACK_GAS_PRICE_GWEI'] || DEFAULT_FALLBACK_GAS_PRICE_GWEI),
            gasPriceMultiplier: Number(process.env['ITEMCONTRACT_GAS_PRICE_MULTIPLIER'] || DEFAULT_GAS_PRICE_MULTIPLIER)
          };
          console.log(`🔧 Configuración especial aplicada para ${contract.name}`);
          break;

        default:
          securityConfig.minGasPriceGwei = contractMinGasPriceGwei;
          securityConfig.fallbackGasPriceGwei = contractFallbackGasPriceGwei;
          securityConfig.gasPriceMultiplier = contractGasPriceMultiplier;
          console.log(`⚙️ Usando configuración por defecto (con overrides .env) para ${contract.name}`);
      }

      console.log(`   - minGasPriceGwei: ${securityConfig.minGasPriceGwei} gwei`);
      console.log(`   - fallbackGasPriceGwei: ${securityConfig.fallbackGasPriceGwei} gwei`);
      console.log(`   - gasPriceMultiplier: ${securityConfig.gasPriceMultiplier}`);
      console.log(`   - maxGasLimit: ${securityConfig.maxGasLimit}`);

      const existing = await ContractWhitelist.findOne({
        contractAddress: contract.address.toLowerCase()
      });

      if (!existing) {
        console.log(`➕ Agregando ${contract.name} a whitelist...`);
        await ContractWhitelist.create({
          contractAddress: contract.address.toLowerCase(),
          contractName: contract.name,
          description: contract.description || `Contrato ${contract.name}`,
          abi: contract.abi,
          enabled: true,
          securityConfig: securityConfig,
          stats: {
            totalCalls: 0,
            successfulCalls: 0,
            failedCalls: 0,
            totalGasUsed: '0',
            lastCall: null
          }
        });
        console.log(`✅ ${contract.name} añadido a whitelist`);
        agregados++;
      } else {
        console.log(`🔄 Contrato ${contract.name} ya existe, actualizando configuración de seguridad...`);
        await ContractWhitelist.updateOne(
          { contractAddress: contract.address.toLowerCase() },
          {
            $set: {
              securityConfig: securityConfig,
              updatedAt: new Date()
            }
          }
        );
        console.log(`✅ ${contract.name} actualizado en whitelist`);
        agregados++;
      }
    }

    const totalHabilitados = await ContractWhitelist.countDocuments({ enabled: true });
    console.log(`✅ Whitelist inicializada. Procesados: ${agregados} contratos (omitidos: ${omitidos}). Total habilitados: ${totalHabilitados}`);
  }

  async recoverPendingTransactions() {
    if (!relayerWallet) return;
    
    try {
      const pendingTxs = await RelayedTransaction.find({
        status: { $in: ['pending', 'processing', 'signed', 'broadcasted'] },
        createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Últimas 24h
      }).limit(100);
      
      if (pendingTxs.length > 0) {
        console.log(`🔄 Recuperando ${pendingTxs.length} transacciones pendientes`);
        
        for (const tx of pendingTxs) {
          // Verificar estado en blockchain
          try {
            if (tx.txHash) {
              const receipt = await provider.getTransactionReceipt(tx.txHash);
              
              if (receipt) {
                if (receipt.status === 1) {
                  tx.status = 'confirmed';
                  tx.blockNumber = receipt.blockNumber;
                  tx.gasUsed = receipt.gasUsed.toString();
                  tx.confirmedAt = new Date();
                } else {
                  tx.status = 'reverted';
                  tx.gasUsed = receipt.gasUsed.toString();
                  tx.revertReason = 'Transaction reverted';
                }
                await tx.save();
              } else {
                // Transacción no minada, reenviar
                if (tx.status === 'broadcasted' && tx.createdAt < new Date(Date.now() - 5 * 60 * 1000)) {
                  console.log(`🔄 Reenviando transacción ${tx.transactionId}`);
                  await this.processTransactionFromQueue(tx);
                }
              }
            }
          } catch (error) {
            console.error(`❌ Error recuperando tx ${tx.transactionId}:`, error.message);
          }
        }
      }
    } catch (error) {
      console.error('❌ Error en recoverPendingTransactions:', error);
    }
  }
  
  async addToQueue(transactionData) {
    const queueItem = {
      id: uuidv4(),
      data: transactionData,
      timestamp: Date.now(),
      priority: transactionData.priority || 'normal'
    };
    
    this.transactionQueue.push(queueItem);
    
    // Ordenar por prioridad
    this.transactionQueue.sort((a, b) => {
      const priorityOrder = { high: 0, normal: 1, low: 2 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });
    
    return queueItem.id;
  }
  
  startQueueProcessor() {
    if (!relayerWallet) return;
    
    setInterval(async () => {
      if (this.processingLock || this.transactionQueue.length === 0) return;
      
      this.processingLock = true;
      
      try {
        // Procesar hasta 5 transacciones por intervalo
        const batchSize = 5;
        const itemsToProcess = this.transactionQueue.splice(0, batchSize);
        
        for (const item of itemsToProcess) {
          try {
            await this.processTransaction(item.data);
          } catch (error) {
            console.error(`❌ Error procesando transacción ${item.id}:`, error);
            
            // Reintentar si es un error temporal
            if (this.shouldRetry(error)) {
              item.data.retryCount = (item.data.retryCount || 0) + 1;
              if (item.data.retryCount <= 3) {
                item.timestamp = Date.now() + (item.data.retryCount * 5000); // Esperar 5s, 10s, 15s
                this.transactionQueue.push(item);
              }
            }
          }
        }
      } catch (error) {
        console.error('❌ Error en procesador de cola:', error);
      } finally {
        this.processingLock = false;
      }
    }, 1000); // Procesar cada segundo
  }
  
  shouldRetry(error) {
    const retryableErrors = [
      'nonce too low',
      'replacement transaction underpriced',
      'transaction underpriced',
      'insufficient funds',
      'network error',
      'timeout'
    ];
    
    return retryableErrors.some(msg => 
      error.message?.toLowerCase().includes(msg.toLowerCase())
    );
  }
  
  // PROTECCIÓN CONTRA GAS DRAIN
  async validateGasParameters(gasLimit, gasPrice) {
    // Verificar límites de gas
    const maxGasLimit = BigInt(SECURITY_CONFIG.THRESHOLDS.MAX_GAS_LIMIT);
    if (gasLimit > maxGasLimit) {
      throw new Error(`Gas limit ${gasLimit} excede el máximo permitido ${maxGasLimit}`);
    }
    
    // Verificar precio de gas (convertir a gwei)
    const gasPriceInGwei = Number(ethers.formatUnits(gasPrice, 'gwei'));
    if (gasPriceInGwei > SECURITY_CONFIG.THRESHOLDS.MAX_GAS_PRICE_GWEI) {
      throw new Error(`Gas price ${gasPriceInGwei} gwei excede el máximo permitido ${SECURITY_CONFIG.THRESHOLDS.MAX_GAS_PRICE_GWEI} gwei`);
    }
    
    // Verificar relación valor/gas
    const minValuePerGas = SECURITY_CONFIG.THRESHOLDS.MIN_VALUE_PER_GAS;
    // Aquí podrías añadir más validaciones específicas
    
    return true;
  }
  
  async processTransaction(transactionData) {
    if (!relayerWallet) {
      throw new Error('Relayer no configurado');
    }
    
    const {
      playerAddress,
      playerName,
      contractAddress,
      contractName,
      functionName,
      parameters,
      ip,
      userAgent,
      sessionId
    } = transactionData;
    
    const transactionId = `relay_${uuidv4()}`;
    const internalId = crypto.createHash('sha256').update(transactionId).digest('hex');
    
    const relayTx = new RelayedTransaction({
      transactionId,
      internalId,
      playerAddress,
      playerName,
      contractName,
      contractAddress: contractAddress.toLowerCase(),
      functionName,
      parameters,
      status: 'processing',
      ip,
      userAgent,
      sessionId,
      chainId: CHAIN_ID,
      network: NETWORK_NAME
    });
    
    await relayTx.save();
      
    try {
      // 1. Verificar whitelist del contrato
      const whitelisted = await ContractWhitelist.findOne({
        contractAddress: contractAddress.toLowerCase(),
        enabled: true
      });
      
      if (!whitelisted) {
        throw new Error(`Contract ${contractAddress} is not whitelisted`);
      }
      
      // 2. Verificar límites del jugador
      const canCall = await this.checkPlayerLimits(playerAddress, contractAddress, functionName);
      if (!canCall.allowed) {
        throw new Error(`Player limit exceeded: ${canCall.reason}`);
      }
      
      // 3. Preparar transacción
      const contract = new ethers.Contract(
        contractAddress,
        whitelisted.abi,
        relayerWallet
      );
      
      // Verificar que la función existe
      if (!contract[functionName]) {
        throw new Error(`Function ${functionName} not found in contract ABI`);
      }
      
      // 4. Obtener nonce
      const nonce = await relayerNonceManager.getNextNonce();
      relayTx.nonce = nonce;
      
      // 5. Estimar gas
      let gasLimit;
      try {
        const args = Object.values(parameters);
        gasLimit = await contract[functionName].estimateGas(...args);
        
        // Añadir margen de seguridad (20%)
        gasLimit = (gasLimit * 120n) / 100n;
        
        // Aplicar límite máximo
        const maxGas = BigInt(whitelisted.securityConfig.maxGasLimit || 500000);
        if (gasLimit > maxGas) {
          gasLimit = maxGas;
        }
        
        // Validar parámetros de gas
        await this.validateGasParameters(gasLimit, 0n); // El precio se validará después
      } catch (estimateError) {
        console.warn(`⚠️  Error estimando gas, usando valor por defecto:`, estimateError.message);
        gasLimit = 10000000n; // Valor por defecto seguro
      }
      
      // 6. Obtener gas price con multiplicador
      let gasPrice;
      if (FIXED_GAS_PRICE_GWEI !== null) {
        gasPrice = ethers.parseUnits(FIXED_GAS_PRICE_GWEI.toString(), 'gwei');
        console.log(`   - ⚙️ Gas price fijo (FIXED_GAS_PRICE_GWEI): ${FIXED_GAS_PRICE_GWEI} gwei`);
      } else {
        const feeData = await provider.getFeeData();
        gasPrice = feeData.gasPrice || await provider.getGasPrice();
        console.log(`   - Gas price base: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);

        // Aplicar multiplicador de seguridad
        const multiplier = whitelisted.securityConfig.gasPriceMultiplier || GAS_PRICE_MULTIPLIER;
        gasPrice = (gasPrice * BigInt(Math.floor(multiplier * 100))) / 100n;

        const minGasPrice = ethers.parseUnits(MIN_GAS_PRICE_GWEI, "gwei");
        if (gasPrice < minGasPrice) {
          gasPrice = minGasPrice;
          console.log(`   - Gas price elevado al mínimo (env): ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
        } else {
          console.log(`   - Gas price obtenido: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
        }
      }
      
      // Validar precio de gas
      await this.validateGasParameters(gasLimit, gasPrice);
      
      // 7. Construir transacción
      const args = Object.values(parameters);
      const tx = await contract[functionName].populateTransaction(...args);
      
      tx.nonce = nonce;
      tx.gasLimit = gasLimit;
      tx.gasPrice = gasPrice;
      tx.chainId = CHAIN_ID;
      
      // 8. Calcular costo estimado
      const estimatedCost = gasLimit * gasPrice;
      relayTx.estimatedCost = estimatedCost.toString();
      relayTx.gasLimit = gasLimit.toString();
      relayTx.gasPrice = gasPrice.toString();
      
      // 9. Verificar saldo del relayer
      const relayerBalance = await provider.getBalance(relayerWallet.address);
      if (relayerBalance < estimatedCost) {
        throw new Error(`Relayer insufficient balance: ${ethers.formatEther(relayerBalance)} < ${ethers.formatEther(estimatedCost)}`);
      }
      
      // 10. APLICAR TIME-LOCK SI ES NECESARIO (para transacciones grandes)
      if (estimatedCost > ethers.parseEther("0.1")) { // Más de 0.1 ETH
        console.log(`⏰ Aplicando time-lock para transacción grande: ${ethers.formatEther(estimatedCost)} ETH`);
        await multiSigManager.requireTimeLock(relayTx, 20); // 5 minutos de delay
      }
      
      relayTx.status = 'signed';
      relayTx.signedAt = new Date();
      await relayTx.save();
      
      // 11. Firmar y enviar
      const signedTx = await relayerWallet.signTransaction(tx);
      const txResponse = await provider.broadcastTransaction(signedTx);
      
      relayTx.status = 'broadcasted';
      relayTx.txHash = txResponse.hash;
      relayTx.broadcastedAt = new Date();
      await relayTx.save();
      
      // 12. Actualizar estadísticas
      this.stats.totalRelayed++;
      await this.updatePlayerLimits(playerAddress, true);
      await this.updateContractStats(contractAddress, true);
      
      // 13. Esperar confirmación (no bloqueante)
      this.waitForConfirmation(txResponse.hash, relayTx);
      
      return {
        success: true,
        transactionId,
        txHash: txResponse.hash,
        nonce,
        estimatedCost: estimatedCost.toString(),
        message: 'Transaction relayed successfully'
      };
      
    } catch (error) {
      console.error(`❌ Error en processTransaction:`, error);
      
      relayTx.status = 'failed';
      relayTx.error = error.message;
      await relayTx.save();
      
      // Actualizar estadísticas de error
      await this.updatePlayerLimits(playerAddress, false);
      await this.updateContractStats(contractAddress, false);
      
      this.stats.failed++;
      
      throw error;
    }
  }
  
  async checkPlayerLimits(playerAddress, contractAddress, functionName) {
    try {
      let playerLimit = await PlayerLimit.findOne({ playerAddress });
      
      if (!playerLimit) {
        playerLimit = new PlayerLimit({
          playerAddress,
          'limits.hourly.resetAt': new Date(Date.now() + 60 * 60 * 1000),
          'limits.daily.resetAt': new Date(Date.now() + 24 * 60 * 60 * 1000),
          'limits.weekly.resetAt': new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });
        await playerLimit.save();
      }
      
      // Verificar suspensión
      if (playerLimit.isSuspended) {
        if (playerLimit.suspensionUntil && playerLimit.suspensionUntil > new Date()) {
          return {
            allowed: false,
            reason: `Player suspended until ${playerLimit.suspensionUntil}`
          };
        } else {
          // Suspensión expirada
          playerLimit.isSuspended = false;
          playerLimit.suspensionReason = '';
          playerLimit.suspensionUntil = null;
        }
      }
      
      // Verificar y resetear límites si es necesario
      const now = new Date();
      
      // Límite por hora
      if (!playerLimit.limits.hourly.resetAt || playerLimit.limits.hourly.resetAt <= now) {
        playerLimit.limits.hourly.calls = 0;
        playerLimit.limits.hourly.resetAt = new Date(now.getTime() + 60 * 60 * 1000);
      }
      
      // Límite diario
      if (!playerLimit.limits.daily.resetAt || playerLimit.limits.daily.resetAt <= now) {
        playerLimit.limits.daily.calls = 0;
        playerLimit.limits.daily.resetAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);
      }
      
      // Límite semanal
      if (!playerLimit.limits.weekly.resetAt || playerLimit.limits.weekly.resetAt <= now) {
        playerLimit.limits.weekly.calls = 0;
        playerLimit.limits.weekly.resetAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      }
      
      // Verificar límites
      if (playerLimit.limits.hourly.calls >= playerLimit.limits.hourly.maxCalls) {
        return { allowed: false, reason: 'Hourly limit exceeded' };
      }
      
      if (playerLimit.limits.daily.calls >= playerLimit.limits.daily.maxCalls) {
        return { allowed: false, reason: 'Daily limit exceeded' };
      }
      
      if (playerLimit.limits.weekly.calls >= playerLimit.limits.weekly.maxCalls) {
        return { allowed: false, reason: 'Weekly limit exceeded' };
      }
      
      // Verificar contrato específico en whitelist
      const whitelisted = await ContractWhitelist.findOne({
        contractAddress: contractAddress.toLowerCase(),
        enabled: true
      });
      
      if (whitelisted) {
        // Verificar función permitida
        if (whitelisted.securityConfig.allowedFunctions.length > 0 &&
            !whitelisted.securityConfig.allowedFunctions.includes(functionName)) {
          return { allowed: false, reason: `Function ${functionName} not allowed for this contract` };
        }
      }
      
      return { allowed: true };
      
    } catch (error) {
      console.error('❌ Error en checkPlayerLimits:', error);
      return { allowed: false, reason: 'Internal error checking limits' };
    }
  }
  
  async updatePlayerLimits(playerAddress, success) {
    try {
      const playerLimit = await PlayerLimit.findOne({ playerAddress });
      if (!playerLimit) return;
      
      const now = new Date();
      
      // Actualizar contadores
      playerLimit.limits.hourly.calls += 1;
      playerLimit.limits.daily.calls += 1;
      playerLimit.limits.weekly.calls += 1;
      
      playerLimit.lastTransaction = now;
      if (!playerLimit.firstTransaction) {
        playerLimit.firstTransaction = now;
      }
      
      await playerLimit.save();
      
    } catch (error) {
      console.error('❌ Error en updatePlayerLimits:', error);
    }
  }
  
  async updateContractStats(contractAddress, success) {
    try {
      await ContractWhitelist.findOneAndUpdate(
        { contractAddress: contractAddress.toLowerCase() },
        {
          $inc: {
            'stats.totalCalls': 1,
            [`stats.${success ? 'successfulCalls' : 'failedCalls'}`]: 1
          },
          $set: { 'stats.lastCall': new Date() }
        }
      );
    } catch (error) {
      console.error('❌ Error en updateContractStats:', error);
    }
  }
  
  async waitForConfirmation(txHash, relayTx) {
    if (!relayerWallet) return;
    
    try {
      console.log(`⏳ Esperando confirmación para ${txHash}`);
      
      const receipt = await provider.waitForTransaction(txHash, 1, 30000); // 30s timeout
      
      if (receipt) {
        relayTx.status = receipt.status === 1 ? 'confirmed' : 'reverted';
        relayTx.blockNumber = receipt.blockNumber;
        relayTx.blockHash = receipt.blockHash;
        relayTx.transactionIndex = receipt.index;
        relayTx.gasUsed = receipt.gasUsed.toString();
        
        const effectiveGasPriceStr = receipt.effectiveGasPrice?.toString();
        relayTx.effectiveGasPrice = effectiveGasPriceStr;
        
        if (receipt.gasUsed && receipt.effectiveGasPrice) {
          const gasUsedBigInt = BigInt(receipt.gasUsed.toString());
          const effectiveGasPriceBigInt = BigInt(effectiveGasPriceStr);
          const actualCost = gasUsedBigInt * effectiveGasPriceBigInt;
          relayTx.actualCost = actualCost.toString();
          
          if (receipt.status === 1) {
            this.stats.successful++;
            this.stats.totalGasUsed += gasUsedBigInt;
            this.stats.totalCost += actualCost;
          } else {
            this.stats.failed++;
          }
        } else {
          relayTx.actualCost = "0";
          if (receipt.status === 1) {
            this.stats.successful++;
          } else {
            this.stats.failed++;
          }
        }
        
        relayTx.confirmedAt = new Date();
        relayTx.logs = receipt.logs || [];
        
        if (receipt.status === 0) {
          relayTx.revertReason = 'Transaction reverted by EVM';
        }
        
        await relayTx.save();
        
        console.log(`✅ Transaction ${txHash} ${receipt.status === 1 ? 'confirmed' : 'reversed'} en bloc ${receipt.blockNumber}`);
      }
    } catch (error) {
      console.error(`❌ Error esperando confirmación para ${txHash}:`, error);
      
      relayTx.status = 'failed';
      relayTx.error = `Confirmation timeout: ${error.message}`;
      await relayTx.save();
    }
  }

  async processTransactionFromQueue(relayTx) {
    if (!relayerWallet) return null;
    
    try {
      console.log(`🔄 Reprocesando transacción desde cola: ${relayTx.transactionId}`);
      console.log(`📋 Detalles de la transacción:`);
      console.log(`   - Contrato: ${relayTx.contractAddress}`);
      console.log(`   - Función: ${relayTx.functionName}`);
      console.log(`   - Estado actual: ${relayTx.status}`);
      console.log(`   - Error anterior: ${relayTx.error || 'Ninguno'}`);
      
      // Buscar en whitelist
      const whitelisted = await ContractWhitelist.findOne({
        contractAddress: relayTx.contractAddress.toLowerCase(),
        enabled: true
      });
      
      if (!whitelisted) {
        console.error(`❌ Contrato no encontrado en whitelist: ${relayTx.contractAddress}`);
        throw new Error('Contract not whitelisted');
      }
      
      console.log(`✅ Contrato encontrado en whitelist: ${whitelisted.contractName}`);
      
      // Crear instancia del contrato
      const contract = new ethers.Contract(
        relayTx.contractAddress,
        whitelisted.abi,
        relayerWallet
      );
      
      // Verificar que la función existe
      if (!contract[relayTx.functionName]) {
        console.error(`❌ Función no encontrada en ABI: ${relayTx.functionName}`);
        throw new Error(`Function ${relayTx.functionName} not found in contract ABI`);
      }
      
      // Reutilizar nonce si existe, sino obtener nuevo
      let nonce;
      if (relayTx.nonce && relayTx.nonce > 0) {
        nonce = relayTx.nonce;
        console.log(`🔢 Reutilizando nonce existente: ${nonce}`);
      } else {
        nonce = await relayerNonceManager.getNextNonce();
        console.log(`🔢 Obteniendo nuevo nonce: ${nonce}`);
      }
      
      // ========== CONFIGURACIÓN DE GAS MEJORADA ==========
      let gasLimit;
      let gasPrice;
      
      // Obtener configuración de gas desde metadata si existe
      if (relayTx.metadata && relayTx.metadata.gasConfig) {
        console.log(`⛽ Usando configuración de gas desde metadata`);
        const gasConfig = relayTx.metadata.gasConfig;
        
        if (gasConfig.gasLimit) {
          gasLimit = BigInt(gasConfig.gasLimit);
          console.log(`   - Gas limit desde metadata: ${gasLimit}`);
        }
        
        if (gasConfig.gasPrice) {
          gasPrice = BigInt(gasConfig.gasPrice);
          console.log(`   - Gas price desde metadata: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
        }
      }
      
      // Si no hay configuración de gas en metadata, calcular nuevos valores
      if (!gasLimit || !gasPrice) {
        console.log(`⛽ Calculando nueva configuración de gas`);
        
        // 1. Configurar gas limit
        if (relayTx.functionName === 'logMessage') {
          // Para SimpleMessageLogger, usar límite alto fijo
          gasLimit = 10000000n; // 3 millones de gas para STT
          console.log(`   - Gas limit fijo para logMessage: ${gasLimit}`);
        } else if (relayTx.gasLimit) {
          // Usar el gas limit anterior pero aumentarlo en 200%
          gasLimit = BigInt(relayTx.gasLimit) * 3n / 1n; // Triple para asegurar
          console.log(`   - Gas limit aumentado (200%): ${gasLimit} (anterior: ${relayTx.gasLimit})`);
        } else {
          // Valor por defecto muy alto para STT
          gasLimit = 10000000n; // 3 millones de gas
          console.log(`   - Gas limit por defecto para STT: ${gasLimit}`);
        }
        
        // 2. Configurar gas price
        try {
          if (FIXED_GAS_PRICE_GWEI !== null) {
            gasPrice = ethers.parseUnits(FIXED_GAS_PRICE_GWEI.toString(), 'gwei');
            console.log(`   - ⚙️ Gas price fijo (FIXED_GAS_PRICE_GWEI): ${FIXED_GAS_PRICE_GWEI} gwei`);
          } else {
            const feeData = await provider.getFeeData();
            gasPrice = feeData.gasPrice || await provider.getGasPrice();
            console.log(`   - Gas price base: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);

            const multiplier = Number(process.env.GAS_PRICE_MULTIPLIER || "1.0");
            gasPrice = (gasPrice * BigInt(Math.floor(multiplier * 100))) / 100n;

            const minGasPrice = ethers.parseUnits(MIN_GAS_PRICE_GWEI, "gwei");
            if (gasPrice < minGasPrice) {
              gasPrice = minGasPrice;
              console.log(`   - Gas price elevado al mínimo (env): ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
            } else {
              console.log(`   - Gas price obtenido: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
            }
          }
        } catch (gasError) {
          console.warn(`⚠️ Error obteniendo gas price, usando valor fijo:`, gasError.message);
          gasPrice = ethers.parseUnits(FALLBACK_GAS_PRICE_GWEI, "gwei");
          console.log(`   - Gas price fijo (env): ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
        }
      }
      
      // 3. Verificar límites de gas para STT
      await this.validateGasParameters(gasLimit, gasPrice);
      
      // Calcular costo estimado en STT
      const estimatedCost = gasLimit * gasPrice;
      console.log(`💰 Costo estimado en STT: ${ethers.formatEther(estimatedCost)} STT`);
      console.log(`📊 Detalles de gas finales:`);
      console.log(`   - Gas Limit: ${gasLimit}`);
      console.log(`   - Gas Price: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
      console.log(`   - Costo Total: ${ethers.formatEther(estimatedCost)} STT`);
      
      // 4. Verificar saldo del relayer en STT
      const relayerBalance = await provider.getBalance(relayerWallet.address);
      console.log(`💰 Saldo del relayer: ${ethers.formatEther(relayerBalance)} STT`);
      
      if (relayerBalance < estimatedCost) {
        const errorMsg = `Relayer insufficient STT balance: ${ethers.formatEther(relayerBalance)} < ${ethers.formatEther(estimatedCost)}`;
        console.error(`❌ ${errorMsg}`);
        
        relayTx.status = 'failed';
        relayTx.error = errorMsg;
        await relayTx.save();
        
        throw new Error(errorMsg);
      }
      
      // 5. Preparar parámetros para la transacción
      console.log(`📝 Preparando parámetros para ${relayTx.functionName}`);
      const args = Object.values(relayTx.parameters);
      
      if (relayTx.functionName === 'logMessage') {
        console.log(`📋 Parámetros específicos para logMessage:`);
        console.log(`   - _message: ${relayTx.parameters._message}`);
        console.log(`   - _userNonce: ${relayTx.parameters._userNonce} (tipo: ${typeof relayTx.parameters._userNonce})`);
        
        if (args[1] && typeof args[1] !== 'string') {
          args[1] = args[1].toString();
          console.log(`   - _userNonce convertido a string: ${args[1]}`);
        }
      }
      
      // 6. Construir transacción
      console.log(`🔨 Construyendo transacción...`);
      const tx = await contract[relayTx.functionName].populateTransaction(...args);
      
      tx.nonce = nonce;
      tx.gasLimit = gasLimit;
      tx.gasPrice = gasPrice;
      tx.chainId = CHAIN_ID;
      
      console.log(`✅ Transacción construida:`);
      console.log(`   - Nonce: ${nonce}`);
      console.log(`   - Chain ID: ${CHAIN_ID}`);
      console.log(`   - To: ${relayTx.contractAddress}`);
      
      // 7. Firmar transacción
      console.log(`✍️ Firmando transacción...`);
      const signedTx = await relayerWallet.signTransaction(tx);
      console.log(`✅ Transacción firmada`);
      
      // 8. Enviar transacción
      console.log(`📤 Enviando transacción a la red Somnia...`);
      const txResponse = await provider.broadcastTransaction(signedTx);
      
      console.log(`🎉 Transacción enviada exitosamente!`);
      console.log(`📝 Hash: ${txResponse.hash}`);
      console.log(`🔗 Explorer URL: ${EXPLORER_URL}/tx/${txResponse.hash}`);
      
      // 9. Actualizar estado de la transacción
      relayTx.status = 'broadcasted';
      relayTx.txHash = txResponse.hash;
      relayTx.nonce = nonce;
      relayTx.gasLimit = gasLimit.toString();
      relayTx.gasPrice = gasPrice.toString();
      relayTx.estimatedCost = estimatedCost.toString();
      relayTx.broadcastedAt = new Date();
      
      const retryCount = (relayTx.retryCount || 0) + 1;
      relayTx.retryCount = retryCount;
      relayTx.lastRetryAt = new Date();
      
      if (!relayTx.retryHistory) {
        relayTx.retryHistory = [];
      }
      relayTx.retryHistory.push({
        retryNumber: retryCount,
        timestamp: new Date(),
        gasLimit: gasLimit.toString(),
        gasPrice: gasPrice.toString(),
        nonce: nonce,
        status: 'broadcasted'
      });
      
      await relayTx.save();
      
      console.log(`📊 Transacción actualizada en BD con nuevo estado`);
      console.log(`   - Retry count: ${retryCount}`);
      console.log(`   - Nuevo gas limit: ${gasLimit}`);
      console.log(`   - Nuevo gas price: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
      
      if (global.io) {
        global.io.emit('transaction_retried', {
          transactionId: relayTx.transactionId,
          txHash: txResponse.hash,
          playerAddress: relayTx.playerAddress,
          contractAddress: relayTx.contractAddress,
          functionName: relayTx.functionName,
          retryCount: retryCount,
          gasLimit: gasLimit.toString(),
          gasPrice: gasPrice.toString(),
          estimatedCost: estimatedCost.toString(),
          timestamp: new Date()
        });
      }
      
      console.log(`⏳ Iniciando seguimiento de confirmación...`);
      this.waitForConfirmation(txResponse.hash, relayTx);
      
      return txResponse.hash;
      
    } catch (error) {
      console.error(`❌ Error crítico en processTransactionFromQueue:`, error);
      console.error(`📋 Detalles del error:`, {
        transactionId: relayTx?.transactionId,
        contractAddress: relayTx?.contractAddress,
        functionName: relayTx?.functionName,
        errorMessage: error.message,
        errorStack: error.stack,
        errorCode: error.code
      });
      
      if (relayTx) {
        relayTx.status = 'failed';
        relayTx.error = error.message;
        relayTx.errorDetails = {
          message: error.message,
          stack: error.stack,
          code: error.code,
          timestamp: new Date()
        };
        relayTx.lastErrorAt = new Date();
        
        relayTx.errorCount = (relayTx.errorCount || 0) + 1;
        
        await relayTx.save();
        
        console.log(`📝 Transacción marcada como fallida en BD`);
      }
      
      if (global.io && relayTx) {
        global.io.emit('transaction_retry_failed', {
          transactionId: relayTx.transactionId,
          playerAddress: relayTx.playerAddress,
          contractAddress: relayTx.contractAddress,
          functionName: relayTx.functionName,
          error: error.message,
          errorCount: relayTx.errorCount || 1,
          timestamp: new Date()
        });
      }
      
      throw error;
    }
  }

  startCleanupInterval() {
    // Limpiar transacciones viejas cada hora
    setInterval(async () => {
      try {
        const oneMonthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        
        const result = await RelayedTransaction.deleteMany({
          status: { $in: ['confirmed', 'failed', 'reverted'] },
          createdAt: { $lt: oneMonthAgo }
        });
        
        if (result.deletedCount > 0) {
          console.log(`🧹 Limpiadas ${result.deletedCount} transacciones antiguas`);
        }
      } catch (error) {
        console.error('❌ Error en limpieza de transacciones:', error);
      }
    }, 60 * 60 * 1000);
  }
  
  async getStats() {
    const [
      totalTransactions,
      pendingTransactions,
      playerCount,
      contractCount
    ] = await Promise.all([
      RelayedTransaction.countDocuments(),
      RelayedTransaction.countDocuments({ status: { $in: ['pending', 'processing', 'signed', 'broadcasted'] } }),
      PlayerLimit.countDocuments(),
      ContractWhitelist.countDocuments({ enabled: true })
    ]);
    
    let relayerBalance = '0';
    if (relayerWallet) {
      const balance = await provider.getBalance(relayerWallet.address);
      relayerBalance = ethers.formatEther(balance);
    }
    
    return {
      system: this.stats,
      database: {
        totalTransactions,
        pendingTransactions,
        playerCount,
        contractCount
      },
      relayer: {
        enabled: !!relayerWallet,
        address: relayerWallet ? relayerWallet.address : 'Not configured',
        balance: relayerBalance,
        nonce: await relayerNonceManager.currentNonce
      }
    };
  }
  
  async getTransactionStatus(transactionId) {
    try {
      const tx = await RelayedTransaction.findOne({ 
        $or: [
          { transactionId },
          { txHash: transactionId },
          { internalId: transactionId }
        ]
      });
      
      if (!tx) {
        return { found: false };
      }
      
      // Si está pendiente, verificar en blockchain
      if (tx.txHash && ['broadcasted', 'processing'].includes(tx.status)) {
        try {
          const receipt = await provider.getTransactionReceipt(tx.txHash);
          if (receipt) {
            if (receipt.status === 1) {
              tx.status = 'confirmed';
              tx.blockNumber = receipt.blockNumber;
              tx.gasUsed = receipt.gasUsed.toString();
              tx.confirmedAt = new Date();
            } else {
              tx.status = 'reverted';
              tx.gasUsed = receipt.gasUsed.toString();
            }
            await tx.save();
          }
        } catch (error) {
          // Ignorar errores de consulta
        }
      }
      
      return {
        found: true,
        ...tx.toObject(),
        explorerUrl: `${EXPLORER_URL}/tx/${tx.txHash}`
      };
    } catch (error) {
      console.error('❌ Error en getTransactionStatus:', error);
      throw error;
    }
  }
}

// Inicializar Relay Manager
const relayManager = new RelayManager();

// Verificar balance al inicio
setTimeout(async () => {
  await checkRelayerBalance();
}, 3000);

// --- CONTROLADORES ESPECIALIZADOS ---
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

      if (this.io) {
        this.io.emit('waterCollected', {
          playerName,
          collectionCycle: record.collectionCycle,
          collectionsToday: record.totalCollectionsToday,
          nextAvailableTime: record.nextAvailableTime,
          isDailyLimitReached: record.isDailyLimitReached,
          timestamp: now
        });
      }

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

class CropController {
  constructor(io) {
    this.io = io;
    
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
      Semillax2: {
        id: 'Semillax2',
        name: 'trigo',
        type: 'semilla2',
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
          stage1: 'tierra_seca_plant_trigo',
          stage2: 'tierra_mojada_plant_trigo',
          stage3: 'tierra_mojada_plant2_trigo',
          stage4: 'tierra_mojada_plant3_trigo',
          stage5: 'tierra_muerta_plant4_trigo'
        },
        rewards: {
          item: 'trigo_buena',
          quantity: 1,
          progress_reward: 'trigo_corta',
          progress_quantity: 1,
          deadReward: 'trigo_mala',
          deadQuantity: 1
        }
      },
      Semillax3: {
        id: 'Semillax3',
        name: 'calabaza',
        type: 'semilla3',
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
          stage1: 'tierra_seca_plant_calabaza',
          stage2: 'tierra_mojada_plant_calabaza',
          stage3: 'tierra_mojada_plant2_calabaza',
          stage4: 'tierra_mojada_plant3_calabaza',
          stage5: 'tierra_muerta_plant4_calabaza'
        },
        rewards: {
          item: 'calabaza_buena',
          quantity: 1,
          progress_reward: 'calabaza_corta',
          progress_quantity: 1,
          deadReward: 'calabaza_mala',
          deadQuantity: 1
        }
      },
    };
    
    this.startGrowthTimers();
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
        adjustedChance = 50;
      }
      
      if (isNaN(adjustedChance) || !isFinite(adjustedChance)) {
        adjustedChance = 50;
      }
      
      if (adjustedChance >= 100) {
        adjustedChance = 95;
      }
      
      adjustedChance = Math.max(1, Math.min(100, adjustedChance));

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

      if (this.io) {
        this.io.emit('cropPlanted', {
          userId,
          plotId,
          crop: cropWithConfig,
          successChance: adjustedChance
        });
      }

      console.log(`🌱 ${userId} plantó ${cropConfig.name} en ${plotId} - Posibilidad: ${adjustedChance}%`);
      
      return cropWithConfig;
      
    } catch (error) {
      console.error(`❌ Error en plantSeed:`, error.message);
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

      if (this.io) {
        this.io.emit('cropWatered', {
          userId,
          plotId,
          crop: cropWithConfig
        });
      }

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

      if (this.io) {
        this.io.emit('cropHarvested', {
          userId,
          plotId,
          rewards: {
            item: crop.rewards.item,
            quantity: crop.rewards.quantity
          },
          history
        });
      }

      console.log(`🎉 ${userId} cosechó ${plotId} - Recompensa: ${crop.rewards.quantity} ${crop.rewards.item}`);
      
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

      if (crop.isDead) {
        rewards = {
          item: crop.rewards.deadReward || 'Madera_podrida',
          quantity: crop.rewards.deadQuantity || 1
        };
      } else if (!crop.isCompleted) {
        rewards = {
          item: crop.rewards.progress_reward || 'palo_de_madera',
          quantity: crop.rewards.progress_quantity || 1
        };
      } else {
        rewards = { item: 'Madera', quantity: 1 };
      }

      if (!rewards.item || !rewards.quantity) {
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

      if (this.io) {
        this.io.emit('cropCut', {
          userId,
          plotId,
          rewards: rewards,
          isDead: crop.isDead,
          wasInProgress: !crop.isCompleted && !crop.isDead
        });
      }

      console.log(`✂️ ${userId} cortó ${plotId} - Recompensa: ${rewards.quantity} ${rewards.item}`);
      
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
            } else {
              crop.isCompleted = true;
            }
          }

          if (this.io) {
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
          }

          if (newStage !== crop.growthStage) {
            crop.growthStage = newStage;
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

// --- SOCKET.IO SETUP COMPLETO ---
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: function(origin, callback) {
      // Permitir todos los orígenes en desarrollo
      if (NODE_ENV === 'development' || !origin) {
        return callback(null, true);
      }
      if (allowedOrigins.indexOf(origin) !== -1) {
        return callback(null, true);
      }
      console.warn('❌ CORS bloqueado para origen:', origin);
      return callback(new Error('CORS not allowed'), false);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "X-Requested-With", "Accept"],
    exposedHeaders: ["Set-Cookie", "X-CSRF-Token"]
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
  cookie: {
    name: 'io',
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: NODE_ENV === 'production' ? 'strict' : 'lax',
    path: '/'
  }
});

global.io = io;

// Inicializar controladores
const waterCollectionController = new WaterCollectionController(io);
const cropController = new CropController(io);

// Variables globales para Socket.IO
let players = {};
let chatHistory = [];
const MAX_HISTORY = 50;
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

// FIX: Middleware de autenticación Socket.IO
// Verifica el JWT de la cookie 'session' antes de permitir la conexión.
// Los eventos de juego usan socket.authenticatedAddress para verificar ownership.
io.use((socket, next) => {
  try {
    // Intentar leer el token de la cookie del handshake
    const cookieHeader = socket.handshake.headers.cookie || '';
    const sessionMatch = cookieHeader.match(/(?:^|;\s*)session=([^;]+)/);
    const token = sessionMatch ? decodeURIComponent(sessionMatch[1]) : null;

    if (!token) {
      // Permitir conexión sin auth pero marcar como anónimo.
      // Los eventos sensibles verificarán socket.authenticatedAddress.
      socket.authenticatedAddress = null;
      socket.authenticatedPlayer  = null;
      return next();
    }

    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== 'access') {
      socket.authenticatedAddress = null;
      socket.authenticatedPlayer  = null;
      return next();
    }

    socket.authenticatedAddress = payload.address;
    socket.authenticatedPlayer  = null; // se llena en joinRoom tras verificar en DB

    next();
  } catch (err) {
    // Token inválido/expirado — conectar como anónimo
    socket.authenticatedAddress = null;
    socket.authenticatedPlayer  = null;
    next();
  }
});

// ============================================================================
// ANTI-SPAM DE SIEMBRA: penalización progresiva por sembrar semillas UNA POR
// UNA (varias confirmaciones separadas) en vez de agruparlas en un solo lote.
//
// El servidor no ve directamente las transacciones de blockchain (esas las
// hace el cliente contra el contrato), así que no puede saber "cuántas
// transacciones" se mandaron. Lo que SÍ puede observar es el patrón de
// llegada de los eventos 'plantSeed': cuando el cliente agrupa varias
// semillas en un solo lote (un solo ✔), todos esos 'plantSeed' del mismo
// tipo de semilla llegan casi al mismo tiempo (milisegundos de diferencia).
// Cuando el jugador siembra de a una, cada 'plantSeed' del mismo tipo llega
// separado por varios segundos (tiene que: seleccionar semilla, hacer clic,
// presionar ✔, esperar la transacción, y repetir).
//
// Regla: si para el MISMO tipo de semilla llegan 3 "acciones de siembra"
// separadas (cada una más de PLANT_SPAM_WINDOW_MS después de la anterior),
// se bloquea la siembra por un tiempo, que escala cada vez que se repite:
// 1ra sanción: 3 minutos | 2da: 7 minutos | 3ra en adelante: 20 minutos.
// ============================================================================
const plantSpamTracker = new Map(); // userId -> estado

const PLANT_SPAM_WINDOW_MS = 4000;            // separación mínima para contar como acción individual nueva
const PLANT_SPAM_STREAK_LIMIT = 3;            // 3 acciones individuales seguidas -> sanción
const PLANT_SPAM_PENALTIES_MIN = [3, 7, 20];  // minutos: 1ra, 2da, 3ra+ vez

// Consulta de SOLO LECTURA: solo mira si hay un bloqueo activo, sin
// registrar ningún intento nuevo ni afectar el conteo de rachas. Se usa
// para que el CLIENTE pregunte "¿estoy bloqueado?" ANTES de mandar la
// transacción de blockchain que descuenta las semillas, para no
// desperdiciarla si la respuesta es que sí.
function isPlantLocked(userId) {
  const ahora = Date.now();
  const estado = plantSpamTracker.get(userId);
  if (estado && estado.lockedUntil && ahora < estado.lockedUntil) {
    return { locked: true, secondsRemaining: Math.ceil((estado.lockedUntil - ahora) / 1000) };
  }
  return { locked: false, secondsRemaining: 0 };
}

function checkAndTrackPlantSpam(userId, seedType) {
  const ahora = Date.now();
  let estado = plantSpamTracker.get(userId);

  if (!estado) {
    estado = { seedType: null, lastPlantAt: 0, singleStreak: 0, violations: 0, lockedUntil: 0 };
    plantSpamTracker.set(userId, estado);
  }

  // ¿Sigue bloqueado de una sanción anterior?
  if (estado.lockedUntil && ahora < estado.lockedUntil) {
    return { bloqueado: true, segundosRestantes: Math.ceil((estado.lockedUntil - ahora) / 1000) };
  }

  const esMismaSemilla = estado.seedType === seedType;
  const dentroDeVentana = (ahora - estado.lastPlantAt) <= PLANT_SPAM_WINDOW_MS;

  if (esMismaSemilla && dentroDeVentana) {
    // Llega pegado al anterior: es parte del MISMO lote (un solo ✔), no
    // cuenta como una acción individual nueva.
    estado.lastPlantAt = ahora;
    return { bloqueado: false };
  }

  // Llega separado en el tiempo: cuenta como una acción de siembra nueva
  estado.singleStreak = esMismaSemilla ? estado.singleStreak + 1 : 1;
  estado.seedType = seedType;
  estado.lastPlantAt = ahora;

  if (estado.singleStreak >= PLANT_SPAM_STREAK_LIMIT) {
    const idx = Math.min(estado.violations, PLANT_SPAM_PENALTIES_MIN.length - 1);
    const minutos = PLANT_SPAM_PENALTIES_MIN[idx];
    estado.lockedUntil = ahora + minutos * 60 * 1000;
    estado.violations += 1;
    estado.singleStreak = 0;
    return { bloqueado: true, segundosRestantes: minutos * 60, nuevaSancionMin: minutos };
  }

  return { bloqueado: false };
}

// Socket.IO handlers COMPLETOS
io.on("connection", (socket) => {
  console.log(`🔗 Nueva conexión Socket.io: ${socket.id} desde IP: ${socket.handshake.address}`);

  // Verificar IP bloqueada - PERMITIR IPs LOCALES EN DESARROLLO
  const clientIp = socket.handshake.address;
  
  if (NODE_ENV === 'development') {
    if (clientIp.startsWith('127.') || clientIp.startsWith('192.168.') || clientIp.startsWith('10.') || 
        clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
      console.log(`✅ Conexión desde IP local permitida: ${clientIp}`);
    } else {
      securityController.isIPBlocked(clientIp).then(isBlocked => {
        if (isBlocked) {
          socket.emit('security_blocked', {
            message: 'Tu IP ha sido bloqueada por estar en la lista negra',
            code: 'IP_BLOCKED'
          });
          socket.disconnect(true);
          return;
        }
      });
    }
  } else {
    securityController.isIPBlocked(clientIp).then(isBlocked => {
      if (isBlocked) {
        socket.emit('security_blocked', {
          message: 'Tu IP ha sido bloqueada por estar en la lista negra',
          code: 'IP_BLOCKED'
        });
        socket.disconnect(true);
        return;
      }
    });
  }

  socket.emit("connected", {
    message: "Conectado al servidor de juego",
    socketId: socket.id,
    timestamp: Date.now(),
    environment: NODE_ENV
  });

  socket.playerData = {
    id: socket.id,
    room: null,
    username: '---',
    lastScene: null,
    ip: clientIp
  };

  // Eventos de recolección de agua
  socket.on('collectWater', async (data) => {
    try {
      const { playerName } = data;
      // FIX: Verificar que el playerName corresponde al socket autenticado
      if (socket.authenticatedPlayer && socket.authenticatedPlayer !== playerName) {
        return socket.emit('collectWaterError', { error: 'No autorizado: playerName no coincide' });
      }
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

  // Eventos de cultivos COMPLETOS
  socket.emit('cropConfig', cropController.getCropConfig());

  // Helper interno: verifica que el userId del evento coincide con el jugador autenticado
  function assertCropOwner(userId, emitEvent, plotId = null) {
    if (socket.authenticatedPlayer && socket.authenticatedPlayer !== userId) {
      const payload = { error: 'No autorizado: userId no coincide con el jugador autenticado' };
      if (plotId !== null) payload.plotId = plotId;
      socket.emit(emitEvent, payload);
      return false;
    }
    return true;
  }

  // Consulta previa (sin efectos secundarios) para que el cliente sepa si
  // está bloqueado ANTES de gastar una transacción de blockchain.
  socket.on('checkPlantLock', (data) => {
    const { userId } = data || {};
    if (!assertCropOwner(userId, 'plantLockStatus')) return;
    const estado = isPlantLocked(userId);
    socket.emit('plantLockStatus', estado);
  });

  socket.on('plantSeed', async (data) => {
    try {
      const { userId, plotId, seedType, userStats, successChance } = data;
      if (!assertCropOwner(userId, 'plantError', plotId)) return;

      const spamCheck = checkAndTrackPlantSpam(userId, seedType);
      if (spamCheck.bloqueado) {
        const minutosRestantes = Math.ceil(spamCheck.segundosRestantes / 60);
        const mensaje = spamCheck.nuevaSancionMin
          ? `You're planting one seed at a time too often. Planting is locked for ${spamCheck.nuevaSancionMin} minute(s) — try batching your seeds together next time.`
          : `Planting is temporarily locked. Try again in ${minutosRestantes} minute(s).`;
        socket.emit('plantError', { plotId, error: mensaje });
        return;
      }

      const crop = await cropController.plantSeed(userId, plotId, seedType, userStats, successChance);
      socket.emit('plantSuccess', { plotId, crop });
    } catch (error) {
      socket.emit('plantError', { plotId: data.plotId, error: error.message });
    }
  });

  socket.on('waterCrop', async (data) => {
    try {
      const { userId, plotId } = data;
      if (!assertCropOwner(userId, 'waterError')) return;
      const crop = await cropController.waterCrop(userId, plotId);
      socket.emit('waterSuccess', { plotId, crop });
    } catch (error) {
      socket.emit('waterError', { error: error.message });
    }
  });

  socket.on('harvestCrop', async (data) => {
    try {
      const { userId, plotId } = data;
      if (!assertCropOwner(userId, 'harvestError', plotId)) return;
      const result = await cropController.harvestCrop(userId, plotId);
      socket.emit('harvestSuccess', { plotId, rewards: result.rewards });
    } catch (error) {
      // FIX: se incluye plotId en el error para que el cliente pueda saber
      // exactamente cuál solicitud (de un lote con varios cuadros a la vez)
      // falló, en vez de no poder distinguir cuál de todas fue.
      socket.emit('harvestError', { plotId: data.plotId, error: error.message });
    }
  });

  socket.on('cutCrop', async (data) => {
    try {
      const { userId, plotId } = data;
      if (!assertCropOwner(userId, 'cutError', plotId)) return;
      const result = await cropController.cutCrop(userId, plotId);
      socket.emit('cutSuccess', { 
        plotId, 
        rewards: result.rewards,
        isDead: result.crop.isDead,
        wasInProgress: !result.crop.isCompleted && !result.crop.isDead
      });
    } catch (error) {
      // FIX: mismo motivo que en harvestError arriba.
      socket.emit('cutError', { plotId: data.plotId, error: error.message });
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

  // Eventos de salas y personajes COMPLETOS
  socket.on("joinRoom", async (data) => {
    const { room, username, lastScene } = data;
    
    console.log(`🔵 joinRoom: ${socket.id} -> ${room}, último escena: ${lastScene}`);
    
    if (!room || !username) {
      socket.emit("error", { message: "Datos de sala inválidos" });
      return;
    }

    // FIX: Si el socket tiene dirección autenticada, verificar que el username
    // corresponde a un jugador real vinculado a esa dirección.
    if (socket.authenticatedAddress && !socket.authenticatedPlayer) {
      try {
        const auth = await PlayerAuth.findOne({ address: socket.authenticatedAddress }).lean();
        if (auth && auth.playerName) {
          socket.authenticatedPlayer = auth.playerName;
        }
      } catch (e) {
        // continuar sin bloquear — mejor experiencia que romper el join
      }
    }

    if (socket.playerData.room === room && socket.playerData.lastScene === lastScene) {
      return;
    }

    if (socket.playerData.room && socket.playerData.room !== room) {
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
    
    socket.playerData.room = room;
    socket.playerData.username = username || '---';
    socket.playerData.lastScene = lastScene || 'unknown';
    
    if (!rooms[room]) {
      rooms[room] = {};
    }
    
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
    console.log(`✅ ${socket.id} unido a ${room} como ${username}`);
    
    const otherPlayers = Object.values(rooms[room]).filter(p => p.id !== socket.id);
    socket.emit("currentPlayers", otherPlayers);
    
    socket.to(room).emit("newPlayer", rooms[room][socket.id]);
    
    io.to(room).emit("playerCount", Object.keys(rooms[room]).length);
  });

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

  // chatTyping — rebroadcast to room so others see typing dots
  socket.on('chatTyping', (data) => {
    try {
      const room = socket.playerData && socket.playerData.room;
      if (!room) return;
      socket.to(room).emit('chatTyping', { ...data, id: socket.id });
    } catch (_) {}
  });

  socket.on('chatMessage', (payload) => {
    try {
      const room = socket.playerData.room;
      if (!room) return;
      
      const now = Date.now();
      if (now - (socket.chatLastSent || 0) < 1000) {
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

  socket.on('requestHistory', () => {
    try {
      socket.emit('chatHistory', chatHistory.slice(-MAX_HISTORY));
    } catch (e) {
      console.error('Error enviando chatHistory:', e);
    }
  });

  socket.on("ping", (data) => {
    socket.emit("pong", {
      timestamp: Date.now(),
      serverTime: new Date().toISOString()
    });
  });

  socket.on("disconnect", () => {
    const room = socket.playerData.room;
    
    if (room && rooms[room]) {
      delete rooms[room][socket.id];
      
      // Use playerLeft (same format as joinRoom-triggered leave) so all clients handle it
      io.to(room).emit("playerLeft", { id: socket.id, reason: 'disconnected' });
      io.to(room).emit("playerCount", Object.keys(rooms[room]).length);
      
      console.log(`❌ ${socket.id} desconectado de la sala: ${room}`);
    }
  });

  socket.on("error", (error) => {
    console.error(`❌ Error en socket ${socket.id}:`, error);
  });
});

// --- MIDDLEWARES DE SEGURIDAD CORREGIDOS ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // FIX: Eliminado 'unsafe-inline' de scriptSrc — permitía XSS sin restricción.
      // Si tu frontend carga scripts inline, muévelos a archivos externos.
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "http://localhost:*", "http://127.0.0.1:*", "ws://localhost:*", "ws://127.0.0.1:*", "wss://*.grasslandforest.com"],
      fontSrc: ["'self'", "data:"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    },
  },
  crossOriginResourcePolicy: { policy: "same-site" },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "same-origin" },
  hsts: NODE_ENV === 'production' ? {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  } : false,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  frameguard: { action: "deny" },
  noSniff: true,
  ieNoOpen: true,
  xssFilter: true,
  hidePoweredBy: true,
  dnsPrefetchControl: { allow: false }
}));

app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

if (NODE_ENV === 'production') {
  // En producción: confiar en loopback (127.0.0.1) y el IP de tu proxy/load balancer real.
  // Cambia el IP del proxy real en TRUSTED_PROXY_IP en .env si usas nginx/cloudflare.
  const trustedProxy = process.env.TRUSTED_PROXY_IP;
  app.set('trust proxy', trustedProxy ? ['loopback', trustedProxy] : ['loopback']);
} else {
  // En desarrollo: solo loopback
  app.set('trust proxy', ['loopback']);
}

if (NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https' && !req.secure) {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

// CORS dinámico CORREGIDO
const corsOptions = {
  origin: function(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }
    
    if (NODE_ENV === 'development') {
      const allowedLocalOrigins = [
        'http://localhost:3000',
        'http://localhost:5501',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5501',
        'http://localhost:8080',
        'http://127.0.0.1:8080',
        'http://localhost:3001',
        'http://127.0.0.1:3001'
      ];
      
      if (allowedLocalOrigins.includes(origin) || origin.includes('localhost') || origin.includes('127.0.0.1')) {
        console.log(`✅ CORS permitido en desarrollo para: ${origin}`);
        return callback(null, true);
      }
    }
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    console.warn('❌ CORS bloqueado para origen:', origin);
    return callback(new Error('CORS not allowed'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With', 'Cache-Control', 'Origin', 'X-CSRF-Token', 'x-csrf-token', 'X-Requested-With', 'Access-Control-Request-Method', 'Access-Control-Request-Headers'],
  exposedHeaders: ['Set-Cookie', 'X-CSRF-Token', 'X-Token-Expires-Soon'],
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Middleware para debug de cookies en desarrollo
app.use((req, res, next) => {
  if (NODE_ENV === 'development') {
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Requested-With, Accept');
    res.header('Access-Control-Expose-Headers', 'Set-Cookie');
  }
  next();
});

// User Agent y IP middleware
app.use(useragent.express());
app.use(requestIp.mw());

// Middleware de análisis de seguridad
app.use(async (req, res, next) => {
  await securityController.analyzeRequest(req, res, next);
});

// --- RATE LIMITERS CORREGIDOS (con validate: false para evitar error IPv6) ---
const createCustomRateLimiter = (windowMs, max, message, skipDevelopment = false) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    validate: false, // 🔥 Desactiva validación de IPv6 en keyGenerator personalizado
    skip: (req) => {
      if (skipDevelopment && NODE_ENV === 'development') {
        const ip = req.clientIp || req.ip;
        if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
            ip === '::1' || ip === '::ffff:127.0.0.1' || ip === 'localhost') {
          return true;
        }
      }
      return false;
    }
  });
};

// Rate limiters con configuración especial para desarrollo
const nonceLimiter = createCustomRateLimiter(60 * 1000, NODE_ENV === 'development' ? 50 : 10, 'too_many_nonce_requests', true);
const loginLimiter = createCustomRateLimiter(15 * 60 * 1000, NODE_ENV === 'development' ? 50 : 20, 'too_many_login_attempts', true);
const apiLimiter = createCustomRateLimiter(60 * 1000, NODE_ENV === 'development' ? 500 : 200, 'too_many_requests', true);
const strictLimiter = createCustomRateLimiter(15 * 60 * 1000, NODE_ENV === 'development' ? 500 : 200, 'Demasiadas peticiones. Por favor espera.', true);
const relayLimiter = createCustomRateLimiter(60 * 1000, NODE_ENV === 'development' ? 50 : 20, 'too_many_relay_requests', true);

const transactionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: SECURITY_CONFIG.MAX_TRANSACTIONS_PER_HOUR,
  message: { error: 'Límite de transacciones por hora excedido' },
  keyGenerator: (req) => {
    if (req.user && req.user.address) {
      return `user_${req.user.address}`;
    }
    const ip = req.clientIp || req.ip;
    return ip || 'unknown';
  },
  standardHeaders: true,
  legacyHeaders: false,
  validate: false, // 🔥 Desactiva validación de IPv6
  skip: (req) => {
    if (NODE_ENV === 'development') {
      const ip = req.clientIp || req.ip;
      if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || 
          ip === '::1' || ip === '::ffff:127.0.0.1' || ip === 'localhost') {
        return true;
      }
    }
    return false;
  }
});

// --- FUNCIONES DE COOKIES CORREGIDAS PARA DESARROLLO ---
function setCookieOptions(maxAgeSeconds, csrf = false) {
  const opts = {
    httpOnly: !csrf,
    secure: NODE_ENV === 'production',
    sameSite: NODE_ENV === 'development' ? 'Lax' : 'Strict',
    maxAge: (maxAgeSeconds || 0) * 1000,
    path: '/',
  };
  
  // EN DESARROLLO: Configuración especial para 127.0.0.1
  if (NODE_ENV === 'development') {
    opts.sameSite = 'Lax';
    opts.secure = false;
    opts.httpOnly = true;
    
    // IMPORTANTE: Establecer dominio explícitamente para 127.0.0.1
    // Esto asegura que las cookies se envíen desde 127.0.0.1:5501 a 127.0.0.1:3001
    opts.domain = '127.0.0.1';
  }
  
  if (NODE_ENV === 'production' && COOKIE_DOMAIN) {
    opts.domain = COOKIE_DOMAIN;
  }
  
  return opts;
}

// --- CSRF Protection CORREGIDO ---
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

function verifyCSRFToken(req) {
  const tokenFromHeader = req.headers['x-csrf-token'] || req.headers['X-CSRF-Token'];
  const tokenFromCookie = req.cookies && req.cookies['csrf-token'];
  
  if (!tokenFromHeader || !tokenFromCookie) {
    console.log('❌ CSRF: Faltan tokens', { 
      header: !!tokenFromHeader, 
      cookie: !!tokenFromCookie,
      path: req.path,
      method: req.method 
    });
    return false;
  }
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(tokenFromHeader), 
      Buffer.from(tokenFromCookie)
    );
  } catch {
    return false;
  }
}

function csrfProtection(req, res, next) {
  // NO aplicar CSRF a estos endpoints
  const noCSRFPaths = [
    '/api/auth/nonce',
    '/api/auth/refresh',
    '/api/auth/login',
    '/api/health',
    '/pingxxx',
    '/api/auth/csrf-token',
    '/api/relay/call-view'
  ];
  
  // También excluir métodos GET
  if (noCSRFPaths.includes(req.path) || req.method === 'GET' || req.method === 'OPTIONS') {
    return next();
  }
  
  if (!verifyCSRFToken(req)) {
    console.warn('❌ CSRF attempt from IP:', req.clientIp || req.ip, 'Path:', req.path, 'Method:', req.method);
    
    // En desarrollo, permitir continuar pero con advertencia
    if (NODE_ENV === 'development') {
      console.warn('⚠️  CSRF bypassed in development mode for debugging');
      return next();
    }
    
    return res.status(403).json({ 
      error: 'csrf_token_invalid',
      message: 'Token CSRF inválido o faltante',
      code: 'CSRF_ERROR'
    });
  }
  next();
}

// --- HELPERS DE AUTENTICACIÓN CORREGIDOS ---
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

// --- AUTH MIDDLEWARE (ACTUALIZADO Y CORREGIDO) ---
function authMiddleware(req, res, next) {
  console.log('🔐 Verificando autenticación...');
  
  try {
    // PRIMERO buscar en cookies
    let token = req.cookies && req.cookies.session;
    
    // Si no está en cookies, buscar en Authorization header
    if (!token && req.headers.authorization) {
      const authHeader = req.headers.authorization;
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
        console.log('🔑 Token obtenido de Authorization header');
      }
    }
    
    if (!token) {
      console.log('❌ No se encontró token de autenticación');
      console.log('🔍 Detalles de la solicitud:', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });
      
      return res.status(401).json({ 
        authenticated: false, 
        error: 'authentication_required',
        code: 'NO_ACCESS_TOKEN',
        message: 'Se requiere autenticación'
      });
    }
    
    console.log('🔍 Token encontrado, verificando...');
    
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      
      if (payload.type !== 'access') {
        console.log('❌ Token no es de tipo access');
        throw new Error('Invalid token type');
      }
      
      console.log(`✅ Token válido para dirección: ${payload.address?.substring(0, 10)}...`);
      
      // Verificar si el token está por expirar
      const now = Math.floor(Date.now() / 1000);
      const expiresIn = payload.exp - now;
      
      if (expiresIn < 300) {
        console.log(`⚠️  Token por expirar en ${expiresIn} segundos`);
        res.setHeader('X-Token-Expires-Soon', expiresIn);
      }
      
      req.user = payload;
      return next();
      
    } catch (err) {
      console.log(`❌ Error verificando token: ${err.name} - ${err.message}`);
      
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          authenticated: false, 
          error: 'token_expired',
          code: 'TOKEN_EXPIRED',
          message: 'El token ha expirado',
          canRefresh: true
        });
      }
      
      return res.status(401).json({ 
        authenticated: false, 
        error: 'invalid_session',
        code: 'INVALID_SESSION',
        message: 'Sesión inválida'
      });
    }
  } catch (err) {
    console.error('❌ Error crítico en authMiddleware:', err);
    return res.status(500).json({ 
      error: 'internal_server_error',
      message: 'Error interno del servidor'
    });
  }
}

// --- CONEXIÓN MONGODB ---
mongoose.connect(MONGO, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  maxPoolSize: 10,
  minPoolSize: 2,
  maxIdleTimeMS: 10000,
  retryWrites: true,
  w: 'majority'
})
  .then(async () => {
    console.log('✅ MongoDB connected');
    
    // Limpieza inicial
    try {
      await BlockedIP.deleteMany({
        isPermanent: false,
        blockedUntil: { $lt: new Date() }
      });
      
      // Limpiar tokens expirados
      await RefreshToken.deleteMany({ expiresAt: { $lt: new Date() } });
      
      console.log('✅ Sistema de seguridad inicializado');
    } catch (e) {
      console.log('Error limpiando datos iniciales:', e);
    }
  })
  .catch(err => {
    console.error('❌ MongoDB connection error', err);
    process.exit(1);
  });

// En server.js, después de las rutas de relay existentes:

// Endpoint para llamadas de solo lectura (view/pure)
app.post('/api/relay/call-view',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('contractAddress').isString().isLength({ min: 42, max: 42 }),
    body('functionName').isString().notEmpty(),
    body('parameters').optional().isObject()
  ],
  async (req, res) => {
    try {
      const { contractAddress, functionName, parameters = {} } = req.body;
      
      console.log(`📖 Llamando función view: ${functionName} en ${contractAddress}`);
      console.log(`📝 Parámetros:`, parameters);
      
      // Verificar que el contrato está en la whitelist
      const whitelisted = await ContractWhitelist.findOne({
        contractAddress: contractAddress.toLowerCase(),
        enabled: true
      });
      
      if (!whitelisted) {
        // Verificar si es un contrato predefinido
        const predefined = Object.values(CONTRACTS).find(
          contract => contract.address.toLowerCase() === contractAddress.toLowerCase()
        );
        
        if (!predefined) {
          console.log(`❌ Contrato no whitelisted: ${contractAddress}`);
          return res.status(403).json({
            success: false,
            error: 'Contract not whitelisted for view calls'
          });
        }
      }
      
      // Obtener ABI
      const abi = whitelisted ? whitelisted.abi : 
        Object.values(CONTRACTS).find(c => 
          c.address.toLowerCase() === contractAddress.toLowerCase()
        )?.abi;
      
      if (!abi) {
        console.log(`❌ ABI no encontrado para: ${contractAddress}`);
        return res.status(400).json({
          success: false,
          error: 'ABI not found for contract'
        });
      }
      
      // Crear contrato de solo lectura
      const readContract = new ethers.Contract(contractAddress, abi, provider);
      
      // Verificar que la función existe
      if (!readContract[functionName]) {
        console.log(`❌ Función no encontrada: ${functionName}`);
        return res.status(400).json({
          success: false,
          error: `Function ${functionName} not found in contract`
        });
      }
      
      // Verificar que es una función view o pure
      const abiFunction = abi.find(item => 
        item.type === 'function' && 
        item.name === functionName
      );
      
      if (!abiFunction) {
        return res.status(400).json({
          success: false,
          error: `Function ${functionName} not found in ABI`
        });
      }
      
      // Verificar que es una función view o pure (stateMutability)
      const isViewOrPure = ['view', 'pure'].includes(abiFunction.stateMutability);
      if (!isViewOrPure) {
        console.warn(`⚠️  Función ${functionName} no es view/pure: ${abiFunction.stateMutability}`);
        // Podemos continuar pero con advertencia
      }
      
      // Llamar a la función
      const args = Object.values(parameters);
      console.log(`🔧 Llamando función con args:`, args);
      
      const result = await readContract[functionName](...args);
      console.log(`✅ Resultado crudo de ${functionName}:`, result);
      
      // Función para convertir BigInt a string de forma recursiva.
      // CRÍTICO: los Result de ethers v5 extienden Array y además tienen propiedades
      // nombradas (.id, .manualId, etc.). Hay dos casos que debemos distinguir:
      //
      //  • tuple[]  (array de structs, ej. getUserInventorySnapshot):
      //    raw = [Result{0:'1',id:'1',...}, Result{0:'2',id:'2',...}, ...]
      //    Cada elemento es un Result con propiedades nombradas.
      //    → Convertir cada elemento como objeto nombrado para preservar los campos.
      //
      //  • tuple    (struct único, ej. getInvoice, getInvoiceByManualId):
      //    raw = Result{0:'1', 1:'g33...', id:'1', manualId:'g33...', tipo:'hacha de madera', ...}
      //    → Convertir como array plano (comportamiento original) para que _normalizeResult
      //      del relay luego mapee raw[0]=id, raw[1]=manualId, etc. en out0..outN.
      //      GameScene._getInvoiceFieldsFromResponse ya sabe leer ese formato.
      //
      // La distinción: si el primer elemento del array también tiene propiedades nombradas,
      // es un tuple[]; si el primer elemento es un primitivo/BigInt, es un tuple simple.
      function convertBigIntToString(obj) {
        if (obj === null || obj === undefined) return obj;
        if (typeof obj === 'bigint') return obj.toString();

        // BigNumber de ethers v5
        if (obj && typeof obj === 'object' && (obj._isBigNumber || obj._isIndexed)) {
          try { return obj.toString(); } catch (e) { return String(obj); }
        }

        if (Array.isArray(obj)) {
          // Detectar si es un tuple[] (array de structs con propiedades nombradas)
          // vs un tuple simple (cuyos elementos son primitivos/BigInt)
          const firstElem = obj[0];
          const firstIsStruct = firstElem !== null && firstElem !== undefined &&
            typeof firstElem === 'object' && !firstElem._isBigNumber &&
            Object.keys(firstElem).some(k => isNaN(k) && !k.startsWith('_'));

          if (firstIsStruct) {
            // tuple[]: convertir cada struct como objeto nombrado
            return obj.map(item => {
              if (item && typeof item === 'object' && !item._isBigNumber) {
                const namedKeys = Object.keys(item).filter(k => isNaN(k) && !k.startsWith('_'));
                if (namedKeys.length > 0) {
                  const out = {};
                  namedKeys.forEach(k => { out[k] = convertBigIntToString(item[k]); });
                  return out;
                }
              }
              return convertBigIntToString(item);
            });
          }

          // tuple simple o array plano de primitivos: comportamiento original
          return obj.map(item => convertBigIntToString(item));
        }

        if (typeof obj === 'object') {
          if (obj._isBigNumber || obj._isIndexed) {
            try { return obj.toString(); } catch (e) { return String(obj); }
          }
          const newObj = {};
          for (const key in obj) {
            if (key.startsWith('_')) continue;
            if (obj.hasOwnProperty(key)) {
              newObj[key] = convertBigIntToString(obj[key]);
            }
          }
          return newObj;
        }

        return obj;
      }
      
      const serializableResult = convertBigIntToString(result);
      
      console.log(`📦 Resultado serializable:`, serializableResult);
      
      res.json({
        success: true,
        result: serializableResult,
        contractAddress,
        functionName,
        timestamp: new Date()
      });
      
    } catch (error) {
      console.error('❌ Error en call-view:', error);
      
      const errorDetails = {
        message: error.message,
        code: error.code,
        reason: error.reason,
        transaction: error.transaction,
        receipt: error.receipt,
        stack: error.stack
      };
      
      res.status(500).json({
        success: false,
        error: error.message || 'Failed to call view function',
        details: errorDetails
      });
    }
  }
);

// Health endpoint — sin datos sensibles internos
app.get('/api/health', async (req, res) => {
  try {
    const mongoOk = mongoose.connection.readyState === 1;
    
    // FIX: No exponer versión, tipo de key management, balance del relayer,
    // ni dirección del wallet. Un atacante no necesita saber nada de eso.
    res.json({ 
      ok: true, 
      timestamp: Date.now(),
      database: { connected: mongoOk },
      relay: { enabled: !!relayerWallet },
      uptime: Math.floor(process.uptime())
    });
  } catch (error) {
    res.json({ ok: false, timestamp: Date.now() });
  }
});

// CSRF token endpoint
app.get('/api/auth/csrf-token', (req, res) => {
  const csrfToken = generateCSRFToken();
  res.cookie('csrf-token', csrfToken, setCookieOptions(3600, true));
  res.setHeader('X-CSRF-Token', csrfToken);
  return res.json({ 
    csrfToken,
    expiresIn: 3600,
    message: 'Token CSRF generado exitosamente',
    environment: NODE_ENV
  });
});

// CORREGIDO: Nonce endpoint - AHORA FUNCIONA CORRECTAMENTE
app.get('/api/auth/nonce', nonceLimiter, async (req, res) => {
  try {
    const address = (req.query.address || '').toLowerCase();
    console.log(`🔢 Solicitando nonce para dirección: ${address}`);
    
    if (!address || !isValidEthereumAddress(address)) {
      console.log(`❌ Dirección inválida: ${address}`);
      return res.status(400).json({ 
        error: 'valid_ethereum_address_required',
        message: 'Se requiere una dirección Ethereum válida'
      });
    }
    
    // Verificar si el usuario ya tiene un nonce válido (menos de 10 minutos)
    const existingPlayer = await PlayerAuth.findOne({ address }).exec();
    
    if (existingPlayer && existingPlayer.nonce && existingPlayer.nonceTimestamp) {
      const now = new Date();
      const nonceAge = now.getTime() - existingPlayer.nonceTimestamp.getTime();
      const MAX_NONCE_AGE = 10 * 60 * 1000; // 10 minutos
      
      if (nonceAge < MAX_NONCE_AGE) {
        console.log(`✅ Usando nonce existente para ${address.substring(0, 10)}... (edad: ${Math.floor(nonceAge/1000)}s)`);
        return res.json({ 
          nonce: existingPlayer.nonce,
          message: 'Nonce existente reutilizado',
          expiresIn: Math.floor((MAX_NONCE_AGE - nonceAge) / 1000),
          timestamp: existingPlayer.nonceTimestamp,
          reused: true
        });
      } else {
        console.log(`🔄 Nonce expirado para ${address.substring(0, 10)}... (edad: ${Math.floor(nonceAge/1000)}s)`);
      }
    }
    
    const player = await PlayerAuth.findOne({ address }).exec();
    if (player && player.loginBlockedUntil && player.loginBlockedUntil > new Date()) {
      const remaining = Math.ceil((player.loginBlockedUntil - new Date()) / 1000);
      console.log(`🚫 Cuenta bloqueada para ${address.substring(0, 10)}... por ${remaining}s`);
      return res.status(429).json({ 
        error: 'account_temporarily_blocked', 
        retryAfter: remaining,
        message: 'Cuenta bloqueada temporalmente por demasiados intentos'
      });
    }
    
    const nonce = generateNonce();
    const nonceTimestamp = new Date();
    
    // Usar findOneAndUpdate con upsert para asegurar que se guarda
    const result = await PlayerAuth.findOneAndUpdate(
      { address }, 
      { 
        $set: { 
          nonce, 
          nonceTimestamp, 
          loginAttempts: 0, 
          loginBlockedUntil: null 
        } 
      }, 
      { 
        upsert: true, 
        new: true,
        setDefaultsOnInsert: true
      }
    );
    
    console.log(`✅ Nonce generado para ${address.substring(0, 10)}...: ${nonce.substring(0, 20)}...`);
    console.log(`📊 Nonce guardado en DB: ${result.nonce ? 'SÍ' : 'NO'}`);
    
    return res.json({ 
      nonce,
      message: 'Nonce generado exitosamente',
      expiresIn: 600, // 10 minutos
      timestamp: nonceTimestamp,
      reused: false
    });
  } catch (err) {
    console.error('❌ Nonce error:', err);
    return res.status(500).json({ 
      error: 'internal_error',
      message: 'Error interno del servidor'
    });
  }
});

// CORREGIDO COMPLETAMENTE: Login endpoint 
app.post('/api/auth/login', loginLimiter, csrfProtection, async (req, res) => {
  const startTime = Date.now();
  try {
    const { address, signature, token, message } = req.body || {};
    
    console.log(`🔐 Intentando login para: ${address ? address.substring(0, 10) + '...' : 'dirección no proporcionada'}`);
    console.log('📦 Body recibido:', { 
      hasAddress: !!address, 
      hasSignature: !!signature, 
      hasToken: !!token, 
      hasMessage: !!message 
    });
    
    if (!address || !signature || !token || !message) {
      console.log('❌ Faltan parámetros en login');
      return res.status(400).json({ 
        error: 'missing_required_parameters',
        message: 'Faltan parámetros requeridos'
      });
    }
    
    const lcAddress = address.toLowerCase();
    if (!isValidEthereumAddress(lcAddress)) {
      console.log(`❌ Dirección inválida: ${lcAddress}`);
      return res.status(400).json({ 
        error: 'invalid_ethereum_address',
        message: 'Dirección Ethereum inválida'
      });
    }

    let player = await PlayerAuth.findOne({ address: lcAddress }).exec();
    if (!player) {
      console.log(`❌ Usuario no encontrado: ${lcAddress.substring(0, 10)}...`);
      return res.status(401).json({ 
        error: 'authentication_failed',
        message: 'Autenticación fallida - usuario no encontrado'
      });
    }

    // DEBUG: Mostrar estado actual del nonce
    console.log(`🔍 Estado del nonce para ${lcAddress.substring(0, 10)}...:`);
    console.log(`   - Nonce en DB: ${player.nonce ? player.nonce.substring(0, 20) + '...' : 'NULL'}`);
    console.log(`   - nonceTimestamp: ${player.nonceTimestamp}`);
    console.log(`   - Token recibido: ${token.substring(0, 20)}...`);

    if (!player.nonce) {
      console.log(`❌ Nonce no encontrado para ${lcAddress.substring(0, 10)}...`);
      return res.status(401).json({ 
        error: 'authentication_failed',
        message: 'Autenticación fallida - nonce no encontrado o expirado'
      });
    }

    if (player.nonceTimestamp && (Date.now() - player.nonceTimestamp.getTime() > 10 * 60 * 1000)) {
      console.log(`⏰ Nonce expirado para ${lcAddress.substring(0, 10)}...`);
      await PlayerAuth.updateOne(
        { address: lcAddress }, 
        { $set: { nonce: null, nonceTimestamp: null } }
      );
      return res.status(401).json({ 
        error: 'nonce_expired',
        message: 'Nonce expirado'
      });
    }

    const [nonceFromToken, tsStr] = String(token).split(':');
    const ts = parseInt(tsStr, 10);
    
    if (!nonceFromToken || !ts || isNaN(ts)) {
      console.log(`❌ Formato de token inválido: ${token}`);
      return res.status(400).json({ 
        error: 'invalid_token_format',
        message: 'Formato de token inválido'
      });
    }

    // CORREGIDO: Comparación segura de nonce
    if (nonceFromToken !== player.nonce) {
      console.log(`❌ Nonce no coincide:`);
      console.log(`   - Nonce esperado: ${player.nonce ? player.nonce.substring(0, 20) + '...' : 'NULL'}`);
      console.log(`   - Nonce recibido: ${nonceFromToken.substring(0, 20) + '...'}`);
      
      const newAttempts = (player.loginAttempts || 0) + 1;
      let updateData = { loginAttempts: newAttempts };
      
      if (newAttempts >= 5) {
        updateData.loginBlockedUntil = new Date(Date.now() + 15 * 60 * 1000);
        console.log(`🚫 Cuenta bloqueada para ${lcAddress.substring(0, 10)}... por 15 minutos`);
      }
      
      await PlayerAuth.updateOne({ address: lcAddress }, { $set: updateData });
      return res.status(401).json({ 
        error: 'authentication_failed',
        message: 'Autenticación fallida - nonce incorrecto'
      });
    }

    const now = Math.floor(Date.now() / 1000);
    const MAX_AGE = 60 * 5; // 5 minutos
    
    if (Math.abs(now - ts) > MAX_AGE) {
      console.log(`⏰ Token expirado (timestamp: ${ts}, ahora: ${now})`);
      return res.status(401).json({ 
        error: 'token_expired',
        message: 'Token expirado'
      });
    }

    if (!validateSignedMessage(message, token)) {
      console.log(`❌ Validación de mensaje fallida`);
      return res.status(401).json({ 
        error: 'message_validation_failed',
        message: 'Validación de mensaje fallida'
      });
    }

    let recovered;
    try {
      console.log(`🔐 Verificando firma...`);
      const hash = ethers.hashMessage(message);
      recovered = ethers.recoverAddress(hash, signature);
      console.log(`   - Dirección recuperada: ${recovered}`);
      console.log(`   - Dirección esperada: ${lcAddress}`);
    } catch (err) {
      console.error(`❌ Error verificando firma:`, err);
      return res.status(401).json({ 
        error: 'signature_verification_failed',
        message: 'Verificación de firma fallida'
      });
    }

    if (!recovered || recovered.toLowerCase() !== lcAddress.toLowerCase()) {
      console.log(`❌ Dirección no coincide: ${recovered} vs ${lcAddress}`);
      return res.status(401).json({ 
        error: 'address_mismatch',
        message: 'Dirección no coincide'
      });
    }

    // ✅ AUTENTICACIÓN EXITOSA
    
    // Crear tokens
    const refreshTokenId = uuidv4();
    const rawRefresh = jwt.sign(
      { 
        address: lcAddress, 
        jti: refreshTokenId, 
        type: 'refresh' 
      }, 
      JWT_SECRET, 
      { expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d` }
    );
    
    const refreshHash = await bcrypt.hash(rawRefresh, 12);
    const accessToken = jwt.sign(
      { 
        address: lcAddress, 
        type: 'access', 
        jti: uuidv4() 
      }, 
      JWT_SECRET, 
      { expiresIn: ACCESS_TOKEN_EXPIRES }
    );

    // Guardar refresh token en colección separada
    const decoded = jwt.decode(rawRefresh);
    const expiresAt = new Date(decoded.exp * 1000);
    
    await RefreshToken.create({
      token: crypto.createHash('sha256').update(rawRefresh).digest('hex'),
      address: lcAddress,
      expiresAt,
      userAgent: req.headers['user-agent'],
      ip: req.clientIp
    });

    // Obtener playerName de GamePlayer
    const gamePlayer = await GamePlayer.findOne({ address: lcAddress }).exec();
    const playerName = gamePlayer ? gamePlayer.playerName : lcAddress; // Usar address si no hay nombre

    // Preparar datos de actualización para PlayerAuth
    const updateData = {
      nonce: null,
      nonceTimestamp: null,
      refreshTokenHash: refreshHash,
      refreshTokenId,
      lastLogin: new Date(),
      loginAttempts: 0,
      loginBlockedUntil: null,
      playerName: playerName // Asegurar que playerName se guarde
    };

    // Actualizar PlayerAuth
    await PlayerAuth.findOneAndUpdate(
      { address: lcAddress }, 
      { $set: updateData }, 
      { upsert: true }
    );

    // IMPORTANTE: Configurar cookies CORRECTAMENTE para desarrollo
    const accessCookieOpts = setCookieOptions(15 * 60); // 15 minutos
    const refreshCookieOpts = setCookieOptions(REFRESH_TOKEN_TTL_DAYS * 24 * 3600);

    // Establecer cookies
    res.cookie('session', accessToken, accessCookieOpts);
    res.cookie('refresh', rawRefresh, refreshCookieOpts);

    // Generar nuevo token CSRF
    const csrfToken = generateCSRFToken();
    res.cookie('csrf-token', csrfToken, setCookieOptions(3600, true));
    res.setHeader('X-CSRF-Token', csrfToken);

    const duration = Date.now() - startTime;
    console.log(`✅ Login exitoso para ${lcAddress.substring(0, 10)}... (${duration}ms)`);
    console.log(`   - PlayerName: ${playerName}`);
    console.log(`   - Cookies establecidas: session, refresh, csrf-token`);
    console.log(`   - Nonce limpiado de la base de datos`);

    return res.json({ 
      authenticated: true, 
      address: lcAddress, 
      playerName,
      csrfToken,
      expiresIn: 15 * 60, // 15 minutos en segundos
      refreshExpiresIn: REFRESH_TOKEN_TTL_DAYS * 24 * 3600,
      message: 'Login exitoso'
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    return res.status(500).json({ 
      error: 'internal_server_error',
      message: 'Error interno del servidor'
    });
  }
});

// Refresh token - CORREGIDO
app.post('/api/auth/refresh', async (req, res) => {
  console.log('🔄 Solicitud de refresh recibida');
  
  try {
    const raw = req.cookies && req.cookies.refresh;
    if (!raw) {
      console.log('❌ No hay refresh token en cookies');
      return res.status(401).json({ 
        error: 'refresh_token_required',
        canRetry: false,
        message: 'Token de refresco requerido'
      });
    }

    let payload;
    try {
      payload = jwt.verify(raw, JWT_SECRET);
      if (payload.type !== 'refresh') {
        console.log('❌ Token no es de tipo refresh');
        throw new Error('Invalid token type');
      }
    } catch (err) {
      console.log(`❌ Error verificando refresh token: ${err.name}`);
      
      // Limpiar cookies inválidas
      res.clearCookie('session', setCookieOptions(0));
      res.clearCookie('refresh', setCookieOptions(0));
      res.clearCookie('csrf-token', setCookieOptions(0, true));
      
      return res.status(401).json({ 
        error: 'invalid_refresh_token',
        canRetry: false,
        requiresReauth: true,
        message: 'Token de refresco inválido'
      });
    }

    // Verificar si el token existe en la base de datos
    const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
    const storedToken = await RefreshToken.findOne({ 
      token: tokenHash,
      address: payload.address.toLowerCase()
    });

    if (!storedToken) {
      console.log(`❌ Refresh token no encontrado en DB para ${payload.address.substring(0, 10)}...`);
      return res.status(401).json({ 
        error: 'refresh_token_not_found',
        canRetry: false,
        requiresReauth: true,
        message: 'Token de refresco no encontrado'
      });
    }

    if (storedToken.expiresAt < new Date()) {
      console.log(`❌ Refresh token expirado para ${payload.address.substring(0, 10)}...`);
      await RefreshToken.deleteOne({ _id: storedToken._id });
      return res.status(401).json({ 
        error: 'refresh_token_expired',
        canRetry: false,
        requiresReauth: true,
        message: 'Token de refresco expirado'
      });
    }

    // ✅ Token válido - proceder con el refresh
    console.log(`✅ Refresh token válido para ${payload.address.substring(0, 10)}...`);
    
    // Eliminar token antiguo
    await RefreshToken.deleteOne({ _id: storedToken._id });
    
    // Crear nuevos tokens
    const newRefreshTokenId = uuidv4();
    const newRawRefresh = jwt.sign({ 
      address: payload.address, 
      jti: newRefreshTokenId, 
      type: 'refresh' 
    }, JWT_SECRET, { expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d` });
    
    const newRefreshHash = await bcrypt.hash(newRawRefresh, 12);
    const accessToken = jwt.sign({ 
      address: payload.address, 
      type: 'access', 
      jti: uuidv4() 
    }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES });

    // Guardar nuevo refresh token
    const decoded = jwt.decode(newRawRefresh);
    const expiresAt = new Date(decoded.exp * 1000);
    
    await RefreshToken.create({
      token: crypto.createHash('sha256').update(newRawRefresh).digest('hex'),
      address: payload.address.toLowerCase(),
      expiresAt,
      userAgent: req.headers['user-agent'],
      ip: req.clientIp
    });

    // Obtener playerName
    const gamePlayer = await GamePlayer.findOne({ address: payload.address.toLowerCase() }).exec();
    const playerName = gamePlayer ? gamePlayer.playerName : payload.address;

    // Actualizar en PlayerAuth
    await PlayerAuth.updateOne({ 
      address: payload.address.toLowerCase() 
    }, { 
      $set: {
        refreshTokenHash: newRefreshHash, 
        refreshTokenId: newRefreshTokenId,
        lastLogin: new Date(),
        playerName: playerName
      }
    });

    // Configurar cookies
    const accessCookieOpts = setCookieOptions(15 * 60);
    const refreshCookieOpts = setCookieOptions(REFRESH_TOKEN_TTL_DAYS * 24 * 3600);

    res.cookie('session', accessToken, accessCookieOpts);
    res.cookie('refresh', newRawRefresh, refreshCookieOpts);

    // Generar nuevo token CSRF
    const csrfToken = generateCSRFToken();
    res.cookie('csrf-token', csrfToken, setCookieOptions(3600, true));
    res.setHeader('X-CSRF-Token', csrfToken);

    console.log(`✅ Token refrescado exitosamente para ${payload.address.substring(0, 10)}...`);
    
    return res.json({ 
      ok: true, 
      csrfToken,
      accessTokenExpiresIn: 15 * 60, // 15 minutos en segundos
      refreshTokenExpiresIn: REFRESH_TOKEN_TTL_DAYS * 24 * 3600,
      message: 'Token refrescado exitosamente'
    });
    
  } catch (err) {
    console.error('❌ Error crítico en refresh:', err);
    return res.status(500).json({ 
      error: 'internal_server_error',
      message: 'Error al procesar la solicitud de refresh'
    });
  }
});

// CORREGIDO: Get current user - endpoint me
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const address = (req.user && req.user.address) || null;
    if (!address) {
      return res.status(401).json({ 
        authenticated: false, 
        error: 'user_not_found',
        message: 'Usuario no encontrado'
      });
    }
    
    console.log(`🔍 Buscando datos para: ${address.substring(0, 10)}...`);
    
    const player = await PlayerAuth.findOne({ address }).lean().exec();
    const gamePlayer = await GamePlayer.findOne({ address }).lean().exec();
    
    if (!player) {
      console.log(`❌ No se encontró PlayerAuth para ${address.substring(0, 10)}...`);
      return res.status(404).json({ 
        authenticated: false, 
        error: 'player_not_found',
        message: 'Jugador no encontrado'
      });
    }
    
    console.log(`✅ Datos encontrados para ${address.substring(0, 10)}...`);
    
    return res.json({
      authenticated: true,
      address,
      playerName: player.playerName || address,
      gameData: gamePlayer || null,
      lastLogin: player.lastLogin || null,
      message: 'Usuario autenticado'
    });
  } catch (err) {
    console.error('❌ Error en /api/auth/me:', err);
    return res.status(500).json({ 
      error: 'internal_server_error',
      message: 'Error interno del servidor'
    });
  }
});

// Logout
app.post('/api/auth/logout', csrfProtection, async (req, res) => {
  console.log('🔒 Solicitud de logout recibida');
  
  try {
    const raw = req.cookies && req.cookies.refresh;
    
    if (raw) {
      try {
        const payload = jwt.verify(raw, JWT_SECRET);
        if (payload.type === 'refresh' && payload.address) {
          console.log(`🔒 Logout para ${payload.address.substring(0, 10)}...`);
          
          // Limpiar de PlayerAuth
          await PlayerAuth.updateOne({ 
            address: payload.address.toLowerCase() 
          }, { 
            $set: { 
              refreshTokenHash: null, 
              refreshTokenId: null 
            } 
          });
          
          // Limpiar de RefreshToken collection
          const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
          await RefreshToken.deleteMany({ 
            token: tokenHash,
            address: payload.address.toLowerCase()
          });
          
          console.log(`✅ Tokens eliminados para ${payload.address.substring(0, 10)}...`);
        }
      } catch (err) {
        console.log('⚠️  Error procesando refresh token durante logout:', err.message);
      }
    }
    
    // Limpiar todas las cookies
    res.clearCookie('session', setCookieOptions(0));
    res.clearCookie('refresh', setCookieOptions(0));
    res.clearCookie('csrf-token', setCookieOptions(0, true));
    
    console.log('✅ Logout completado exitosamente');
    return res.json({ 
      ok: true, 
      message: 'Sesión cerrada exitosamente' 
    });
  } catch (err) {
    console.error('❌ Error durante logout:', err);
    return res.status(500).json({ 
      error: 'internal_server_error',
      message: 'Error al procesar el logout' 
    });
  }
});

// Set playerName
app.post('/api/auth/set-playerName', authMiddleware, strictLimiter, csrfProtection, [
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
    const address = req.user.address.toLowerCase();
    
    const auth = await PlayerAuth.findOne({ address }).exec();
    if (!auth) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Verificar si el playerName ya está en uso
    const existingAuth = await PlayerAuth.findOne({ 
      playerName: playerName,
      address: { $ne: address }
    });
    
    if (existingAuth) {
      return res.status(400).json({ error: 'PlayerName ya está en uso por otro usuario' });
    }

    const existingGamePlayer = await GamePlayer.findOne({ 
      playerName: playerName,
      address: { $ne: address }
    });
    
    if (existingGamePlayer) {
      return res.status(400).json({ error: 'PlayerName ya está en uso en el juego por otro jugador' });
    }

    // Actualizar playerName
    auth.playerName = playerName;
    await auth.save();

    // Actualizar o crear GamePlayer
    let gamePlayer = await GamePlayer.findOne({ address });
    if (gamePlayer) {
      gamePlayer.playerName = playerName;
      await gamePlayer.save();
    } else {
      gamePlayer = new GamePlayer({
        playerName: playerName,
        address: address
      });
      await gamePlayer.save();
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


// -------------------- Árboles / Deforestación --------------------
app.get('/api/tree/state/:treeKey',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const { treeKey } = req.params;
      const lock = await TreeLock.findOne({ treeKey });
      const lockedUntil = lock?.lockedUntil || null;
      res.json({ treeKey, lockedUntil });
    } catch (error) {
      console.error('Error obteniendo estado del árbol:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);
// En server.js
app.get('/api/tree/locks/active', authMiddleware, async (req, res) => {
  try {
    const now = new Date();
    const locks = await TreeLock.find({ lockedUntil: { $gt: now } });
    res.json(locks);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/tree/deforestation',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('treeType').isIn(['pinos', 'arbustos', 'arbolx']),
    body('increment').isInt({ min: 1, max: 100 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      const { treeType, increment } = req.body;

      const deforest = await Deforestation.findOneAndUpdate(
        { treeType },
        { $inc: { percent: increment } },
        { new: true, upsert: true }
      );

      if (deforest.percent > 100) {
        deforest.percent = 100;
        await deforest.save();
      }

      res.json({ 
        success: true, 
        treeType, 
        newPercent: deforest.percent 
      });
    } catch (error) {
      console.error('Error actualizando deforestación:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);


// -----------------------------------------------------------------------------
// Configuración de tipos de árbol (debe coincidir con el frontend)
// -----------------------------------------------------------------------------

const TREE_TYPE_CONFIG = {
  pinos:     { baseRespawn: 300, respawnMultiplier: 0 },   // 300 segundos = 5 minutos
  arbustos:  { baseRespawn: 300, respawnMultiplier: 0 },
  arbolx:    { baseRespawn: 300, respawnMultiplier: 0 }
};

// -----------------------------------------------------------------------------
// Endpoint para bloquear un árbol (ya NO recibe lockedUntil del cliente)
// -----------------------------------------------------------------------------
app.post('/api/tree/lock',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('treeKey').isString().notEmpty(),
    body('treeType').isIn(['pinos', 'arbustos', 'arbolx'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      const { treeKey, treeType } = req.body;

      // Obtener el porcentaje actual de deforestación para este tipo
      const deforest = await Deforestation.findOne({ treeType });
      const percent = deforest ? deforest.percent : 0;

      const config = TREE_TYPE_CONFIG[treeType];
      if (!config) {
        return res.status(400).json({ error: 'Tipo de árbol no válido' });
      }

      let lockedUntil;
      if (percent >= 100) {
        lockedUntil = new Date('3000-01-01T00:00:00.000Z'); // bloqueo permanente
      } else {
        const respawnSeconds = config.baseRespawn + (percent * config.respawnMultiplier);
        lockedUntil = new Date(Date.now() + respawnSeconds * 1000);
      }

      await TreeLock.findOneAndUpdate(
        { treeKey },
        { treeType, lockedUntil },
        { upsert: true }
      );

      res.json({ success: true, treeKey, lockedUntil });
    } catch (error) {
      console.error('Error bloqueando árbol:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.get('/api/tree/deforestation/:treeType',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const { treeType } = req.params;
      const deforest = await Deforestation.findOne({ treeType });
      res.json({ 
        treeType, 
        percent: deforest?.percent || 0 
      });
    } catch (error) {
      console.error('Error obteniendo deforestación:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);



// -----------------------------------------------------------------------------
// CONFIGURACIÓN DE TIPOS DE MINERAL (debe coincidir con el frontend)
// -----------------------------------------------------------------------------
const MINERAL_TYPE_CONFIG = {
  piedra: { baseRespawn: 300, respawnMultiplier: 0 },   // 300s = 5 min
  cobre:  { baseRespawn: 300, respawnMultiplier: 0 },
  hierro: { baseRespawn: 300, respawnMultiplier: 0 },
  carbon: { baseRespawn: 300, respawnMultiplier: 0 }
};
 
 
// =============================================================================
// ENDPOINTS
// =============================================================================
 
// -----------------------------------------------------------------------------
// GET /api/mine/state/:mineKey
// Consulta si una mina específica está bloqueada.
// Equivalente a GET /api/tree/state/:treeKey
// -----------------------------------------------------------------------------
app.get(
  '/api/mine/state/:mineKey',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const { mineKey } = req.params;
      if (!mineKey || typeof mineKey !== 'string' || mineKey.trim() === '') {
        return res.status(400).json({ error: 'mineKey inválido' });
      }
 
      const lock = await MineLock.findOne({ mineKey });
      if (!lock) {
        return res.json({ mineKey, lockedUntil: null, isLocked: false });
      }
 
      const isLocked = lock.lockedUntil > new Date();
      return res.json({
        mineKey,
        lockedUntil: isLocked ? lock.lockedUntil : null,
        isLocked
      });
    } catch (error) {
      console.error('Error obteniendo estado de mina:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);
 
 
// -----------------------------------------------------------------------------
// POST /api/mine/lock
// Bloquea una mina. El servidor calcula lockedUntil con el agotamiento actual.
// Body: { mineKey, mineralType }
// Equivalente a POST /api/tree/lock
// -----------------------------------------------------------------------------
app.post(
  '/api/mine/lock',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('mineKey').isString().notEmpty(),
    body('mineralType').isIn(['piedra', 'cobre', 'hierro', 'carbon'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
 
      const { mineKey, mineralType } = req.body;
 
      const config = MINERAL_TYPE_CONFIG[mineralType];
      if (!config) {
        return res.status(400).json({ error: 'Tipo de mineral no válido' });
      }
 
      // Obtener porcentaje de agotamiento actual
      const depletion = await MineDepletion.findOne({ mineralType });
      const percent   = depletion ? depletion.percent : 0;
 
      let lockedUntil;
      if (percent >= 100) {
        // Bloqueo permanente si el mineral está totalmente agotado
        lockedUntil = new Date('3000-01-01T00:00:00.000Z');
      } else {
        const respawnSeconds = config.baseRespawn + (percent * config.respawnMultiplier);
        lockedUntil = new Date(Date.now() + respawnSeconds * 1000);
      }
 
      await MineLock.findOneAndUpdate(
        { mineKey },
        { mineralType, lockedUntil },
        { upsert: true, new: true }
      );
 
      return res.json({ success: true, mineKey, lockedUntil });
    } catch (error) {
      console.error('Error bloqueando mina:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);
 
 
// -----------------------------------------------------------------------------
// POST /api/mine/depletion
// Incrementa el % de agotamiento global de un tipo de mineral.
// Body: { mineralType, increment }
// Equivalente a POST /api/tree/deforestation
// -----------------------------------------------------------------------------
app.post(
  '/api/mine/depletion',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('mineralType').isIn(['piedra', 'cobre', 'hierro', 'carbon']),
    body('increment').isFloat({ min: 0, max: 100 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
 
      const { mineralType, increment } = req.body;
 
      const updated = await MineDepletion.findOneAndUpdate(
        { mineralType },
        { $inc: { percent: increment } },
        { upsert: true, new: true }
      );
 
      // Clampear a 100
      if (updated.percent > 100) {
        updated.percent = 100;
        await updated.save();
      }
 
      return res.json({ success: true, mineralType, newPercent: updated.percent });
    } catch (error) {
      console.error('Error actualizando agotamiento de mina:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);
 
 
// -----------------------------------------------------------------------------
// GET /api/mine/depletion/:mineralType
// Consulta el % de agotamiento actual de un tipo de mineral.
// Equivalente a GET /api/tree/deforestation/:treeType
// -----------------------------------------------------------------------------
app.get(
  '/api/mine/depletion/:mineralType',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const { mineralType } = req.params;
      if (!['piedra', 'cobre', 'hierro', 'carbon'].includes(mineralType)) {
        return res.status(400).json({ error: 'Tipo de mineral no válido' });
      }
 
      const depletion = await MineDepletion.findOne({ mineralType });
      return res.json({
        mineralType,
        percent: depletion?.percent || 0
      });
    } catch (error) {
      console.error('Error obteniendo agotamiento de mina:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);
 
 
// -----------------------------------------------------------------------------
// GET /api/mine/locks/active
// Devuelve todos los bloqueos de minas que siguen activos (lockedUntil > now).
// Usado al cargar la escena para restaurar el estado visual de las minas.
// Equivalente a GET /api/tree/locks/active
// -----------------------------------------------------------------------------
app.get(
  '/api/mine/locks/active',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const now = new Date();
      const activeLocks = await MineLock.find({ lockedUntil: { $gt: now } })
        .select('mineKey mineralType lockedUntil -_id')
        .lean();
 
      return res.json(activeLocks);
    } catch (error) {
      console.error('Error obteniendo bloqueos activos de minas:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);
 



// --- RUTAS DEL SISTEMA DE RELAY ---

// 1. Obtener contratos disponibles
// RUTA ORIGINAL (actualizar)
app.get('/api/relay/contracts', 
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      // INCLUIR el campo 'abi' en la consulta
      const contracts = await ContractWhitelist.find({ enabled: true })
        .select('contractAddress contractName description securityConfig stats abi') // <-- AÑADIR 'abi'
        .lean();
      
      // Añadir contratos predefinidos que no estén en la base de datos
      const allContracts = [...contracts];
      
      Object.values(CONTRACTS).forEach(contract => {
        if (contract.address && contract.address !== '0x...') {
          const exists = contracts.some(c => 
            c.contractAddress.toLowerCase() === contract.address.toLowerCase()
          );
          
          if (!exists) {
            allContracts.push({
              contractAddress: contract.address,
              contractName: contract.name,
              description: contract.description,
              abi: contract.abi, // <-- AÑADIR ABI
              securityConfig: {
                maxCallsPerHour: 100,
                maxCallsPerDay: 1000,
                requirePlayerOwnership: false,
                allowedFunctions: [],
                minGasPriceMultiplier: 0.1,
                maxGasLimit: 10000000
              },
              stats: {
                totalCalls: 0,
                successfulCalls: 0,
                failedCalls: 0,
                totalGasUsed: "0",
                lastCall: null
              }
            });
          }
        }
      });
      
      res.json({
        success: true,
        contracts: allContracts,
        total: allContracts.length
      });
    } catch (error) {
      console.error('❌ Error obteniendo contratos:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// 2. Obtener ABI de un contrato
app.get('/api/relay/contract/:address/abi',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const { address } = req.params;
      
      // Buscar en whitelist
      const whitelisted = await ContractWhitelist.findOne({
        contractAddress: address.toLowerCase(),
        enabled: true
      }).select('abi contractName');
      
      if (whitelisted) {
        return res.json({
          success: true,
          contractAddress: address,
          contractName: whitelisted.contractName,
          abi: whitelisted.abi
        });
      }
      
      // Buscar en contratos predefinidos
      const predefined = Object.values(CONTRACTS).find(
        contract => contract.address.toLowerCase() === address.toLowerCase()
      );
      
      if (predefined) {
        return res.json({
          success: true,
          contractAddress: address,
          contractName: predefined.name,
          abi: predefined.abi
        });
      }
      
      res.status(404).json({
        success: false,
        error: 'Contract not found or not whitelisted'
      });
    } catch (error) {
      console.error('❌ Error obteniendo ABI:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// 3. Enviar transacción relay (ENDOPOINT PRINCIPAL)
// server.js - En el endpoint /api/relay/transaction (alrededor de la línea 4900)
app.post('/api/relay/transaction',
  relayLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('contractAddress').isString().isLength({ min: 42, max: 42 }),
    body('functionName').isString().notEmpty(),
    body('parameters').isObject(),
    body('priority').optional().isIn(['low', 'normal', 'high'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      
      const { contractAddress, functionName, parameters, priority } = req.body;
      const playerAddress = req.user.address.toLowerCase();
      
      // Verificar que el relay esté configurado
      if (!relayerWallet) {
        return res.status(503).json({
          error: 'relay_not_configured',
          message: 'El sistema de relay no está configurado'
        });
      }
      
      // Obtener playerName
      const auth = await PlayerAuth.findOne({ address: playerAddress });
      if (!auth || !auth.playerName) {
        return res.status(404).json({ error: 'Player not found' });
      }
      
      const playerName = auth.playerName;
      
      // Verificar que el contrato está en whitelist y obtener el nombre
      const whitelisted = await ContractWhitelist.findOne({
        contractAddress: contractAddress.toLowerCase(),
        enabled: true
      });
      
      let contractName = 'Unknown Contract';
      
      if (!whitelisted) {
        // Verificar si es un contrato predefinido
        const predefined = Object.values(CONTRACTS).find(
          contract => contract.address.toLowerCase() === contractAddress.toLowerCase()
        );
        
        if (!predefined) {
          return res.status(403).json({
            error: 'contract_not_whitelisted',
            message: 'Este contrato no está autorizado para transacciones relay'
          });
        }
        
        contractName = predefined.name;
        
        // Si es predefinido pero no en whitelist, agregarlo
        await ContractWhitelist.create({
          contractAddress: contractAddress.toLowerCase(),
          contractName: predefined.name,
          description: predefined.description,
          abi: predefined.abi,
          enabled: true
        });
      } else {
        contractName = whitelisted.contractName;
      }
      
      console.log(`✅ Procesando transacción para ${playerName}: ${contractName}.${functionName}`);
      
      // Preparar datos de transacción
      const transactionData = {
        playerAddress,
        playerName,
        contractAddress: contractAddress.toLowerCase(),
        contractName, // AÑADIDO: Nombre del contrato
        functionName,
        parameters,
        priority: priority || 'normal',
        ip: req.clientIp || req.ip,
        userAgent: req.headers['user-agent'],
        sessionId: req.cookies?.session?.split('.')[0] || 'unknown'
      };
      
      // Añadir a la cola de procesamiento
      const result = await relayManager.processTransaction(transactionData);
      
      // Emitir evento de Socket.io si está disponible
      if (global.io) {
        global.io.emit('relay_transaction_sent', {
          playerAddress,
          playerName,
          contractName,
          contractAddress,
          functionName,
          transactionId: result.transactionId,
          txHash: result.txHash,
          timestamp: new Date()
        });
      }
      
      res.json({
        success: true,
        message: 'Transaction queued for relay',
        transactionId: result.transactionId,
        txHash: result.txHash,
        estimatedCost: result.estimatedCost,
        explorerUrl: `${EXPLORER_URL}/tx/${result.txHash}`,
        timestamp: new Date()
      });
      
    } catch (error) {
      console.error('❌ Error en relay transaction:', error);
      
      res.status(500).json({
        success: false,
        error: error.message || 'Failed to relay transaction',
        code: 'RELAY_ERROR'
      });
    }
  }
);

// 4. Endpoint específico para enviar mensajes (ejemplo)
app.post('/api/relay/send-message',
  relayLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('message').isString().notEmpty().isLength({ max: 200 })
  ],
  async (req, res) => {
    try {
      const { message } = req.body;
      const playerAddress = req.user.address.toLowerCase();
      
      // Verificar que tenemos contrato de mensajes configurado
      const messageContract = CONTRACTS.MESSAGE_CONTRACT;
      if (!messageContract.address || messageContract.address === '0x...') {
        return res.status(501).json({
          error: 'message_contract_not_configured',
          message: 'El contrato de mensajes no está configurado'
        });
      }
      
      // Preparar parámetros
      const parameters = {
        _message: message,
        _player: playerAddress
      };
      
      const transactionData = {
        playerAddress,
        playerName: req.user.playerName || 'unknown',
        contractAddress: messageContract.address,
        functionName: 'sendMessage',
        parameters,
        priority: 'normal',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        sessionId: req.cookies?.session?.split('.')[0] || 'unknown'
      };
      
      const result = await relayManager.processTransaction(transactionData);
      
      res.json({
        success: true,
        message: 'Message sent via relay',
        transactionId: result.transactionId,
        txHash: result.txHash,
        explorerUrl: `${EXPLORER_URL}/tx/${result.txHash}`
      });
      
    } catch (error) {
      console.error('❌ Error enviando mensaje:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// 5. Verificar estado de transacción
app.get('/api/relay/transaction/:id',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const playerAddress = req.user.address.toLowerCase();
      
      const status = await relayManager.getTransactionStatus(id);
      
      if (!status.found) {
        return res.status(404).json({ error: 'Transaction not found' });
      }
      
      // Verificar que la transacción pertenece al jugador
      if (status.playerAddress.toLowerCase() !== playerAddress) {
        return res.status(403).json({ error: 'Not authorized to view this transaction' });
      }
      
      res.json({
        success: true,
        transaction: status
      });
    } catch (error) {
      console.error('❌ Error obteniendo estado:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);



// GET /api/transactions?playerName=xxx
app.get('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const { playerName } = req.query;
    if (!playerName) return res.status(400).json({ error: 'playerName required' });
    const txs = await TransactionLog.find({ playerName }).lean();
    // Group by category
    const grouped = { interaction: [], items: [] };
    txs.forEach(tx => grouped[tx.category].push(tx));
    res.json(grouped);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/transactions
app.post('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const tx = new TransactionLog(req.body);
    await tx.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/transactions/:id
app.delete('/api/transactions/:id', authMiddleware, async (req, res) => {
  try {
    await TransactionLog.deleteOne({ id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 6. Obtener historial de transacciones del jugador
app.get('/api/relay/transactions/history',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const playerAddress = req.user.address.toLowerCase();
      const { page = 1, limit = 20 } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);
      
      const [transactions, total] = await Promise.all([
        RelayedTransaction.find({ playerAddress })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .lean(),
        RelayedTransaction.countDocuments({ playerAddress })
      ]);
      
      // Añadir URLs del explorador
      const enrichedTransactions = transactions.map(tx => ({
        ...tx,
        explorerUrl: tx.txHash ? `${EXPLORER_URL}/tx/${tx.txHash}` : null
      }));
      
      res.json({
        success: true,
        transactions: enrichedTransactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit))
        }
      });
    } catch (error) {
      console.error('❌ Error obteniendo historial:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// 7. Obtener límites del jugador
app.get('/api/relay/limits',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const playerAddress = req.user.address.toLowerCase();
      
      let playerLimit = await PlayerLimit.findOne({ playerAddress });
      
      if (!playerLimit) {
        playerLimit = new PlayerLimit({
          playerAddress,
          'limits.hourly.resetAt': new Date(Date.now() + 60 * 60 * 1000),
          'limits.daily.resetAt': new Date(Date.now() + 24 * 60 * 60 * 1000),
          'limits.weekly.resetAt': new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });
        await playerLimit.save();
      }
      
      // Calcular tiempos restantes
      const now = new Date();
      const timeUntilHourlyReset = playerLimit.limits.hourly.resetAt 
        ? Math.max(0, playerLimit.limits.hourly.resetAt.getTime() - now.getTime())
        : 0;
      
      const timeUntilDailyReset = playerLimit.limits.daily.resetAt
        ? Math.max(0, playerLimit.limits.daily.resetAt.getTime() - now.getTime())
        : 0;
      
      const timeUntilWeeklyReset = playerLimit.limits.weekly.resetAt
        ? Math.max(0, playerLimit.limits.weekly.resetAt.getTime() - now.getTime())
        : 0;
      
      res.json({
        success: true,
        limits: {
          hourly: {
            used: playerLimit.limits.hourly.calls,
            max: playerLimit.limits.hourly.maxCalls,
            remaining: playerLimit.limits.hourly.maxCalls - playerLimit.limits.hourly.calls,
            resetIn: Math.floor(timeUntilHourlyReset / 1000)
          },
          daily: {
            used: playerLimit.limits.daily.calls,
            max: playerLimit.limits.daily.maxCalls,
            remaining: playerLimit.limits.daily.maxCalls - playerLimit.limits.daily.calls,
            resetIn: Math.floor(timeUntilDailyReset / 1000)
          },
          weekly: {
            used: playerLimit.limits.weekly.calls,
            max: playerLimit.limits.weekly.maxCalls,
            remaining: playerLimit.limits.weekly.maxCalls - playerLimit.limits.weekly.calls,
            resetIn: Math.floor(timeUntilWeeklyReset / 1000)
          }
        },
        stats: {
          totalRelayerCost: playerLimit.totalRelayerCost,
          totalGasUsed: playerLimit.totalGasUsed,
          lastTransaction: playerLimit.lastTransaction,
          firstTransaction: playerLimit.firstTransaction
        },
        suspension: {
          isSuspended: playerLimit.isSuspended,
          reason: playerLimit.suspensionReason,
          until: playerLimit.suspensionUntil
        }
      });
    } catch (error) {
      console.error('❌ Error obteniendo límites:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// 8. Estadísticas del sistema (admin)
app.get('/api/relay/stats',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      // Verificar que el usuario es admin (simplificado)
      // En producción, usar un sistema de roles real
      const address = req.user.address.toLowerCase();
      const isAdmin = process.env.ADMIN_ADDRESSES 
        ? process.env.ADMIN_ADDRESSES.split(',').includes(address)
        : false;
      
      if (!isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
      }
      
      const stats = await relayManager.getStats();
      
      res.json({
        success: true,
        ...stats
      });
    } catch (error) {
      console.error('❌ Error obteniendo stats:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// --- RUTAS DE SEGURIDAD (ADMIN) ---
const adminAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token de administrador requerido' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.role !== 'admin' && decoded.role !== 'security_admin') {
      return res.status(403).json({ error: 'No autorizado para operaciones de seguridad' });
    }
    
    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Token de administrador inválido' });
  }
};

// --- RUTAS DE ADMIN PARA GESTIÓN DE CONTRATOS ---
const contractAdminAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token de administrador requerido' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.role !== 'admin' && decoded.role !== 'contract_admin') {
      return res.status(403).json({ error: 'No autorizado para operaciones de contratos' });
    }
    
    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Token de administrador inválido' });
  }
};

// Agregar contrato a whitelist
app.post('/api/admin/contracts/whitelist',
  contractAdminAuth,
  strictLimiter,
  csrfProtection,
  [
    body('contractAddress').isString().isLength({ min: 42, max: 42 }),
    body('contractName').isString().notEmpty(),
    body('abi').isArray(),
    body('description').optional().isString(),
    body('enabled').optional().isBoolean()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      
      const {
        contractAddress,
        contractName,
        abi,
        description,
        enabled = true
      } = req.body;
      
      // Verificar que el contrato existe en blockchain
      try {
        const code = await provider.getCode(contractAddress);
        if (code === '0x') {
          return res.status(400).json({ error: 'No contract code at this address' });
        }
      } catch (error) {
        console.warn('⚠️  No se pudo verificar código del contrato:', error.message);
      }
      
      // Crear o actualizar en whitelist
      const contract = await ContractWhitelist.findOneAndUpdate(
        { contractAddress: contractAddress.toLowerCase() },
        {
          contractAddress: contractAddress.toLowerCase(),
          contractName,
          description: description || `Contract at ${contractAddress}`,
          abi,
          enabled,
          updatedAt: new Date()
        },
        { upsert: true, new: true }
      );
      
      console.log(`✅ Contrato ${contractName} añadido/actualizado en whitelist por admin ${req.admin.username}`);
      
      res.json({
        success: true,
        message: 'Contract whitelisted successfully',
        contract
      });
    } catch (error) {
      console.error('❌ Error whitelisting contract:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Mantener todas las rutas existentes de seguridad
app.get('/api/security/blocked-ips', adminAuth, strictLimiter, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const result = await securityController.getBlockedIPs(parseInt(page), parseInt(limit));
    
    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    console.error('Error obteniendo IPs bloqueadas:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.get('/api/security/ip-activity/:ip', adminAuth, strictLimiter, async (req, res) => {
  try {
    const { ip } = req.params;
    const { page = 1 } = req.query;
    
    const result = await securityController.getIPActivity(ip, parseInt(page));
    
    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    console.error('Error obteniendo actividad de IP:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/security/block-ip', adminAuth, strictLimiter, [
  body('ip').isIP().notEmpty(),
  body('reason').optional().isString(),
  body('durationMinutes').optional().isInt({ min: 0 }),
  body('details').optional().isObject()
], async (req, res) => {
  try {
    const validationErrors = validationResult(req);
    if (!validationErrors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validación fallida', 
        details: validationErrors.array() 
      });
    }
    
    const { ip, reason = 'manual_block', durationMinutes = 60, details = {} } = req.body;
    
    const blocked = await securityController.blockIPManual(
      ip, 
      reason, 
      durationMinutes, 
      { ...details, admin: req.admin.username }
    );
    
    if (blocked) {
      res.json({
        success: true,
        message: `IP ${ip} bloqueada exitosamente`,
        duration: durationMinutes > 0 ? `${durationMinutes} minutos` : 'permanentemente'
      });
    } else {
      res.status(400).json({
        success: false,
        error: 'No se pudo bloquear la IP'
      });
    }
  } catch (error) {
    console.error('Error bloqueando IP:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/security/unblock-ip/:ip', adminAuth, strictLimiter, async (req, res) => {
  try {
    const { ip } = req.params;
    
    const unblocked = await securityController.unblockIP(ip);
    
    if (unblocked) {
      res.json({
        success: true,
        message: `IP ${ip} desbloqueada exitosamente`
      });
    } else {
      res.status(404).json({
        success: false,
        error: 'IP no encontrada en la lista de bloqueados'
      });
    }
  } catch (error) {
    console.error('Error desbloqueando IP:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.get('/api/security/stats', adminAuth, strictLimiter, async (req, res) => {
  try {
    const [blockedCount, incidentsCount, activityCount] = await Promise.all([
      BlockedIP.countDocuments(),
      SecurityIncident.countDocuments(),
      IPActivity.countDocuments()
    ]);
    
    const recentIncidents = await SecurityIncident.find()
      .sort({ detectedAt: -1 })
      .limit(10)
      .lean();
    
    const topThreats = await IPActivity.find()
      .sort({ threatScore: -1 })
      .limit(10)
      .lean();
    
    res.json({
      success: true,
      stats: {
        blockedIPs: blockedCount,
        securityIncidents: incidentsCount,
        monitoredIPs: activityCount,
        failedAttemptsTracking: securityController.failedAttempts.size
      },
      recentIncidents,
      topThreats
    });
  } catch (error) {
    console.error('Error obteniendo estadísticas de seguridad:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// --- Mantener todas las rutas existentes del juego ---

// SAVE endpoint
app.post('/api/save/:playerName',
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
    let { inventory, chest, missionsData } = req.body;

    try {
      // ----- VALIDACIÓN: SOLO ÍTEMS CON IDX Y Manualid -----
      const validarItems = (items) => {
        if (!items || !Array.isArray(items)) return items;
        // Filtra: conserva solo los objetos que tienen IDX y Manualid NO nulos/undefined
        return items.filter(item => 
          item.hasOwnProperty('IDX') && 
          item.hasOwnProperty('Manualid') &&
          item.IDX !== null && item.IDX !== undefined &&
          item.Manualid !== null && item.Manualid !== undefined
        );
      };

      const originalInventoryCount = inventory?.length ?? 0;
      const originalChestCount = chest?.length ?? 0;

      if (inventory) inventory = validarItems(inventory);
      if (chest) chest = validarItems(chest);

      const validInventoryCount = inventory?.length ?? 0;
      const validChestCount = chest?.length ?? 0;
      // ----- FIN VALIDACIÓN -----

      const auth = await PlayerAuth.findOne({ address }).exec();
      if (!auth) return res.status(404).json({ error: 'user_not_found' });

      if (!auth.playerName) {
        auth.playerName = playerName;
        await auth.save();
      } else if (auth.playerName !== playerName) {
        return res.status(403).json({ error: 'not_authorized_for_player' });
      }

      const update = Object.assign({}, req.body, { address });
      // Sobrescribir con los arrays ya validados
      if (inventory) update.inventory = inventory;
      if (chest) update.chest = chest;

      // ── Usar valores canónicos del contrato para moneda/moneda_plata ──────
      // El cliente puede enviar valores stale. PlayerStats tiene la verdad.
      try {
        const pStats = await PlayerStats.findOne({ playerName }).lean();
        if (pStats) {
          update.moneda       = pStats.oro   ?? update.moneda       ?? 0;
          update.moneda_plata = pStats.plata  ?? update.moneda_plata ?? 0;
          update.vidaPorcentaje   = pStats.vida   ?? update.vidaPorcentaje   ?? 0;
          update.aguaPorcentaje   = pStats.agua   ?? update.aguaPorcentaje   ?? 0;
          update.comidaPorcentaje = pStats.comida ?? update.comidaPorcentaje ?? 0;
        }
      } catch (psErr) {
        console.warn('⚠️  No se pudo leer PlayerStats para save:', psErr.message);
      }

      await GamePlayer.findOneAndUpdate(
        { playerName },
        { $set: update },
        { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
      );

      if (missionsData && typeof missionsData === 'object') {
        await MissionsPlayer.findOneAndUpdate(
          { playerName },
          { $set: missionsData },
          { upsert: true, new: true, runValidators: false }
        );
      }

      // Registrar actividad (geolocalización, etc.)
      const geoInfo = await securityController.getGeoInfo(req.ip);
      await UserActivity.findOneAndUpdate(
        { playerName },
        {
          $set: {
            ip: req.ip,
            geo: geoInfo,
            lastLogin: new Date()
          },
          $inc: { loginCount: 1 }
        },
        { upsert: true }
      );

      await ConnectedUser.findOneAndUpdate(
        { playerName },
        { connectedAt: new Date() },
        { upsert: true }
      );

      // Respuesta con estadísticas de validación
      const response = { success: true };
      if (originalInventoryCount !== validInventoryCount) {
        response.warning = `Se omitieron ${originalInventoryCount - validInventoryCount} ítems de inventario por faltar IDX/Manualid`;
      }
      if (originalChestCount !== validChestCount) {
        response.warning = `Se omitieron ${originalChestCount - validChestCount} ítems de baúl por faltar IDX/Manualid`;
      }
      response.validated = {
        inventory: validInventoryCount,
        chest: validChestCount
      };

      return res.json(response);
    } catch (e) {
      console.error('Error en save:', e);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }
);

// LOAD endpoint
app.get('/api/load/:playerName',
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

      const response = Object.assign({}, p, { 
        hora: a.hora, 
        dia_noche: a.dia_noche, 
        missionsData 
      });
      
      return res.json(response);
    } catch (e) {
      console.error('Error en load:', e);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }
);

// --- RUTAS DE RECOLECCIÓN DE AGUA ---
app.get('/api/water/status/:playerName',
  apiLimiter,
  authMiddleware,
  param('playerName').isString().notEmpty(),
  async (req, res) => {
    try {
      const { playerName } = req.params;
      const address = req.user.address.toLowerCase();
      
      const auth = await PlayerAuth.findOne({ address }).exec();
      if (!auth || auth.playerName !== playerName) {
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

app.post('/api/water/collect',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  body('playerName').isString().notEmpty(),
  async (req, res) => {
    try {
      const { playerName } = req.body;
      const address = req.user.address.toLowerCase();
      
      const auth = await PlayerAuth.findOne({ address }).exec();
      if (!auth || auth.playerName !== playerName) {
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

// Misiones diarias
app.get('/api/missions/daily/:npcId/:date?',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const { npcId, date } = req.params;
      const address = req.user.address.toLowerCase();
      
      // Usar PlayerAuth en lugar de User
      const auth = await PlayerAuth.findOne({ address }).exec();
      
      if (!auth || !auth.playerName) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const playerName = auth.playerName;

      // Usar fecha proporcionada o hoy
      const targetDate = date || new Date().toISOString().split('T')[0];
      
      // Buscar misiones del día
      const dailyMission = await DailyMission.findOne({ 
        npcId, 
        day: targetDate 
      });

      if (!dailyMission) {
        return res.status(404).json({ 
          error: 'No hay misiones disponibles para hoy',
          npcId,
          day: targetDate
        });
      }

      // Obtener progreso del usuario
      const userProgress = await UserDailyProgress.findOne({
        playerName: playerName,
        npcId,
        day: targetDate
      });

      // Calcular tiempo hasta el reset
      const now = new Date();
      const resetTime = new Date(now);
      resetTime.setUTCHours(dailyMission.dailyResetHour, 0, 0, 0);
      
      if (now >= resetTime) {
        resetTime.setDate(resetTime.getDate() + 1);
      }
      
      const hoursUntilReset = Math.ceil((resetTime - now) / (1000 * 60 * 60));

      res.json({
        success: true,
        npcId,
        day: targetDate,
        missions: dailyMission.missions,
        userProgress: userProgress || {
          completedMissions: [],
          completedCount: 0
        },
        resetInfo: {
          nextResetUTC: resetTime.toISOString(),
          hoursUntilReset,
          resetHourUTC: dailyMission.dailyResetHour
        }
      });

    } catch (error) {
      console.error('Error obteniendo misiones diarias:', error);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

// Marketplace P2P — todas las rutas /api/marketplace/* viven en marketplace-routes.js
// (se monta más abajo, después de que PlayerStats esté definido — ver "MARKETPLACE ROUTES MOUNT")

// Error Reports
app.post('/api/report-error', async (req, res) => {
    const safeLog = (...args) => {
        if (typeof process !== 'undefined' && process.stdout) {
            process.stdout.write('[ERROR-REPORTER] ' + args.join(' ') + '\n');
        }
    };
    
    try {
        const { errors, password } = req.body;
        
        if (password !== ERROR_PASSWORD) {
            safeLog('Contraseña incorrecta recibida');
            return res.status(401).json({ 
                success: false, 
                error: 'Contraseña incorrecta' 
            });
        }
        
        if (!errors || !Array.isArray(errors)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Formato inválido' 
            });
        }
        
        safeLog(`Recibidos ${errors.length} errores del frontend`);
        
        let procesados = 0;
        let guardadosNuevos = 0;
        
        for (const error of errors.slice(0, 50)) {
            try {
                if (error.message && (
                    error.message.includes('errores enviados') ||
                    error.message.includes('ErrorReporter') ||
                    error.message.includes('error-reporter') ||
                    error.message.includes('📤') ||
                    error.message.includes('✅') ||
                    error.message.includes('⚠️')
                )) {
                    continue;
                }
                
                const errorId = generateErrorId(error);
                
                const nuevoError = new ErrorReport({
                    errorId: errorId,
                    type: error.type || 'unknown',
                    message: (error.message || 'Sin mensaje').substring(0, 800),
                    url: error.url || 'unknown',
                    scene: error.scene || 'unknown',
                    userAgent: error.userAgent || 'unknown',
                    phaserVersion: error.phaserVersion || 'unknown',
                    timestamp: new Date(error.timestamp || Date.now()),
                    line: error.line || 'unknown',
                    column: error.column || 'unknown',
                    file: error.file || 'unknown',
                    stack: error.stack ? error.stack.substring(0, 1500) : undefined,
                    count: 1,
                    lastSeen: new Date()
                });
                
                await nuevoError.save();
                guardadosNuevos++;
                procesados++;
                
            } catch (dbError) {
                safeLog('Error DB:', dbError.message);
            }
        }
        
        const total = await ErrorReport.countDocuments();
        
        res.json({ 
            success: true,
            procesados: procesados,
            nuevos: guardadosNuevos,
            total: total
        });
        
    } catch (error) {
        safeLog('Error crítico:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

function generateErrorId(error) {
    try {
        const contenido = [
            error.type || 'unknown',
            error.message || 'no-message',
            error.scene || 'no-scene',
            error.url || 'no-url',
            error.file || 'no-file',
            error.line || 'no-line'
        ].join('|');
        
        let hash = 0;
        for (let i = 0; i < contenido.length; i++) {
            const char = contenido.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & 0xFFFFFFFF;
        }
        
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substring(2, 9);
        
        return `err_${Math.abs(hash).toString(16).substring(0, 8)}_${timestamp}_${random}`;
        
    } catch (e) {
        return `err_fallback_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    }
}

// Socket status
app.get('/api/socket/status', (req, res) => {
  res.json({
    connectedSockets: io.engine.clientsCount,
    activeRooms: Object.keys(rooms).filter(room => Object.keys(rooms[room]).length > 0),
    timestamp: Date.now()
  });
});

// Ping endpoint
app.get('/pingxxx', (req, res) => {
  res.json({ time: Date.now() });
});

// --- LIMPIEZA PERIÓDICA ---
setInterval(async () => {
  try {
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const result = await PlayerAuth.updateMany(
      { 
        nonce: { $ne: null }, 
        nonceTimestamp: { $lt: tenMinutesAgo } 
      },
      { 
        $set: { 
          nonce: null, 
          nonceTimestamp: null 
        } 
      }
    );
    if (result.modifiedCount > 0) {
      console.log(`🧹 Limpiados ${result.modifiedCount} nonces expirados (más de 10 minutos)`);
    }
  } catch (err) {
    console.error('Error en limpieza de nonces expirados:', err);
  }
}, 5 * 60 * 1000); // Cada 5 minutos

setInterval(async () => {
  try {
    const result = await RateLimit.deleteMany({ firstAttempt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    if (result.deletedCount > 0) console.log(`🧹 Limpiados ${result.deletedCount} rate limits expirados`);
  } catch (err) {
    console.error('Error en limpieza de rate limits:', err);
  }
}, 30 * 60 * 1000);

// Limpieza diaria de progresos antiguos
setInterval(async () => {
  try {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const dateString = sevenDaysAgo.toISOString().split('T')[0];

    await UserDailyProgress.deleteMany({
      day: { $lt: dateString }
    });

    console.log(`🧹 Progresos de misiones antiguos limpiados (anteriores a ${dateString})`);
  } catch (error) {
    console.error('Error limpiando progresos antiguos:', error);
  }
}, 24 * 60 * 60 * 1000);

// Limpieza de tokens expirados
setInterval(async () => {
  try {
    const result = await RefreshToken.deleteMany({ expiresAt: { $lt: new Date() } });
    if (result.deletedCount > 0) console.log(`🧹 Limpiados ${result.deletedCount} refresh tokens expirados`);
  } catch (err) {
    console.error('Error limpiando refresh tokens:', err);
  }
}, 60 * 60 * 1000);

// =============================================================================
// TOOL USES — desgaste de herramientas
// =============================================================================

// GET /api/tool/uses/:invoiceId — consultar usos restantes de una herramienta
app.get('/api/tool/uses/:invoiceId',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const invoiceId = parseInt(req.params.invoiceId, 10);
      if (isNaN(invoiceId)) return res.status(400).json({ error: 'invoiceId inválido' });
      const doc = await ToolUses.findOne({ invoiceId });
      if (!doc) {
        // No existe aún: la herramienta no ha sido usada, tiene todos los usos
        return res.json({ invoiceId, usos: null, rota: false });
      }
      return res.json({ invoiceId, usos: doc.usos, maxUsos: doc.maxUsos, rota: doc.rota });
    } catch (err) {
      console.error('Error en GET /api/tool/uses:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/tool/uses/decrease — descontar 1 uso a una herramienta
app.post('/api/tool/uses/decrease',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('invoiceId').isInt({ min: 1 }),
    body('maxUsos').isInt({ min: 1 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { invoiceId, maxUsos } = req.body;

      // Buscar o crear el registro
      let doc = await ToolUses.findOne({ invoiceId });
      if (!doc) {
        // Primera vez que se usa: inicializar con maxUsos - 1
        const usosInicial = Math.max(0, maxUsos - 1);
        doc = await ToolUses.create({
          invoiceId,
          usos: usosInicial,
          maxUsos,
          rota: usosInicial <= 0
        });
        console.log(`🔨 Herramienta ${invoiceId} inicializada con ${usosInicial}/${maxUsos} usos restantes`);
      } else {
        const nuevosUsos = Math.max(0, doc.usos - 1);
        doc.usos = nuevosUsos;
        doc.rota = nuevosUsos <= 0;
        await doc.save();
        console.log(`🔨 Herramienta ${invoiceId}: ${nuevosUsos}/${doc.maxUsos} usos restantes${doc.rota ? ' — ROTA' : ''}`);
      }

      return res.json({ invoiceId, usos: doc.usos, maxUsos: doc.maxUsos, rota: doc.rota });
    } catch (err) {
      console.error('Error en POST /api/tool/uses/decrease:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// =============================================================================
// MERGE COOLDOWN — cooldown de 7 minutos por par de facturas (anti-abuse)
// =============================================================================

// POST /api/tool/uses/bulk — consultar usos de múltiples invoiceIds de una vez
app.post('/api/tool/uses/bulk',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const { invoiceIds } = req.body;
      if (!Array.isArray(invoiceIds) || invoiceIds.length === 0)
        return res.json({ uses: {} });
      const docs = await ToolUses.find({ invoiceId: { $in: invoiceIds.map(Number) } });
      const uses = {};
      docs.forEach(d => {
        uses[d.invoiceId] = { usos: d.usos, maxUsos: d.maxUsos, rota: d.rota };
      });
      return res.json({ uses });
    } catch (err) {
      console.error('Error en POST /api/tool/uses/bulk:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// DELETE /api/tool/uses/:invoiceId — borrar registro de usos (para resetear al romperse 1 item del stack)
app.delete('/api/tool/uses/:invoiceId',
  apiLimiter,
  authMiddleware,
  async (req, res) => {
    try {
      const invoiceId = parseInt(req.params.invoiceId, 10);
      if (isNaN(invoiceId)) return res.status(400).json({ error: 'invoiceId inválido' });
      await ToolUses.deleteOne({ invoiceId });
      console.log(`🗑️ Registro de usos eliminado para invoiceId ${invoiceId} (stack fresco)`);
      return res.json({ success: true, invoiceId });
    } catch (err) {
      console.error('Error en DELETE /api/tool/uses:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/merge/cooldown/check — verificar si un par de facturas tiene cooldown activo
app.post('/api/merge/cooldown/check',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('pairKey').isString().notEmpty().isLength({ max: 100 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { pairKey } = req.body;
      const now = new Date();
      const doc = await MergeCooldown.findOne({ pairKey });

      if (!doc || doc.cooldownUntil <= now) {
        return res.json({ onCooldown: false });
      }

      return res.json({
        onCooldown: true,
        cooldownUntil: doc.cooldownUntil
      });
    } catch (err) {
      console.error('Error en POST /api/merge/cooldown/check:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/merge/cooldown/set — registrar cooldown después de un merge exitoso
app.post('/api/merge/cooldown/set',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('pairKey').isString().notEmpty().isLength({ max: 100 }),
    body('cooldownMinutes').isInt({ min: 1, max: 60 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { pairKey, cooldownMinutes } = req.body;
      const cooldownUntil = new Date(Date.now() + cooldownMinutes * 60 * 1000);

      await MergeCooldown.findOneAndUpdate(
        { pairKey },
        { cooldownUntil },
        { upsert: true, new: true }
      );

      console.log(`⏱️ Merge cooldown registrado: ${pairKey} hasta ${cooldownUntil.toISOString()}`);
      return res.json({ success: true, pairKey, cooldownUntil });
    } catch (err) {
      console.error('Error en POST /api/merge/cooldown/set:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Limpieza periódica de merge cooldowns expirados (cada hora)
setInterval(async () => {
  try {
    const result = await MergeCooldown.deleteMany({ cooldownUntil: { $lt: new Date() } });
    if (result.deletedCount > 0) {
      console.log(`🧹 Limpiados ${result.deletedCount} merge cooldowns expirados`);
    }
  } catch (err) {
    console.error('Error limpiando merge cooldowns:', err);
  }
}, 60 * 60 * 1000);

// =============================================================================
// PLAYER STATS — Modelo MongoDB + Rutas de sincronización con InvoiceSystem
// Sincroniza vida, agua, comida, oro, plata con el smart contract.
// =============================================================================

const playerStatsSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true, index: true },
  address:    { type: String, required: true, lowercase: true, index: true },
  vida:       { type: Number, default: 100000, min: 0 },
  agua:       { type: Number, default: 100000, min: 0 },
  comida:     { type: Number, default: 100000, min: 0 },
  oro:        { type: Number, default: 0,      min: 0 },
  plata:      { type: Number, default: 0,      min: 0 },
  invoiceIds: {
    vida:   { type: Number, default: null },
    agua:   { type: Number, default: null },
    comida: { type: Number, default: null },
    oro:    { type: Number, default: null },
    plata:  { type: Number, default: null },
  },
  manualIds: {
    vida:   { type: String, default: null },
    agua:   { type: String, default: null },
    comida: { type: String, default: null },
    oro:    { type: String, default: null },
    plata:  { type: String, default: null },
  },
  lastSync:    { type: Date, default: null },
  lastUpdated: { type: Date, default: Date.now },
  createdAt:   { type: Date, default: Date.now },
}, { collection: 'player_stats', timestamps: { createdAt: 'createdAt', updatedAt: 'lastUpdated' } });

const PlayerStats = mongoose.model('PlayerStats', playerStatsSchema);

const STAT_TYPES_LIST    = ['vida', 'agua', 'comida', 'oro', 'plata'];
const STAT_DEFAULTS_MAP  = { vida: 100000, agua: 100000, comida: 100000, oro: 0, plata: 0 };

// ── MARKETPLACE ROUTES MOUNT ────────────────────────────────────────────────
// Se monta aquí (y no más arriba) porque necesita GamePlayer, Listing (ya
// definidos) y PlayerStats (recién definido arriba) al mismo tiempo.
require('./marketplace-routes')(app, {
  mongoose,
  authMiddleware,
  csrfProtection,
  apiLimiter,
  strictLimiter,
  GamePlayer,
  PlayerStats,
  Listing
});

function buildStatManualId(address, stat) {
  const addrPart = address.replace(/^0x/i, '').slice(0, 8).toLowerCase();
  return `s_${addrPart}_${stat}`;
}

function getStatsContract() {
  const cfg = CONTRACTS.ITEMS_CONTRACT;
  if (!cfg || !cfg.address || !relayerWallet) return null;
  try { return new ethers.Contract(cfg.address, cfg.abi, relayerWallet); }
  catch (e) { console.error('getStatsContract error:', e.message); return null; }
}

async function getOnChainStats(contract, address) {
  try {
    const snapshot = await contract.getUserInventorySnapshot(address);
    const map = {};
    for (const inv of snapshot) {
      if (inv.active && STAT_TYPES_LIST.includes(inv.tipo)) {
        map[inv.tipo] = { id: Number(inv.id), manualId: inv.manualId, cantidad: Number(inv.cantidad) };
      }
    }
    return map;
  } catch (err) {
    console.error('getOnChainStats error:', err.message);
    return null;
  }
}

async function getSafeGasPriceStats() {
  try {
    const feeData = await provider.getFeeData();
    let gp = feeData.gasPrice || ethers.parseUnits('50', 'gwei');
    const min = ethers.parseUnits(MIN_GAS_PRICE_GWEI || '5', 'gwei');
    return gp < min ? min : gp;
  } catch (_) { return ethers.parseUnits(FALLBACK_GAS_PRICE_GWEI || '50', 'gwei'); }
}

function buildStatsResponse(doc) {
  return {
    vida: doc.vida, agua: doc.agua, comida: doc.comida, oro: doc.oro, plata: doc.plata,
    invoiceIds: {
      vida:   doc.invoiceIds?.vida   ?? null,
      agua:   doc.invoiceIds?.agua   ?? null,
      comida: doc.invoiceIds?.comida ?? null,
      oro:    doc.invoiceIds?.oro    ?? null,
      plata:  doc.invoiceIds?.plata  ?? null,
    }
  };
}

// Helper: resuelve el playerName real a partir de un param que puede ser playerName o address
async function resolvePlayerName(param) {
  if (!param) return null;
  const lc = param.toLowerCase();
  // Si parece una address ethereum, buscar por address
  if (/^0x[0-9a-f]{40}$/i.test(lc)) {
    const gp = await GamePlayer.findOne({ address: lc }).lean();
    return gp ? gp.playerName : lc; // si no tiene playerName registrado, usar address como clave
  }
  return param; // ya es un playerName normal
}




// =============================================================================
// SKILLS ROUTES
// =============================================================================
const skillsSchema = new mongoose.Schema({
  playerName:  { type: String, required: true, unique: true, index: true },
  skills:      { type: Object, default: {} },
  skillPoints: { type: Number, default: 0 },
  updatedAt:   { type: Date, default: Date.now }
}, { collection: 'player_skills' });
const PlayerSkills = mongoose.model('PlayerSkills', skillsSchema);

app.get('/api/skills/:playerName', authMiddleware, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const doc = await PlayerSkills.findOne({ playerName }).lean();
    return res.json({ skills: doc ? doc.skills : {}, skillPoints: doc ? doc.skillPoints : 0 });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

app.post('/api/skills/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const reqAddr = (req.user.address || '').toLowerCase();
    const gp = await GamePlayer.findOne({ playerName }).lean();
    if (gp && gp.address && gp.address.toLowerCase() !== reqAddr)
      return res.status(403).json({ error: 'Forbidden' });
    const { skills, skillPoints } = req.body;
    if (!skills || typeof skills !== 'object') return res.status(400).json({ error: 'Invalid' });
    await PlayerSkills.findOneAndUpdate(
      { playerName },
      { skills, skillPoints: skillPoints || 0, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    return res.json({ success: true });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});
console.log('✅ Skills routes loaded');

// =============================================================================
// PET ROUTES
// =============================================================================
const petSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true, index: true },
  pet: {
    type:     { type: String, default: 'perro' },
    visible:  { type: Boolean, default: true },
    equipped: { type: Boolean, default: true },
    skin:     { type: String, default: null },
    level:    { type: Number, default: 1 },
  },
  updatedAt: { type: Date, default: Date.now }
}, { collection: 'player_pets' });
const PlayerPet = mongoose.model('PlayerPet', petSchema);

// GET /api/pet/:playerName
app.get('/api/pet/:playerName', authMiddleware, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const doc = await PlayerPet.findOne({ playerName }).lean();
    return res.json({ pet: doc ? doc.pet : { type: 'perro', visible: true, equipped: true, level: 1 } });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

// POST /api/pet/:playerName
app.post('/api/pet/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const reqAddr = (req.user.address || '').toLowerCase();
    const gp = await GamePlayer.findOne({ playerName }).lean();
    if (gp && gp.address && gp.address.toLowerCase() !== reqAddr)
      return res.status(403).json({ error: 'Forbidden' });
    const { pet } = req.body;
    if (!pet || typeof pet !== 'object') return res.status(400).json({ error: 'Invalid pet data' });
    await PlayerPet.findOneAndUpdate(
      { playerName },
      { pet, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    return res.json({ success: true });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

console.log('✅ Pet routes loaded: /api/pet/:playerName');

// =============================================================================
// MAIL ROUTES  — /api/mail/:playerName
// =============================================================================
// Simple in-memory mail store keyed by playerName.
// Replace with DB calls (e.g. db.collection('mail')) as needed.
if (!global._mailStore) global._mailStore = {};

function getPlayerMail(player) {
  if (!global._mailStore[player]) global._mailStore[player] = [];
  return global._mailStore[player];
}

// GET /api/mail/:playerName — list mails
app.get('/api/mail/:playerName', authMiddleware, (req, res) => {
  const mails = getPlayerMail(req.params.playerName);
  res.json({ mails });
});

// POST /api/mail/:playerName/read-all — mark all read
app.post('/api/mail/:playerName/read-all', authMiddleware, csrfProtection, (req, res) => {
  getPlayerMail(req.params.playerName).forEach(m => { m.read = true; });
  res.json({ ok: true });
});

// DELETE /api/mail/:playerName/clear — delete all
app.delete('/api/mail/:playerName/clear', authMiddleware, csrfProtection, (req, res) => {
  global._mailStore[req.params.playerName] = [];
  res.json({ ok: true });
});

// DELETE /api/mail/:playerName/:mailId — delete one
app.delete('/api/mail/:playerName/:mailId', authMiddleware, csrfProtection, (req, res) => {
  const store = getPlayerMail(req.params.playerName);
  const idx = store.findIndex(m => String(m.id) === String(req.params.mailId));
  if (idx !== -1) store.splice(idx, 1);
  res.json({ ok: true });
});

// POST /api/mail/:playerName — send a mail (internal use or admin)
app.post('/api/mail/:playerName', authMiddleware, csrfProtection, (req, res) => {
  const { subject, body, from } = req.body || {};
  const mail = { id: Date.now().toString(), subject, body, from, date: new Date().toISOString(), read: false };
  getPlayerMail(req.params.playerName).unshift(mail);
  res.json({ ok: true, mail });
});

// =============================================================================
// BADGES ROUTES  — /api/badges/:playerName
// =============================================================================
// Returns badges array: [{ id, name, image }]
// Replace with real DB query as needed.
app.get('/api/badges/:playerName', authMiddleware, async (req, res) => {
  try {
    // If you have a badges collection:
    // const badges = await db.collection('badges').find({ player: req.params.playerName }).toArray();
    // res.json({ badges });
    // Placeholder: return empty array until DB is wired up
    res.json({ badges: [] });
  } catch (e) {
    res.status(500).json({ badges: [] });
  }
});

console.log('✅ Mail + Badges routes loaded');

// =============================================================================
// FURNACE + NOTIFICATIONS ROUTES
// =============================================================================

// Mongoose schemas
const furnaceSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true, index: true },
  oreItem:    { type: Object, default: null },
  coalItem:   { type: Object, default: null },
  timestamp:  { type: Number, default: 0 },
  result:     { type: Object, default: null },
  updatedAt:  { type: Date,   default: Date.now }
}, { collection: 'furnace_state' });
const FurnaceState = mongoose.model('FurnaceState', furnaceSchema);

const notifSchema = new mongoose.Schema({
  playerName:    { type: String, required: true, unique: true, index: true },
  notifications: { type: Array, default: [] },
  updatedAt:     { type: Date, default: Date.now }
}, { collection: 'player_notifications' });
const PlayerNotifications = mongoose.model('PlayerNotifications', notifSchema);

// GET /api/furnace/:playerName
app.get('/api/furnace/:playerName', authMiddleware, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const doc = await FurnaceState.findOne({ playerName }).lean();
    if (!doc) return res.json({ oreItem: null, coalItem: null, timestamp: 0 });
    return res.json(doc);
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

// POST /api/furnace/:playerName
app.post('/api/furnace/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const { oreItem, coalItem, timestamp } = req.body;
    await FurnaceState.findOneAndUpdate(
      { playerName },
      { oreItem, coalItem, timestamp: timestamp || Date.now(), updatedAt: new Date() },
      { upsert: true, new: true }
    );
    return res.json({ success: true });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

// GET /api/notifications/:playerName
app.get('/api/notifications/:playerName', authMiddleware, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const reqAddr = (req.user.address || '').toLowerCase();
    const gp = await GamePlayer.findOne({ playerName }).lean();
    if (gp && gp.address && gp.address.toLowerCase() !== reqAddr)
      return res.status(403).json({ error: 'Forbidden' });
    const doc = await PlayerNotifications.findOne({ playerName }).lean();
    return res.json({ notifications: doc ? doc.notifications : [] });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

// POST /api/notifications/:playerName
app.post('/api/notifications/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const reqAddr = (req.user.address || '').toLowerCase();
    const gp = await GamePlayer.findOne({ playerName }).lean();
    if (gp && gp.address && gp.address.toLowerCase() !== reqAddr)
      return res.status(403).json({ error: 'Forbidden' });
    const { notifications } = req.body;
    if (!Array.isArray(notifications)) return res.status(400).json({ error: 'Invalid notifications' });
    await PlayerNotifications.findOneAndUpdate(
      { playerName },
      { notifications: notifications.slice(0, 50), updatedAt: new Date() },
      { upsert: true, new: true }
    );
    return res.json({ success: true });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

console.log('✅ Furnace + Notifications routes loaded');

// Lock por jugador para evitar syncs concurrentes
const _syncLocks = new Map();

// ── GET /api/stats/:playerName ────────────────────────────────────────────────
app.get('/api/stats/:playerName', authMiddleware, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const reqAddress = (req.user.address || '').toLowerCase();
    // Verificar permiso: el address del JWT debe coincidir con el dueño
    const ownerGP = await GamePlayer.findOne({ playerName }).lean();
    if (ownerGP && ownerGP.address && ownerGP.address.toLowerCase() !== reqAddress) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    let doc = await PlayerStats.findOne({ playerName }).lean();
    if (!doc) return res.json({ stats: { ...STAT_DEFAULTS_MAP, invoiceIds: { vida: null, agua: null, comida: null, oro: null, plata: null } } });
    return res.json({ stats: buildStatsResponse(doc) });
  } catch (err) { console.error('GET /api/stats error:', err); return res.status(500).json({ error: 'Internal server error' }); }
});

// ── POST /api/stats/:playerName/sync ─────────────────────────────────────────
app.post('/api/stats/:playerName/sync', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const reqAddress2 = (req.user.address || '').toLowerCase();
    let address = (req.body.address || '').toLowerCase() || reqAddress2;
    // Verificar que el address del JWT coincide con el address solicitado
    if (address && address !== reqAddress2) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!address) {
      const gp = await GamePlayer.findOne({ playerName }).lean();
      if (gp && gp.address) address = gp.address.toLowerCase();
    }
    if (!address) return res.status(400).json({ error: 'Player address not found' });

    // Prevenir sync concurrente para el mismo jugador
    const lockKey = `sync_${address}`;
    if (_syncLocks.get(lockKey)) {
      console.log(`⏳ Sync ya en curso para ${address}, esperando...`);
      await new Promise(r => setTimeout(r, 3000));
      const existing = await PlayerStats.findOne({ playerName });
      if (existing) return res.json({ stats: buildStatsResponse(existing), source: 'lock_wait' });
    }
    _syncLocks.set(lockKey, true);

    const contract = getStatsContract();
    let statsDoc = await PlayerStats.findOne({ playerName });
    if (!statsDoc) {
      statsDoc = new PlayerStats({ playerName, address });
      STAT_TYPES_LIST.forEach(s => { statsDoc[s] = STAT_DEFAULTS_MAP[s]; });
    }

    if (!contract) {
      await statsDoc.save();
      return res.json({ stats: buildStatsResponse(statsDoc), source: 'db' });
    }

    const chainMap = await getOnChainStats(contract, address);
    if (!chainMap) {
      await statsDoc.save();
      return res.json({ stats: buildStatsResponse(statsDoc), source: 'db_fallback' });
    }

    const gasPrice = await getSafeGasPriceStats();

    for (const stat of STAT_TYPES_LIST) {
      const existing = chainMap[stat];
      if (existing) {
         statsDoc.invoiceIds[stat] = existing.id;
         statsDoc.manualIds[stat]  = existing.manualId;

          // Si chain=1 (mínimo anti-eliminación) y DB tiene valor mayor, restaurar chain
          const chainQty = Number(existing.cantidad);
          const dbQty    = Number(statsDoc[stat] || 0);
          if (chainQty === 1 && dbQty > 1) {
            const restoreVal = dbQty - 1;
            try {
              const gasPrice = await getSafeGasPriceStats();
              console.log(`🔄 Restaurando [${stat}] id=${existing.id}: chain=1 → ${dbQty}`);
              const tx = await contract.increaseInvoiceQuantity(existing.id, restoreVal, { gasPrice });
              await tx.wait();
              statsDoc[stat] = dbQty;
              console.log(`✅ [${stat}] restaurado a ${dbQty} en contrato`);
            } catch (e) {
              console.warn(`⚠️  No se pudo restaurar [${stat}]:`, e.message);
              statsDoc[stat] = Math.max(chainQty, STAT_DEFAULTS_MAP[stat] || 0);
            }
          } else {
            statsDoc[stat] = chainQty > 1 ? chainQty : Math.max(chainQty, dbQty, STAT_DEFAULTS_MAP[stat] || 0);
          }
          console.log(`✅ Stats sync [${stat}]: id=${existing.id}, qty=${statsDoc[stat]}`);
      } else {
        // ── Leer límites reales del contrato antes de crear ──────────────
        let createVal = STAT_DEFAULTS_MAP[stat] || 0;
        try {
          const ts = await contract.getTipoStats(stat);
          const exists = ts[5] !== undefined ? Boolean(ts[5]) : Boolean(ts.exists);
          if (!exists) {
            // Tipo no configurado: forzar a 0 en DB (no hay factura real)
            if (statsDoc[stat] !== 0) {
              statsDoc[stat] = 0;
              console.warn(`⚠️  Stats sync [${stat}]: tipo no configurado, forzando a 0`);
            } else {
              console.warn(`⚠️  Stats sync [${stat}]: tipo no configurado en contrato — saltando`);
            }
            continue;
          }
          const perInvoiceLimit = Number(ts.perInvoiceLimit ?? ts[2] ?? 0);
          const totalLimit      = Number(ts.limit          ?? ts[1] ?? 0);
          const totalQuantity   = Number(ts.totalQuantity  ?? ts[0] ?? 0);
          const available       = totalLimit > totalQuantity ? totalLimit - totalQuantity : 0;
          if (perInvoiceLimit > 0) createVal = Math.min(createVal, perInvoiceLimit);
          if (available       > 0) createVal = Math.min(createVal, available);
          if (createVal <= 0) { console.log(`⏭️  Stats sync [${stat}]: límite agotado en contrato`); continue; }
          console.log(`📊 [${stat}] perInvoice=${perInvoiceLimit} available=${available} → crear con ${createVal}`);
        } catch (limErr) {
          console.warn(`⚠️  getTipoStats [${stat}] falló:`, limErr.message, '— usando default');
          if (createVal <= 0) continue;
        }

        const manualId = buildStatManualId(address, stat);

        // SIEMPRE verificar manualId on-chain antes de crear — evita facturas duplicadas
        try {
          const [invFound, already] = await contract.getInvoiceByManualIdSafe(manualId);
          if (already) {
            statsDoc.invoiceIds[stat] = Number(invFound.id);
            statsDoc.manualIds[stat]  = invFound.manualId;
            statsDoc[stat]            = Number(invFound.cantidad);
            console.log(`♻️  Stats sync [${stat}]: manualId ya existía id=${invFound.id} qty=${invFound.cantidad}`);
            continue;
          }
        } catch (_) {}

        // Nunca crear con más de STAT_DEFAULTS_MAP (evita usar "available" corrupto por invoices fallidas)
        if (createVal > (STAT_DEFAULTS_MAP[stat] || 0)) createVal = STAT_DEFAULTS_MAP[stat];

        try {
          // Obtener nonce fresco para evitar colisión de nonces en TXs concurrentes
          const freshNonce = await provider.getTransactionCount(relayerWallet.address, 'pending');
          console.log(`🆕 Creando factura [${stat}] para ${address} = ${createVal} (nonce=${freshNonce})`);
          const tx = await contract.createInvoice(address, stat, createVal, manualId, { gasPrice, nonce: freshNonce });
          const receipt = await tx.wait();
          const iface = contract.interface;
          let newId = null;
          for (const log of receipt.logs) {
            try { const p = iface.parseLog(log); if (p?.name === 'InvoiceCreated') { newId = Number(p.args.id); break; } } catch (_) {}
          }
          if (newId) {
            statsDoc.invoiceIds[stat] = newId;
            statsDoc.manualIds[stat]  = manualId;
            statsDoc[stat]            = createVal;
            console.log(`✅ Factura [${stat}] creada: id=${newId} qty=${createVal}`);
          }
        } catch (txErr) { console.error(`❌ Error creando factura [${stat}]:`, txErr.message); }
      }
    }

    // Para stats sin factura en el contrato, asegurar que DB también tiene 0
    for (const stat of STAT_TYPES_LIST) {
      if (!statsDoc.invoiceIds[stat]) {
        statsDoc[stat] = 0;
      }
    }

    statsDoc.markModified('invoiceIds');
    statsDoc.markModified('manualIds');
    statsDoc.lastSync = new Date();
    await statsDoc.save();
    _syncLocks.delete(lockKey);
    return res.json({ stats: buildStatsResponse(statsDoc), source: 'chain' });

  } catch (err) {
    const lk = `sync_${(req.body?.address || '').toLowerCase()}`;
    _syncLocks.delete(lk);
    console.error('POST /api/stats/sync error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/stats/:playerName/update ───────────────────────────────────────
app.post('/api/stats/:playerName/update', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const { stats: updates } = req.body;
    const reqAddress3 = (req.user.address || '').toLowerCase();
    const ownerGP3 = await GamePlayer.findOne({ playerName }).lean();
    if (ownerGP3 && ownerGP3.address && ownerGP3.address.toLowerCase() !== reqAddress3) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!updates || typeof updates !== 'object') return res.status(400).json({ error: 'Invalid stats payload' });

    const validKeys = STAT_TYPES_LIST.filter(k => updates[k] !== undefined);
    if (!validKeys.length) return res.status(400).json({ error: 'No valid stats provided' });

    let doc = await PlayerStats.findOne({ playerName });
    if (!doc) return res.status(404).json({ error: 'Player stats not found. Call /sync first.' });

    const contract   = getStatsContract();
    const gasPrice   = await getSafeGasPriceStats();
    const txOpts     = { gasPrice };
    const txErrors   = [];

    for (const stat of validKeys) {
      const newVal  = Math.max(0, Math.round(Number(updates[stat])));
      const oldVal  = doc[stat] || 0;
      const invId   = doc.invoiceIds[stat];
      if (newVal === oldVal) continue;

      doc[stat] = newVal;

      if (!contract || !invId) {
        console.log(`ℹ️  Update [${stat}] ${oldVal}→${newVal} (solo DB)`);
        continue;
      }

      const delta = newVal - oldVal;
      try {
        // Para stats vitales: nunca bajar a 0 en el contrato (eliminaría la factura).
        // Guardamos el valor real en DB y usamos mínimo 1 en blockchain.
        const chainNewVal = Math.max(1, newVal);
        const chainOldVal = Math.max(1, oldVal);
        const chainDelta  = chainNewVal - chainOldVal;

        if (chainDelta === 0) {
          // Solo actualizar DB, sin TX (igual o ambos en mínimo 1)
          console.log(`📝 [${stat}] sin cambio en chain (${oldVal}→${newVal}), solo DB`);
        } else if (chainDelta > 0) {
          const nonce1 = await provider.getTransactionCount(relayerWallet.address, 'pending');
          console.log(`⬆️  increase [${stat}] id=${invId} +${chainDelta} (nonce=${nonce1})`);
          const tx = await contract.increaseInvoiceQuantity(invId, chainDelta, { ...txOpts, nonce: nonce1 });
          await tx.wait();
        } else {
          const dec = Math.abs(chainDelta);
          const nonce2 = await provider.getTransactionCount(relayerWallet.address, 'pending');
          console.log(`⬇️  decrease [${stat}] id=${invId} -${dec} (chain: ${chainOldVal}→${chainNewVal}, nonce=${nonce2})`);
          const tx = await contract.decreaseInvoiceQuantity(invId, dec, { ...txOpts, nonce: nonce2 });
          await tx.wait();
          // Nota: nunca llega a 0 en chain, así que la factura nunca se elimina
        }
      } catch (txErr) {
        console.error(`❌ TX error [${stat}]:`, txErr.message);
        txErrors.push({ stat, error: txErr.message });
        doc[stat] = oldVal;
      }
    }

    doc.markModified('invoiceIds');
    doc.markModified('manualIds');
    await doc.save();
    return res.json({ stats: buildStatsResponse(doc), errors: txErrors.length ? txErrors : undefined });

  } catch (err) { console.error('POST /api/stats/update error:', err); return res.status(500).json({ error: 'Internal server error' }); }
});

// ── GET /api/stats/:playerName/chain (admin) ─────────────────────────────────
app.get('/api/stats/:playerName/chain', authMiddleware, async (req, res) => {
  try {
    // Solo el propio jugador o si viene con un header especial de admin puede ver chain stats
    const reqAddress4 = (req.user.address || '').toLowerCase();
    const ownerGP4 = await GamePlayer.findOne({ playerName: req.params.playerName }).lean();
    if (ownerGP4 && ownerGP4.address && ownerGP4.address.toLowerCase() !== reqAddress4) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const { playerName } = req.params;
    const gp = await GamePlayer.findOne({ playerName }).lean();
    if (!gp || !gp.address) return res.status(404).json({ error: 'Player not found' });
    const contract = getStatsContract();
    if (!contract) return res.status(503).json({ error: 'Contract unavailable' });
    const chainMap = await getOnChainStats(contract, gp.address.toLowerCase());
    return res.json({ chainStats: chainMap });
  } catch (err) { console.error('GET /api/stats/chain error:', err); return res.status(500).json({ error: 'Internal server error' }); }
});

console.log('✅ Stats routes cargados: GET/POST /api/stats/:playerName (sync, update, chain)');


// --- MANEJO DE ERRORES ---
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'not_found' });
});

app.use((err, req, res, next) => {
  console.error('❌ Error no manejado:', err);
  res.status(500).json({ 
    error: 'internal_server_error', 
    message: NODE_ENV === 'development' ? err.message : undefined 
  });
});

// --- INICIAR SERVIDOR ---
server.listen(PORT, HOST, () => {
  console.log(`=================================`);
  console.log(`🚀 Grassland Forest Backend COMPLETO v5.0 CORREGIDO`);
  console.log(`🌍 Host: ${HOST}`);
  console.log(`🌍 Puerto: ${PORT}`);
  console.log(`🔒 Entorno: ${NODE_ENV}`);
  console.log(`🛡️  Seguridad: ACTIVADA`);
  console.log(`🚫 IPs bloqueadas: ${securityController.blockedIPs.size}`);
  console.log(`⚡ Relay System: ${relayerWallet ? 'ACTIVADO' : 'DESACTIVADO'}`);
  if (relayerWallet) {
    console.log(`👛 Relayer: ${relayerWallet.address.substring(0, 10)}...`);
  }
  console.log(`📜 Contratos: ${Object.keys(CONTRACTS).length}`);
  console.log(`💧 Sistema de agua: ACTIVO`);
  console.log(`🌱 Sistema de cultivos: ACTIVO`);
  console.log(`🎮 Socket.io: ACTIVO`);
  console.log(`🏪 Marketplace: ACTIVO`);
  console.log(`🎯 Misiones diarias: ACTIVAS`);
  console.log(`🔗 Orígenes permitidos: ${allowedOrigins.length}`);
  console.log(`🔐 Gestión de claves: ${KEY_MANAGEMENT_TYPE}`);
  console.log(`🛡️  Protección Gas Drain: ACTIVADA`);
  console.log(`⏰ Sistema Time-Lock: DISPONIBLE`);
  console.log(`⛽ Gas price fijo: ${FIXED_GAS_PRICE_GWEI ? FIXED_GAS_PRICE_GWEI + ' gwei' : 'No (dinámico)'}`);
  console.log(`=================================`);
});

// --- GRACEFUL SHUTDOWN ---
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
