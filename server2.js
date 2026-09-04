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
const PORT = parseInt(process.env.PORT || '8080', 10);
const MONGO = process.env.MONGO_URL || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/grassland';
const NODE_ENV = process.env.NODE_ENV || 'development';

// --- FIX CRÍTICO: JWT_SECRET debe ser persistente en producción ---
// Antes: si no había JWT_SECRET en el entorno, se generaba uno aleatorio en
// cada arranque. Eso invalida TODAS las sesiones en cada reinicio/redeploy, y
// si el hosting corre más de una instancia, cada una firma con un secreto
// distinto: un token válido en la instancia que hizo login puede llegar a
// otra instancia y fallar la verificación. Ambos casos producen el mismo
// síntoma: "Authentication required" justo después de un login que parecía
// exitoso.
if (!process.env.JWT_SECRET) {
  if (NODE_ENV === 'production') {
    console.error('❌ ERROR CRÍTICO: JWT_SECRET no está configurada en producción.');
    console.error('   Genera una y expórtala ANTES de arrancar el proceso, ej:');
    console.error('   node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
    process.exit(1);
  } else {
    console.warn('⚠️  JWT_SECRET no definida — usando un secreto temporal válido solo para esta ejecución (development).');
  }
}
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

const ACCESS_TOKEN_EXPIRES = process.env.ACCESS_EXPIRES || '15m';
const REFRESH_TOKEN_TTL_DAYS = parseInt(process.env.REFRESH_TTL_DAYS || '7', 10);
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN ? process.env.COOKIE_DOMAIN.trim() : undefined;
// 'lax' funciona para login/API/juego repartidos en subdominios de un mismo dominio
// (app.grasslandforest.com, api.grasslandforest.com, game.grasslandforest.com...).
// Solo usa 'none' si tu backend vive en un dominio TOTALMENTE distinto al del
// frontend/juego (ej. sigue en Railway mientras el resto ya está en tu dominio).
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || 'lax').trim().toLowerCase();
if (!['lax', 'strict', 'none'].includes(COOKIE_SAMESITE)) {
  console.warn(`⚠️  COOKIE_SAMESITE="${process.env.COOKIE_SAMESITE}" no es válido (usa lax/strict/none). Cayendo a "lax" por defecto.`);
}
const FRONTEND_ORIGINS_RAW = process.env.FRONTEND_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5501,http://127.0.0.1:5501,http://localhost:8080,http://127.0.0.1:8080,https://grasslandforest.com,https://www.grasslandforest.com,https://app.grasslandforest.com,https://game.grasslandforest.com';
const APP_NAME = process.env.APP_NAME || 'Grassland Forest';

// IMPORTANTE: En desarrollo, escuchar en 127.0.0.1 para consistencia
const HOST = NODE_ENV === 'development' ? '127.0.0.1' : '0.0.0.0';

// --- AUTOCHEQUEO: revisa esto en los logs de arranque para confirmar el entorno real ---
console.log(`🧪 Entorno: NODE_ENV=${JSON.stringify(NODE_ENV)} | COOKIE_DOMAIN=${COOKIE_DOMAIN || '(no seteado → cookie "host-only")'} | COOKIE_SAMESITE=${COOKIE_SAMESITE}`);
if (NODE_ENV !== 'production' && (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID)) {
  console.warn('⚠️  Detecté variables de Railway pero NODE_ENV no es "production". Con NODE_ENV distinto de "production" las cookies se configuran en modo desarrollo (dominio forzado a 127.0.0.1) y el login en tu dominio real se rompe. Define NODE_ENV=production en las variables de entorno de Railway.');
}

// --- Configuración de Blockchain y Relay ---
const RPC_URL = process.env.RPC_URL || "https://liteforge.rpc.caldera.xyz/http";
const CHAIN_ID = 4441;
const NETWORK_NAME = "LitVM Testnet";
const EXPLORER_URL = "https://liteforge.explorer.caldera.xyz";

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
      _origStderrWrite('⚠️  [RPC] Red LitVM no disponible' + (mins > 0 ? ' (' + mins + 'm)' : '') + '. Reintentando cada 60s...\n');
    }
    if (typeof cb === 'function') cb();
    return true;
  }
  // Red vuelve: si el chunk tiene algo exitoso y estábamos caídos, avisar
  const s = chunk.toString();
  if (_rpcDownSince && (s.includes('✅') || s.includes('Relay Manager'))) {
    _origStderrWrite('✅ [RPC] Conexión con LitVM restablecida.\n');
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
    console.log(`💰 Relayer balance (${relayerWallet.address.substring(0, 10)}...): ${balanceInEth} zkLTC`);
    
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
    address: process.env.SIMPLE_MESSAGE_LOGGER_ADDRESS || '0x786E17D89Bf97247fadC04C3A3f0dfD02F914115',
    name: 'SecureMessageLogger',
    description: 'Contrato seguro para registrar mensajes en la blockchain',
    abi: loadContractABI('SecureMessageLogger')
  },
  ITEMS_CONTRACT: {
    address: process.env.ITEM_CONTRACT_ADDRESS || '0x686E17D89Bf97247fadC04C3A3f0dfD02F914115',
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
  // Rutas REALES de esta API. Nunca son un escaneo, por mucho que su texto
  // se parezca a un patrón sospechoso. Se comprueban ANTES que la lista de
  // abajo (ver isSuspiciousPath).
  //
  // Por qué existe esto: la detección usa `includes()`, así que el patrón
  // '/admin' marcaba como escáner a '/api/admin/whoami', '/api/admin/players'
  // y '/api/admin/missions/...'. Abrir el panel de administración disparaba
  // cinco "rutas sospechosas" en segundos y el sistema BLOQUEABA la IP del
  // propio administrador.
  SAFE_OWN_PATHS: [
    '/api/admin/',        // panel de jugadores y editor de misiones
    '/api/auth/',
    '/api/relay/',
    '/api/stats/',
    '/api/security/',
    '/api/access'
  ],
  SUSPICIOUS_PATHS: [
    '/..', '/../', '/../../',
    '/.env', '/.git', '/.git/config',
    '/etc/passwd', '/etc/shadow',
    '/wp-admin', '/wp-login',
    '/administrator',
    '/phpmyadmin', '/mysql',
    '/config', '/backup',
    '/shell', '/cmd',
    '/api/v1/users/search'
    // 'favicon.ico' se quitó: TODOS los navegadores lo piden solos al abrir
    //   una página. Contarlo como escaneo penalizaba a usuarios normales.
    // '/admin' se quitó como patrón suelto: lo cubren '/wp-admin' y
    //   '/administrator', que sí son sondas reales, sin arrastrar nuestras
    //   propias rutas /api/admin/*.
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

  // ── ÚLTIMA ESCRITURA DEL MARKETPLACE EN EL INVENTARIO ──────────────────────
  // BUG QUE ESTO ARREGLA — "compré algo en el market y nunca me lo dieron":
  //
  // El market (market.html) es una PÁGINA APARTE. Al comprar, el servidor mete
  // el ítem en GamePlayer.inventory con un $push directo, y hasta ahí bien.
  // Pero la pestaña del juego tiene su PROPIA copia del inventario en memoria,
  // cargada antes de la compra, y cada vez que guarda hace
  // `update.inventory = inventory` — sobrescribe el array ENTERO. Así que el
  // primer guardado del juego después de la compra borraba el ítem recién
  // comprado. El jugador pagaba y no recibía nada.
  //
  // Aquí se apunta CUÁNDO tocó el market el inventario. /api/save compara esa
  // marca con el momento en que el cliente cargó su copia: si el market
  // escribió después, el guardado NO pisa el inventario y se le pide al
  // cliente que recargue.
  marketWriteAt: { type: Date, default: null },
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
  // Nombre de la mascota. Igual que Username: nace en '---' y solo puede
  // fijarse UNA vez (regla aplicada en /api/save).
  petName: { type: String, default: '---' },
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
  // Tutorial de bienvenida: 0 = el jugador aún no lo ha hecho, 1 = ya lo hizo.
  // Los jugadores nuevos nacen en 0 y ven el tutorial la primera vez que entran.
  tutorial: { type: Number, default: 0 },
  // Nivel de la MASCOTA. Sube con las batallas (ver computePetLevel/bump).
  // Se muestra junto al nombre del perro, propio y de los demás jugadores.
  petLevel: { type: Number, default: 1, min: 1 },

  // ── MASCOTA: vida, modo de comportamiento y muerte ──────────────────────
  // La vida va de 0 a 100 y es un PORCENTAJE: con ella entra a las batallas
  // PvP/PvE (ver crearParticipante). A 0 la mascota muere y hay que revivirla
  // con el elixir del alquimista.
  petHealth: { type: Number, default: 100, min: 0, max: 100 },
  // 'passive' → la mascota no pelea y los animales agresivos van a por el
  // JUGADOR.  'attack' → la mascota pelea y los animales van a por ELLA.
  // Lo decide el servidor a propósito: si lo escribiera el cliente, bastaría
  // con ponerlo en 'attack' para que nada tocara nunca al personaje.
  petMode: { type: String, enum: ['passive', 'attack'], default: 'passive' },
  petDiedAt: { type: Date, default: null },
  // Cuando recibio el ultimo mordisco. Sirve para el ritmo minimo entre
  // golpes: sin persistirlo, el limite se perdia en cada peticion.
  petLastHitAt: { type: Date, default: null },

  // ── MUERTES DEL JUGADOR ─────────────────────────────────────────────────
  // `isGhost` = el personaje está muerto y anda como fantasma hasta que pague
  // el revivir. `deathCount` sube con cada muerte y encarece el precio;
  // `deathWindowAt` marca cuándo empezó la ventana de 24 h tras la cual el
  // contador vuelve a cero y el precio a 30 de plata.
  isGhost: { type: Boolean, default: false },
  deathCount: { type: Number, default: 0, min: 0 },
  deathWindowAt: { type: Date, default: null },

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

// Control de acceso al juego (whitelist / baneos). Doc único '_id: config'.
//   mode 'all'       → entran todos (salvo baneados).
//   mode 'whitelist' → solo direcciones en whitelist (salvo baneados).
// banned: [{ address, reason, date }] — los baneos SIEMPRE aplican.
const accessControlSchema = new mongoose.Schema({
  _id: { type: String, default: 'config' },
  mode: { type: String, enum: ['all', 'whitelist'], default: 'all' },
  whitelist: { type: [String], default: [] },
  banned: {
    type: [{ address: String, reason: String, date: { type: Date, default: Date.now } }],
    default: []
  }
}, { versionKey: false, timestamps: true });
const AccessControl = mongoose.model('AccessControl', accessControlSchema);

async function getAccessControl() {
  let ac = await AccessControl.findById('config').lean();
  if (!ac) { await AccessControl.create({ _id: 'config' }); ac = await AccessControl.findById('config').lean(); }
  return ac;
}

// ¿La dirección es admin? (env ADMIN_ADDRESSES o isAdmin on-chain del ItemContract)
async function isAdminAddress(address) {
  const addr = String(address || '').toLowerCase();
  if (!addr) return false;
  if (process.env.ADMIN_ADDRESSES &&
      process.env.ADMIN_ADDRESSES.toLowerCase().split(',').map(s => s.trim()).includes(addr)) {
    return true;
  }
  try {
    const c = new ethers.Contract(CONTRACTS.ITEMS_CONTRACT.address, CONTRACTS.ITEMS_CONTRACT.abi, provider);
    return await c.isAdmin(addr);
  } catch (_) { return false; }
}

// ── CACHÉ DEL CONTROL DE ACCESO ────────────────────────────────────────────
// El gate se evalúa en CADA petición autenticada, así que no puede consultar
// Mongo (y menos el contrato, para isAdmin) cada vez. Se cachea 30s.
const _accessCfgCache = { doc: null, at: 0 };
const _adminAddrCache = new Map();     // address -> { value, at }
const ACCESS_CACHE_MS = 30000;

function invalidateAccessCache() {
  _accessCfgCache.doc = null;
  _accessCfgCache.at  = 0;
  _adminAddrCache.clear();
}

async function getAccessControlCached() {
  const now = Date.now();
  if (_accessCfgCache.doc && (now - _accessCfgCache.at) < ACCESS_CACHE_MS) return _accessCfgCache.doc;
  const ac = await getAccessControl();
  _accessCfgCache.doc = ac;
  _accessCfgCache.at  = now;
  return ac;
}

async function isAdminAddressCached(address) {
  const a = String(address || '').toLowerCase();
  const now = Date.now();
  const hit = _adminAddrCache.get(a);
  if (hit && (now - hit.at) < ACCESS_CACHE_MS) return hit.value;
  const v = await isAdminAddress(a);
  _adminAddrCache.set(a, { value: v, at: now });
  return v;
}

// ¿Puede este address entrar al juego? Devuelve { allowed, error?, reason?, date? }
async function checkGameAccess(address) {
  const addr = String(address || '').toLowerCase();
  // Los admins siempre pueden entrar (para poder abrir puerta_login).
  if (await isAdminAddressCached(addr)) return { allowed: true };
  const ac = await getAccessControlCached();
  const ban = (ac.banned || []).find(b => String(b.address).toLowerCase() === addr);
  if (ban) return { allowed: false, error: 'banned', reason: ban.reason || '', date: ban.date || null };

  // SUSPENSIÓN TEMPORAL (3 verificadores fallidos = 3 días, o puesta por un
  // administrador). Caduca sola, así que no hay que acordarse de levantarla.
  // Va detrás del baneo permanente porque ése manda sobre todo lo demás.
  try {
    const susp = await getActiveSuspension(addr);
    if (susp.active) {
      return {
        allowed: false,
        error: 'suspended',
        reason: susp.reason || '',
        date: susp.until || null
      };
    }
  } catch (e) {
    // Si la consulta falla no se deja fuera a nadie: se sigue con el resto.
    console.warn('⚠️  No se pudo comprobar la suspensión:', e.message);
  }

  if (ac.mode === 'whitelist') {
    const wl = (ac.whitelist || []).map(a => String(a).toLowerCase());
    if (!wl.includes(addr)) return { allowed: false, error: 'not_whitelisted' };
  }
  return { allowed: true };
}

// ── GATE DE ACCESO EN TODA PETICIÓN AUTENTICADA ────────────────────────────
// El control de whitelist/baneos de puerta_login.html se aplicaba SOLO en
// /api/auth/login. Un jugador que ya tenía la cookie de sesión guardada entraba
// directo al juego (GameScene/tiendajuego) y se saltaba el baneo por completo.
// Aplicándolo aquí, banear a alguien lo expulsa también si YA está dentro: su
// siguiente petición al backend falla con 403.
// Se dejan fuera las rutas de sesión para que un baneado pueda cerrar sesión y
// para que el cliente pueda leer el motivo del bloqueo.
const ACCESS_EXEMPT_PATHS = new Set([
  '/api/auth/logout',
  '/api/auth/refresh',
  '/api/auth/csrf-token',
  '/api/auth/me'
]);

async function enforceGameAccess(req, res, next) {
  try {
    if (ACCESS_EXEMPT_PATHS.has(req.path)) return next();

    const access = await checkGameAccess(req.user && req.user.address);
    if (access.allowed) return next();

    if (access.error === 'banned') {
      return res.status(403).json({
        error: 'banned',
        reason: access.reason || '',
        date: access.date || null,
        message: 'This account is banned'
      });
    }
    if (access.error === 'suspended') {
      return res.status(403).json({
        error: 'suspended',
        reason: access.reason || '',
        until: access.date || null,
        date: access.date || null,
        message: 'This account is temporarily suspended'
      });
    }
    return res.status(403).json({ error: 'not_whitelisted', message: 'This wallet is not on the whitelist' });
  } catch (e) {
    // Ante un fallo del chequeo NO se deja fuera a todo el mundo.
    console.warn('⚠️  enforceGameAccess falló (se permite el paso):', e.message);
    return next();
  }
}

// Middleware: exige que el usuario autenticado sea admin.
async function requireAdmin(req, res, next) {
  try {
    if (await isAdminAddress(req.user && req.user.address)) return next();
    return res.status(403).json({ error: 'admin_required' });
  } catch (e) {
    return res.status(500).json({ error: 'admin_check_failed' });
  }
}

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
    // ── RECOMPENSA EN MONEDAS (2026-08-11) ─────────────────────────────────
    // Faltaba: una misión solo podía dar experiencia y un ítem. Ahora también
    // puede pagar en oro o en plata, que se entregan por la MISMA vía que la
    // experiencia (PlayerStats + factura on-chain), así que cuentan igual que
    // cualquier otra moneda del juego. 0 = no da esa moneda.
    goldReward:   { type: Number, default: 0, min: 0 },
    silverReward: { type: Number, default: 0, min: 0 },
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
// Minutos que aguanta una planta recién sembrada SIN regar antes de secarse.
// Se elige uno al azar de esta lista en cada siembra.
const MINUTOS_PARA_REGAR = [20, 30, 40];

const UserCropSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  plotId: { type: String, required: true },
  cropType: { type: String, required: true },
  seedType: { type: String, required: true },
  growthStage: { type: Number, default: 1 },
  plantedAt: { type: Date, default: Date.now },
  growthDuration: { type: Number, required: true },
  // Duracion ORIGINAL, antes de que ningun cuervo la retrasara. Sin ella no
  // habria contra que medir el tope y los picotazos se acumularian sin fin.
  growthDurationOriginal: { type: Number, default: null },
  currentGrowthTime: { type: Number, default: 0 },
  isWatered: { type: Boolean, default: false },
  isCompleted: { type: Boolean, default: false },
  isHarvested: { type: Boolean, default: false },
  successChance: { type: Number, default: 100 },
  isDead: { type: Boolean, default: false },

  // ── CADUCIDAD DE LA COSECHA (mecánica oculta) ──────────────────────────────
  // Cuando el cultivo termina de crecer se le pone aquí una fecha límite
  // aleatoria de entre 2 y 4 horas. Si el jugador no lo recoge antes, se pudre
  // y pasa a isDead (se lleva la recompensa mala, no la buena).
  //
  // `select: false` es DELIBERADO: el jugador no debe conocer su plazo, es
  // parte del mecanismo. Con esto el campo no sale en ninguna consulta normal,
  // así que no puede colarse en la respuesta de /api/crops ni en los eventos de
  // socket aunque alguien haga un `...crop.toObject()`. Quien lo necesita lo
  // pide a mano con .select('+expiresAt').
  expiresAt: { type: Date, default: null, select: false },

  // ── SED: PLAZO PARA REGAR ──────────────────────────────────────────────────
  // Al sembrar se fija aquí una hora límite aleatoria de 20, 30 o 40 minutos.
  // Si el jugador no riega antes, la planta se seca y pasa a isDead — igual que
  // una cosecha abandonada, así que al recogerla da la recompensa mala y se
  // pinta con el sprite de planta muerta que ya existía.
  //
  // Al regar se pone a null: a partir de ahí manda el temporizador de
  // crecimiento y, cuando termine, el plazo de recogida (expiresAt).
  //
  // `select: false` por el mismo motivo que expiresAt: el plazo exacto es parte
  // de la mecánica y no se le enseña al jugador, así que no puede colarse en
  // ninguna respuesta aunque alguien haga un `...crop.toObject()`.
  sedientaHasta: { type: Date, default: null, select: false },

  rewards: {
    item: String,
    quantity: Number,
    progress_reward: String,
    progress_quantity: Number,
    deadReward: String,
    deadQuantity: Number
  }
});
// Índice para el barrido de caducados: filtra por estado y ordena por fecha.
UserCropSchema.index({ isCompleted: 1, isHarvested: 1, isDead: 1, expiresAt: 1 });
// Índice para el barrido de plantas sin regar.
UserCropSchema.index({ isWatered: 1, isHarvested: 1, isDead: 1, sedientaHasta: 1 });
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

    // ── PUERTA DE ESCAPE DEL ADMINISTRADOR ───────────────────────────────────
    // Si la petición trae una sesión válida de una cartera ADMIN, se deja pasar
    // sin analizar. Sin esto se daba una situación sin salida: el sistema
    // bloqueaba la IP del administrador, y para desbloquearla hay que llamar a
    // /api/security/unblock-ip… que está detrás del mismo bloqueo.
    // Un atacante no puede aprovecharlo: haría falta la firma de una cartera
    // que ya sea admin.
    try {
      const ses = req.cookies && req.cookies.session;
      if (ses) {
        const dec = jwt.verify(ses, JWT_SECRET, { algorithms: ['HS256'] });
        if (dec && dec.address && await isAdminAddressCached(dec.address)) {
          return next();
        }
      }
    } catch (_) { /* sin sesión o inválida: sigue el análisis normal */ }
    
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

    // 1. El recorrido de directorios se mira SIEMPRE, incluso dentro de
    //    nuestras propias rutas: eso nunca es legítimo.
    if (normalizedPath.includes('..') || normalizedPath.includes('%2e%2e')) {
      return true;
    }

    // 2. Rutas propias de esta API: no son un escaneo. Va antes de la lista de
    //    patrones porque la comparación es por `includes()` y un patrón corto
    //    como '/admin' arrastraba a '/api/admin/whoami' (y bloqueaba al
    //    administrador nada más abrir su panel).
    for (const propia of (SECURITY_CONFIG.SAFE_OWN_PATHS || [])) {
      if (normalizedPath.startsWith(propia.toLowerCase())) {
        return false;
      }
    }

    for (const pattern of SECURITY_CONFIG.SUSPICIOUS_PATHS) {
      if (normalizedPath.includes(pattern.toLowerCase())) {
        return true;
      }
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
            maxCallsPerHour: 350,
            maxCallsPerDay: 3500,
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
        // Procesar hasta 5 transacciones por intervalo.
        //
        // FIX: antes esto hacía `splice(0, 5)` a secas, sin mirar `timestamp`.
        // El reintento de abajo escribe `item.timestamp = ahora + 5s/10s/15s`
        // para espaciar los intentos, pero nadie leía ese campo: el elemento
        // volvía a procesarse en el tic siguiente (1 s después) y la espera
        // creciente no ocurría nunca. Con el nodo caído eso son tres golpes
        // seguidos al RPC en tres segundos en vez de repartidos en 30.
        // Ahora solo entran los que ya cumplieron su espera.
        const ahora = Date.now();
        const batchSize = 5;
        const itemsToProcess = [];
        for (let i = 0; i < this.transactionQueue.length && itemsToProcess.length < batchSize; i++) {
          const it = this.transactionQueue[i];
          if (!it.timestamp || it.timestamp <= ahora) {
            itemsToProcess.push(it);
            this.transactionQueue.splice(i, 1);
            i--;
          }
        }
        if (itemsToProcess.length === 0) return;

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
    // Solo causas TRANSITORIAS: cosas que probablemente funcionen al segundo
    // intento sin que nadie tenga que arreglar nada.
    //
    // FIX: 'insufficient funds' estaba en esta lista y NO pertenece aquí. Si el
    // relayer se queda sin saldo, reintentar no lo arregla: se queman los tres
    // intentos y se retrasa el aviso del problema real. Ahora se trata como
    // error definitivo, que es lo que es (checkRelayerBalance ya vigila el
    // saldo y avisa).
    const retryableErrors = [
      'nonce too low',
      'nonce has already been used',
      'replacement transaction underpriced',
      'transaction underpriced',
      'network error',
      'timeout',
      'econnreset',
      'etimedout',
      'socket hang up',
      'server_error',
      'bad response',
      'could not detect network'
    ];

    const msg = (error && (error.message || error.reason || '')).toLowerCase();
    if (!msg) return false;

    // Un revert del contrato nunca se reintenta: la transacción está mal, y
    // repetirla solo gasta gas para volver a fallar igual.
    if (msg.includes('execution reverted') || msg.includes('call_exception')) return false;

    return retryableErrors.some(m => msg.includes(m));
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
  
  // ---------------------------------------------------------------------------
  // VERIFICADOR DE PROPIEDAD DE FACTURA (anti-trampa)
  // Antes de firmar una manipulación de una factura EXISTENTE, lee la factura
  // on-chain y confirma que su `owner` es el jugador solicitante (y, para las
  // que restan/mueven, que hay cantidad suficiente). Lanza si no cumple, así el
  // relay NUNCA firma la manipulación de facturas ajenas o inexistentes.
  // Funciones que NO tocan una factura existente (createInvoice, setLimit,
  // vistas, logMessage…) se omiten.
  // ---------------------------------------------------------------------------
  async verifyInvoiceOwnership(contract, functionName, parameters, playerAddress) {
    // función → posición del id de factura, cantidad y (opcional) dueño de origen.
    const OWNED_INVOICE_FNS = {
      decreaseInvoiceQuantity:         { idArg: 0, amountArg: 1 },
      increaseInvoiceQuantity:         { idArg: 0 },
      deleteInvoice:                   { idArg: 0 },
      transferInvoice:                 { idArg: 2, amountArg: 3, ownerArg: 0 },
      transferQuantityBetweenInvoices: { idArg: 0, amountArg: 2 }
    };
    const cfg = OWNED_INVOICE_FNS[functionName];
    if (!cfg) return; // no es manipulación de una factura existente

    const args = Array.isArray(parameters) ? parameters : Object.values(parameters || {});
    const player = String(playerAddress || '').toLowerCase();

    const invoiceId = Number(args[cfg.idArg]);
    if (!Number.isFinite(invoiceId) || invoiceId <= 0) {
      throw new Error('ownership_check_failed: invalid invoice id');
    }

    // transferInvoice manda el fromOwner explícito: debe ser el propio jugador.
    if (cfg.ownerArg != null) {
      const fromOwner = String(args[cfg.ownerArg] || '').toLowerCase();
      if (fromOwner !== player) {
        throw new Error('ownership_check_failed: fromOwner is not the requesting player');
      }
    }

    /* Leer la factura on-chain (getInvoice revierte si no existe → se captura).
     *
     * PERO NO TODO LO QUE FALLA AQUÍ ES "no existe". Este catch se tragaba
     * TAMBIÉN las caídas del nodo, y ese era un fallo caro:
     *
     *   El nodo de LitVM se cae y vuelve cada pocos minutos (está documentado
     *   arriba, en esErrorTransitorioRPC). Cuando se caía justo en esta
     *   lectura, el error de red se convertía aquí en un
     *   "ownership_check_failed: invoice N not found on-chain" — un mensaje que
     *   ya NO parece transitorio. Y como conReintentoRPC() solo reintenta lo
     *   que parece transitorio, dejaba de reintentar: la comprobación
     *   anti-trampa se saldaba con "esa factura no existe" y la acción del
     *   jugador se perdía. En el juego eso se veía como "❌ Error borrando
     *   invoice 1764" al craftear o al llenar el balde en la fuente, con la
     *   factura perfectamente viva en la cadena.
     *
     * Se distingue: si el nodo no contestó, se relanza el error ORIGINAL para
     * que el reintento lo reconozca y vuelva a intentarlo. Solo cuando la
     * lectura llegó de verdad al contrato y este revirtió se puede afirmar que
     * la factura no está. */
    let inv;
    try {
      inv = await contract.getInvoice(invoiceId);
    } catch (e) {
      if (RelayManager.esErrorTransitorioRPC(e)) throw e;
      throw new Error(`ownership_check_failed: invoice ${invoiceId} not found on-chain`);
    }
    if (!inv || !inv.active) {
      throw new Error(`ownership_check_failed: invoice ${invoiceId} is inactive`);
    }
    if (String(inv.owner || '').toLowerCase() !== player) {
      throw new Error(`ownership_check_failed: invoice ${invoiceId} does not belong to the player`);
    }
    if (cfg.amountArg != null) {
      let amount;
      try { amount = BigInt(args[cfg.amountArg]); } catch (e) { amount = 0n; }
      if (amount > 0n && BigInt(inv.cantidad) < amount) {
        throw new Error(`ownership_check_failed: insufficient quantity in invoice ${invoiceId}`);
      }
    }
    console.log(`🔐 [ownership] OK: ${functionName} sobre factura ${invoiceId} (dueño ${player.substring(0, 10)}…)`);
  }

  // Bloquea (si GATHER_ENFORCE) que el CLIENTE acuñe tipos de recolección vía
  // relay: esos ítems solo puede acuñarlos el servidor (/api/gather/claim), que
  // llama al contrato directamente (sin pasar por aquí). Inerte con el flag off.
  async blockClientGatherMint(contract, functionName, parameters) {
    if (!GATHER_ENFORCE) return;
    const args = Array.isArray(parameters) ? parameters : Object.values(parameters || {});
    let tipo = null;
    if (functionName === 'createInvoice') {
      tipo = String(args[1] || '');                 // createInvoice(owner, tipo, cantidad, manualId)
    } else if (functionName === 'increaseInvoiceQuantity') {
      const id = Number(args[0]);
      if (id > 0) { try { const inv = await contract.getInvoice(id); tipo = String(inv.tipo || ''); } catch (_) {} }
    } else {
      return;
    }
    if (tipo && GATHER_TIPOS.has(tipo)) {
      throw new Error('gather_mint_blocked: los recursos de recolección solo los acuña el servidor (/api/gather/claim)');
    }
  }

  /**
   * ¿El error viene de que el NODO no responde, y no de la transacción en sí?
   *
   * El nodo de LitVM se cae y vuelve cada pocos minutos ("[RPC] Red LitVM no
   * disponible"). Cuando eso pasa a mitad de una transacción, cualquier lectura
   * o el propio envío revientan, y hasta ahora la acción del jugador se perdía:
   * daba igual que fuera cosechar, craftear, talar, minar, recoger agua,
   * comer/beber o comprar en la tienda — todo pasa por aquí.
   *
   * Un revert del CONTRATO (sin cupo, sin saldo, no autorizado) NO entra aquí:
   * ese error es real y hay que devolverlo tal cual.
   */
  static esErrorTransitorioRPC(err) {
    if (!err) return false;
    const code = String(err.code || '');
    if (['NETWORK_ERROR', 'SERVER_ERROR', 'TIMEOUT', 'ECONNRESET', 'ECONNREFUSED',
         'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'EHOSTUNREACH'].includes(code)) {
      return true;
    }
    // Un revert del contrato nunca es transitorio, aunque el texto se parezca.
    if (code === 'CALL_EXCEPTION' || err.reason || err.revert) return false;

    const msg = String(err.shortMessage || err.message || '').toLowerCase();
    return (
      msg.includes('could not detect network') ||
      msg.includes('failed to fetch')          ||
      msg.includes('fetch failed')             ||
      msg.includes('connection refused')       ||
      msg.includes('connection reset')         ||
      msg.includes('socket hang up')           ||
      msg.includes('network error')            ||
      msg.includes('timeout')                  ||
      msg.includes('timed out')                ||
      msg.includes('bad gateway')              ||
      msg.includes('service unavailable')      ||
      msg.includes('gateway timeout')          ||
      msg.includes('502') || msg.includes('503') || msg.includes('504') ||
      msg.includes('server response')          ||
      // Los errno de Node llegan a veces solo dentro del texto (por ejemplo
      // "FetchError: request failed, reason: connect ECONNREFUSED"), sin que
      // err.code los traiga. Sin esto, una caída del nodo se tomaba por un
      // error real y la acción del jugador se perdía.
      msg.includes('econnrefused') || msg.includes('econnreset')  ||
      msg.includes('etimedout')    || msg.includes('enotfound')   ||
      msg.includes('eai_again')    || msg.includes('ehostunreach') ||
      msg.includes('epipe')        || msg.includes('enetunreach')
    );
  }

  /**
   * Ejecuta `fn` reintentando SOLO si el nodo no responde, con espera creciente.
   * Le da al RPC tiempo de volver en vez de perder la acción del jugador.
   */
  static async conReintentoRPC(fn, etiqueta = 'rpc', intentos = 4) {
    let ultimo;
    for (let i = 0; i < intentos; i++) {
      try {
        return await fn();
      } catch (e) {
        ultimo = e;
        if (!RelayManager.esErrorTransitorioRPC(e) || i === intentos - 1) throw e;
        const espera = 800 * Math.pow(2, i);   // 0.8s, 1.6s, 3.2s
        console.warn(`⚠️  [RPC] ${etiqueta} falló (${e.shortMessage || e.message}). Reintento ${i + 1}/${intentos - 1} en ${espera}ms`);
        await new Promise(r => setTimeout(r, espera));
      }
    }
    throw ultimo;
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

      // 3.5. VERIFICACIÓN DE PROPIEDAD (anti-trampa). Antes de manipular una
      // factura EXISTENTE (decrease/increase/delete/transfer), confirmar on-chain
      // que pertenece al jugador que la solicita y que tiene cantidad suficiente.
      // Sin esto, un jugador podía pedir manipular facturas de OTRO usuario.
      // Envuelta en reintento: si el nodo está caído justo ahora, esta lectura
      // fallaría y la acción del jugador se perdería sin motivo real.
      await RelayManager.conReintentoRPC(
        () => this.verifyInvoiceOwnership(contract, functionName, parameters, playerAddress),
        'verifyInvoiceOwnership'
      );

      // 3.6. ANTI-TRAMPA DE RECOLECCIÓN: si GATHER_ENFORCE está activo, el
      // cliente NO puede acuñar los tipos de recolección (madera/minerales);
      // esos SOLO los acuña el servidor en /api/gather/claim. Inerte si el flag
      // está apagado.
      await this.blockClientGatherMint(contract, functionName, parameters);

      // 3.7. CUPO DE LA TABLA DEL ÍTEM. Ver ensureItemTipoOnChain: si el tipo
      // que se va a acuñar no existe todavía en el contrato, o se quedó sin
      // cupo, el relayer (que es admin) lo prepara ANTES de firmar. Sin esto la
      // transacción revierte y el jugador pierde lo que acababa de recolectar.
      // Es la causa del "al minar carbón fallan las transacciones".
      await ensureItemTipoParaTransaccion(contract, functionName, parameters);

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
        const feeData = await RelayManager.conReintentoRPC(
          () => provider.getFeeData(), 'getFeeData'
        );
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
      const relayerBalance = await RelayManager.conReintentoRPC(
        () => provider.getBalance(relayerWallet.address), 'getBalance'
      );
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

      // 11. Firmar y enviar — CON AUTO-RECUPERACIÓN de nonce desincronizado.
      // Antes, si el broadcast fallaba con "nonce too low"/"nonce has already
      // been used" (NONCE_EXPIRED), la transacción se marcaba como fallida y se
      // reembolsaba (síntoma: "Compra parcial 0/N — reembolso"). Ahora, ante ese
      // error, se resetea el nonce del relayer desde la cadena y se REINTENTA
      // con un nonce fresco, así el sistema se auto-corrige solo.
      // Además del nonce, ahora se reintenta cuando el NODO no responde: era el
      // caso más doloroso, porque el jugador ya había gastado el ítem o el
      // recurso y la transacción se perdía por una caída de 10 segundos del RPC.
      let txResponse;
      let currentTxNonce = nonce;
      const MAX_SEND_RETRIES = 5;
      let esperaRPC = 800;
      for (let attempt = 0; attempt < MAX_SEND_RETRIES; attempt++) {
        try {
          tx.nonce = currentTxNonce;
          const signedTx = await relayerWallet.signTransaction(tx);
          txResponse = await provider.broadcastTransaction(signedTx);
          break; // enviado con éxito
        } catch (sendErr) {
          const msg = String(sendErr?.shortMessage || sendErr?.message || '').toLowerCase();
          const isNonceError =
            sendErr?.code === 'NONCE_EXPIRED' ||
            msg.includes('nonce too low') ||
            msg.includes('nonce has already been used') ||
            msg.includes('replacement transaction underpriced');

          const quedanIntentos = attempt < MAX_SEND_RETRIES - 1;

          if (isNonceError && quedanIntentos) {
            console.warn(`⚠️  Nonce desincronizado (usado ${currentTxNonce}): reseteando desde la cadena y reintentando (intento ${attempt + 1}/${MAX_SEND_RETRIES})…`);
            await relayerNonceManager.resetNonce();
            currentTxNonce = await relayerNonceManager.getNextNonce();
            relayTx.nonce = currentTxNonce;
            continue;
          }

          if (RelayManager.esErrorTransitorioRPC(sendErr) && quedanIntentos) {
            console.warn(`⚠️  [RPC] Nodo no disponible al enviar (${sendErr.shortMessage || sendErr.message}). Reintento ${attempt + 1}/${MAX_SEND_RETRIES} en ${esperaRPC}ms…`);
            await new Promise(r => setTimeout(r, esperaRPC));
            esperaRPC = Math.min(esperaRPC * 2, 6000);
            // El nonce se relee: mientras el nodo estaba caído puede haber
            // avanzado por otra vía.
            try {
              await relayerNonceManager.resetNonce();
              currentTxNonce = await relayerNonceManager.getNextNonce();
              relayTx.nonce = currentTxNonce;
            } catch (_) { /* se reintenta con el mismo nonce */ }
            continue;
          }

          throw sendErr; // revert real del contrato, o se agotaron los reintentos
        }
      }

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
      
      // SIEMPRE obtener un nonce FRESCO al reprocesar. Antes se REUTILIZABA
      // relayTx.nonce, pero si la tx original falló por "nonce too low" /
      // "nonce has already been used" (la cadena ya pasó ese nonce), reusar el
      // MISMO nonce la hace fallar en bucle infinito. Un nonce nuevo del manager
      // rompe ese bucle.
      let nonce = await relayerNonceManager.getNextNonce();
      console.log(`🔢 Nonce fresco para reproceso: ${nonce}`);
      
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
          gasLimit = 10000000n; // 3 millones de gas para zkLTC
          console.log(`   - Gas limit fijo para logMessage: ${gasLimit}`);
        } else if (relayTx.gasLimit) {
          // Usar el gas limit anterior pero aumentarlo en 200%
          gasLimit = BigInt(relayTx.gasLimit) * 3n / 1n; // Triple para asegurar
          console.log(`   - Gas limit aumentado (200%): ${gasLimit} (anterior: ${relayTx.gasLimit})`);
        } else {
          // Valor por defecto muy alto para zkLTC
          gasLimit = 10000000n; // 3 millones de gas
          console.log(`   - Gas limit por defecto para zkLTC: ${gasLimit}`);
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
      
      // 3. Verificar límites de gas para zkLTC
      await this.validateGasParameters(gasLimit, gasPrice);
      
      // Calcular costo estimado en zkLTC
      const estimatedCost = gasLimit * gasPrice;
      console.log(`💰 Costo estimado en zkLTC: ${ethers.formatEther(estimatedCost)} zkLTC`);
      console.log(`📊 Detalles de gas finales:`);
      console.log(`   - Gas Limit: ${gasLimit}`);
      console.log(`   - Gas Price: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);
      console.log(`   - Costo Total: ${ethers.formatEther(estimatedCost)} zkLTC`);
      
      // 4. Verificar saldo del relayer en zkLTC
      const relayerBalance = await provider.getBalance(relayerWallet.address);
      console.log(`💰 Saldo del relayer: ${ethers.formatEther(relayerBalance)} zkLTC`);
      
      if (relayerBalance < estimatedCost) {
        const errorMsg = `Relayer insufficient zkLTC balance: ${ethers.formatEther(relayerBalance)} < ${ethers.formatEther(estimatedCost)}`;
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
      
      // 7-8. Firmar y enviar CON auto-recuperación de nonce desincronizado.
      console.log(`✍️ Firmando y enviando transacción...`);
      let txResponse;
      const MAX_NONCE_RETRIES = 3;
      for (let attempt = 0; attempt < MAX_NONCE_RETRIES; attempt++) {
        try {
          tx.nonce = nonce;
          const signedTx = await relayerWallet.signTransaction(tx);
          txResponse = await provider.broadcastTransaction(signedTx);
          break; // enviado con éxito
        } catch (sendErr) {
          const msg = String(sendErr?.shortMessage || sendErr?.message || '').toLowerCase();
          const isNonceError =
            sendErr?.code === 'NONCE_EXPIRED' ||
            msg.includes('nonce too low') ||
            msg.includes('nonce has already been used') ||
            msg.includes('replacement transaction underpriced');
          if (isNonceError && attempt < MAX_NONCE_RETRIES - 1) {
            console.warn(`⚠️  Nonce desincronizado (usado ${nonce}) al reprocesar: reseteando desde la cadena y reintentando (${attempt + 1}/${MAX_NONCE_RETRIES})…`);
            await relayerNonceManager.resetNonce();
            nonce = await relayerNonceManager.getNextNonce();
            continue;
          }
          throw sendErr; // error no recuperable o reintentos agotados
        }
      }

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
      /* CON try/catch, y no es cosmetico.

         Este callback es `async` y no lo capturaba nadie: si Mongo estaba
         reconectando en el momento del tic --y pasa-- el `await` rechazaba,
         nadie recogia el rechazo y, en Node 15 o superior, una promesa
         rechazada sin capturar TERMINA EL PROCESO. O sea que un hipo de la base
         de datos a las 00:00 tiraba el servidor entero con todos los jugadores
         dentro. Ver tambien el guardian de `unhandledRejection` al final del
         archivo. */
      try {
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
      } catch (e) {
        console.error('❌ Reset diario de recoleccion de agua:', e && e.message);
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

  /**
   * DESHACE una recolección ya apuntada.                        (2026-08-05)
   *
   * El pozo funciona en dos pasos: primero se APUNTA aquí (que es lo que
   * impide sacar agua diez veces seguidas) y después el cliente cambia el balde
   * vacío por el lleno con transacciones on-chain. Si esas transacciones no
   * salen, el jugador se quedaba sin balde Y sin el turno del pozo: perdía una
   * de las 5 recolecciones del día y encima tenía que esperar 10 minutos.
   *
   * Con esto, el cliente avisa del fallo y el turno se devuelve tal cual estaba.
   */
  async refundCollection(playerName) {
    const record = await WaterCollection.findOne({ playerName });
    if (!record) return { success: false, error: 'no_record' };

    record.collectionCount       = Math.max(0, (record.collectionCount || 0) - 1);
    record.totalCollectionsToday = Math.max(0, (record.totalCollectionsToday || 0) - 1);
    record.collectionCycle       = ((record.collectionCycle || 0) + 4) % 5; // -1 en módulo 5
    record.isDailyLimitReached   = record.totalCollectionsToday >= 5;
    // Se puede volver a intentar de inmediato: el intento anterior no llegó a
    // entregar nada.
    record.nextAvailableTime     = null;
    record.lastCollectionTime    = null;
    await record.save();

    console.log(`💧 Recolección devuelta a ${playerName} (quedan ${5 - record.totalCollectionsToday} hoy)`);
    return {
      success: true,
      collectionsToday: record.totalCollectionsToday,
      collectionCycle: record.collectionCycle
    };
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

// =============================================================================
// CADUCIDAD DE LAS COSECHAS — MECÁNICA OCULTA                   (2026-08-11)
// -----------------------------------------------------------------------------
// Una cosecha que queda lista y NO se recoge se pudre. El plazo es distinto en
// cada parcela y en cada siembra: se sortea entre 2 y 4 horas en el momento en
// que el cultivo termina de crecer.
//
// Que sea aleatorio y por parcela es lo que hace que el jugador no pueda
// calcular "vuelvo dentro de X y llego justo": tiene que atender el huerto de
// verdad. Por eso el plazo NO se le comunica nunca (el campo `expiresAt` es
// select:false y no viaja en ningún evento ni respuesta).
//
// Se decide en el SERVIDOR, así que no se puede tocar desde el cliente.
// =============================================================================
const CROP_EXPIRE_MIN_H = 2;
const CROP_EXPIRE_MAX_H = 4;

/** Fecha límite aleatoria para recoger una cosecha que acaba de estar lista. */
function nuevaFechaDeCaducidad(desde = Date.now()) {
  const minMs = CROP_EXPIRE_MIN_H * 60 * 60 * 1000;
  const maxMs = CROP_EXPIRE_MAX_H * 60 * 60 * 1000;
  // crypto.randomInt da una distribución uniforme de verdad y no es predecible
  // desde fuera (Math.random sí lo sería si alguien estudiara el patrón).
  const margen = crypto.randomInt(0, Math.max(1, maxMs - minMs));
  return new Date(desde + minMs + margen);
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
      // Fresa. Cultivo de nivel 3: la bolsa se vende a 20 de plata en la
      // tienda y solo aparece a partir de ese nivel. Las claves de imagen
      // tienen que existir en el preload de GameScene.js.
      Semillax4: {
        id: 'Semillax4',
        name: 'Strawberry',
        type: 'semilla4',
        growthStages: 4,
        growthTime: 300,
        waterRequired: true,
        waterCost: 1,
        foodCost: 0.2,
        wateringCost: 0.5,
        agricultureReq: 0,
        strengthReq: 0,
        levelReq: 3,
        images: {
          stage1: 'tierra_seca_plant_fresa',
          stage2: 'tierra_mojada_plant_fresa',
          stage3: 'tierra_mojada_plant2_fresa',
          stage4: 'tierra_mojada_plant3_fresa',
          stage5: 'tierra_muerta_plant4_fresa'
        },
        rewards: {
          item: 'fresa_buena',
          quantity: 1,
          progress_reward: 'fresa_corta',
          progress_quantity: 1,
          deadReward: 'fresa_mala',
          deadQuantity: 1
        }
      },
    };
    
    this.startGrowthTimers();
    // Barrido de cosechas abandonadas (mecánica oculta de caducidad).
    this.startExpiryTimer();
    // Barrido de plantas recién sembradas que nadie riega: se secan a los
    // 20, 30 o 40 minutos según lo que les tocara al sembrarlas.
    this.startThirstTimer();
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

      // DIFICULTAD DESDE EL SERVIDOR (2026-08-04)
      // ---------------------------------------------------------------------
      // Antes, la probabilidad venía en `successChance` DEL CLIENTE, y el
      // cliente mandaba siempre 100 (calcularPosibilidad devolvía "100.00"),
      // así que la siembra no tenía dificultad ninguna — y un cliente
      // manipulado podía mandar lo que quisiera. Ahora manda la configuración
      // editable en admin.html (FarmingConfig). El valor del cliente se ignora
      // por completo; solo se conserva el parámetro por compatibilidad de firma.
      let adjustedChance = 95;
      let farmCfg = null;
      try {
        farmCfg = await getFarmingConfig();
        adjustedChance = await successChanceParaSemilla(seedType);
      } catch (e) {
        console.warn('⚠️  No se pudo leer la configuración de siembra, se usa 95%:', e.message);
      }
      adjustedChance = Math.max(1, Math.min(100, adjustedChance));

      // Si el administrador desactivó las muertes, nada puede morir.
      if (farmCfg && farmCfg.deathEnabled === false) adjustedChance = 100;

      // El tiempo de crecimiento también es configurable.
      const multCrecimiento = farmCfg && Number(farmCfg.growthMultiplier) > 0
        ? Number(farmCfg.growthMultiplier) : 1;
      const duracion = Math.max(5, Math.round(cropConfig.growthTime * multCrecimiento));

      const newCrop = new UserCrop({
        userId,
        plotId,
        cropType: seedType,
        seedType,
        growthDuration: duracion,
        rewards: cropConfig.rewards,
        isWatered: false,
        growthStage: 1,
        successChance: adjustedChance,
        isDead: false,
        // Plazo para regar: 20, 30 o 40 minutos, al azar. Que no sea siempre el
        // mismo evita que se pueda apurar al segundo y obliga a estar pendiente.
        sedientaHasta: new Date(Date.now() + MINUTOS_PARA_REGAR[
          Math.floor(Math.random() * MINUTOS_PARA_REGAR.length)
        ] * 60 * 1000)
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
      // Regada a tiempo: se cancela el plazo de sed y a partir de aquí manda el
      // temporizador de crecimiento.
      crop.sedientaHasta = null;
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

  /**
   * Barrido de cosechas abandonadas.
   *
   * Corre aparte del temporizador de crecimiento a propósito: aquel filtra por
   * `isCompleted: false`, así que en cuanto un cultivo está listo SALE de su
   * consulta y ya nadie lo vuelve a mirar. Ahí es justo donde tiene que
   * empezar a contar el plazo.
   *
   * Cada minuto busca las cosechas que ya pasaron su fecha límite y las pudre:
   * `isDead = true`, con lo que al recogerlas dan la recompensa mala
   * (deadReward) en vez de la buena, y el cliente pinta el sprite de planta
   * muerta que ya existía (`tierra_muerta_plant4`).
   *
   * Un minuto de resolución es de sobra para un plazo de 2–4 horas y cuesta una
   * consulta indexada por minuto.
   */
  async startExpiryTimer() {
    setInterval(async () => {
      try {
        const ahora = new Date();

        // .select('+expiresAt') porque el campo es select:false (oculto al jugador).
        const caducadas = await UserCrop.find({
          isCompleted: true,
          isHarvested: false,
          isDead:      false,
          expiresAt:   { $ne: null, $lte: ahora }
        }).select('+expiresAt');

        if (!caducadas.length) return;

        for (const crop of caducadas) {
          crop.isDead = true;
          await crop.save();

          const cropConfig = this.cropTypes[crop.cropType];

          // Se avisa al cliente con el MISMO evento que usa el crecimiento, para
          // que la escena repinte la parcela sin necesitar código nuevo.
          if (this.io) {
            this.io.emit('cropGrowth', {
              userId:      crop.userId,
              plotId:      crop.plotId,
              growthStage: crop.growthStage,
              currentGrowthTime: crop.currentGrowthTime,
              isHalfway:   false,
              isCompleted: true,
              isDead:      true,
              timeRemaining: 0,
              cropConfig:  cropConfig
              // OJO: aquí no va expiresAt. El plazo no se le enseña al jugador.
            });
          }

          console.log(`🥀 Cosecha perdida por abandono: ${crop.userId} / parcela ${crop.plotId} (${crop.cropType})`);
        }
      } catch (error) {
        console.error('Error en el barrido de cosechas caducadas:', error);
      }
    }, 60 * 1000);
  }

  /**
   * BARRIDO DE PLANTAS SIN REGAR.
   *
   * Va aparte del temporizador de crecimiento porque aquel solo mira cultivos
   * con `isWatered: true` — las que nadie ha regado no entran en su consulta y
   * por eso, hasta ahora, se quedaban indefinidamente esperando un riego que
   * podía no llegar nunca.
   *
   * Cada minuto busca las que pasaron su plazo (20, 30 o 40 min según la
   * siembra) y las seca: `isDead = true`. Al recogerlas dan la recompensa mala
   * (deadReward) y el cliente pinta el sprite de planta muerta, exactamente
   * igual que con una cosecha abandonada — no hace falta código nuevo en el
   * juego.
   */
  async startThirstTimer() {
    setInterval(async () => {
      try {
        const ahora = new Date();

        // .select('+sedientaHasta') porque el campo es select:false.
        const secas = await UserCrop.find({
          isWatered:     false,
          isHarvested:   false,
          isDead:        false,
          isCompleted:   false,
          sedientaHasta: { $ne: null, $lte: ahora }
        }).select('+sedientaHasta');

        if (!secas.length) return;

        for (const crop of secas) {
          crop.isDead = true;
          crop.sedientaHasta = null;
          await crop.save();

          const cropConfig = this.cropTypes[crop.cropType];

          if (this.io) {
            this.io.emit('cropGrowth', {
              userId:      crop.userId,
              plotId:      crop.plotId,
              growthStage: crop.growthStage,
              currentGrowthTime: crop.currentGrowthTime,
              isHalfway:   false,
              isCompleted: false,
              isDead:      true,
              timeRemaining: 0,
              cropConfig:  cropConfig
            });
          }

          console.log(`🥀 Planta seca por falta de riego: ${crop.userId} / parcela ${crop.plotId} (${crop.cropType})`);
        }
      } catch (error) {
        console.error('Error en el barrido de plantas sin regar:', error);
      }
    }, 60 * 1000);
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

          // DURACIÓN REAL DEL CULTIVO (2026-08-04): se usa la que quedó
          // guardada al sembrar (`growthDuration`), no la de la tabla fija.
          // Así el multiplicador de crecimiento que se pone en admin.html
          // afecta de verdad: antes el cultivo se plantaba con una duración y
          // luego maduraba con otra, y la barra del cliente no cuadraba.
          const duracionReal = Number(crop.growthDuration) > 0
            ? Number(crop.growthDuration)
            : cropConfig.growthTime;

          const growthPerStage = duracionReal / cropConfig.growthStages;

          let newStage = 1;
          if (crop.currentGrowthTime >= growthPerStage * 3) {
            newStage = 4;
          } else if (crop.currentGrowthTime >= growthPerStage * 2) {
            newStage = 3;
          } else if (crop.currentGrowthTime >= growthPerStage) {
            newStage = 2;
          }

          const wasHalfway = crop.currentGrowthTime - 1 < duracionReal / 2 &&
                           crop.currentGrowthTime >= duracionReal / 2;
          const isNowCompleted = crop.currentGrowthTime >= duracionReal;

          let isDead = false;
          if (isNowCompleted && !crop.isCompleted) {
            const random = Math.random() * 100;
            isDead = random > crop.successChance;

            if (isDead) {
              crop.isDead = true;
            } else {
              crop.isCompleted = true;
              // La cosecha queda lista: empieza a correr su plazo para
              // recogerla. Ver CROP_EXPIRE_MIN_H / MAX_H.
              crop.expiresAt = nuevaFechaDeCaducidad();
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
              timeRemaining: Math.max(0, duracionReal - crop.currentGrowthTime),
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
/* HISTORIAL DE CHAT POR SALA, NO UNO PARA TODO EL SERVIDOR.
   ────────────────────────────────────────────────────────────────────────────
   FALLO QUE ESTO ARREGLA (fuga entre canales): `chatHistory` era UN solo array
   de 50 mensajes compartido por el servidor entero. Como las salas llevan el
   canal en el nombre ('game#c3', 'tienda#c7'), un jugador del canal 3 que pedía
   el historial recibía los mensajes de los diez canales y de las dos salas.
   Además, con varios canales hablando a la vez, 50 mensajes globales se
   consumían en segundos y el historial de tu propia sala desaparecía enseguida.

   Ahora hay un anillo de 50 POR SALA. Se guardan en un Map, y las salas que se
   quedan sin nadie se borran en la purga periódica para que el Map no crezca
   sin techo con canales que ya nadie usa. */
const chatHistory = new Map();          // sala -> array de mensajes
const MAX_HISTORY = 50;

/** El anillo de mensajes de una sala, creándolo si hace falta. */
function historialDe(room) {
  let h = chatHistory.get(room);
  if (!h) { h = []; chatHistory.set(room, h); }
  return h;
}
const rooms = {
  'game': {},
  'tienda': {}
};

// =============================================================================
// CANALES  (10 canales de 50 jugadores)
// =============================================================================
//
// QUÉ SON: copias paralelas del mundo. Dos jugadores solo se ven, se hablan por
// el chat y aparecen en la clasificación del otro si están en el MISMO canal.
//
// CÓMO SE APOYA EN LO QUE YA HABÍA: el juego ya separaba a la gente por "salas"
// ('game' y 'tienda') y el chat ya iba con io.to(room). El canal se añade al
// nombre de la sala:
//
//      game#c1     tienda#c1      <- canal 1
//      game#c2     tienda#c2      <- canal 2
//
// Así el chat y el movimiento quedan separados por canal sin tocar nada de esa
// lógica, y a la vez se conserva la separación mapa/tienda que ya existía.
//
// CUÁNDO SE ASIGNA: UNA SOLA VEZ, al conectar el socket (más abajo, en
// io.on('connection')). No al entrar en una escena. Ese es justo el punto: si se
// asignara al cargar cada escena, pasar del mapa a la tienda podría meterte en
// otro canal si el tuyo se hubiera llenado entretanto, y perderías de vista a la
// gente con la que estabas jugando. Como window.globalSocket se crea una vez por
// pestaña y sobrevive a los cambios de escena, el canal dura toda la sesión.
//
// DÓNDE VIVE: solo en memoria del servidor (socket.playerData.canal). No se
// guarda en la base de datos ni en el navegador.
const CANALES_TOTAL = 10;
const CANAL_CUPO    = 50;

/** Cuántos jugadores hay ahora en cada canal. Índice 0 sin usar. */
function ocupacionCanales() {
  const cuenta = new Array(CANALES_TOTAL + 1).fill(0);
  try {
    for (const [, s] of io.of('/').sockets) {
      const c = s.playerData && s.playerData.canal;
      if (Number.isInteger(c) && c >= 1 && c <= CANALES_TOTAL) cuenta[c]++;
    }
  } catch (_) {}
  return cuenta;
}

/** Resumen para el cliente: [{canal, jugadores, cupo, lleno}, …] */
function resumenCanales() {
  const cuenta = ocupacionCanales();
  const lista = [];
  for (let c = 1; c <= CANALES_TOTAL; c++) {
    lista.push({ canal: c, jugadores: cuenta[c], cupo: CANAL_CUPO, lleno: cuenta[c] >= CANAL_CUPO });
  }
  return lista;
}

/**
 * Primer canal con hueco: el 1 si cabe, si no el 2, y así sucesivamente.
 * Si estuvieran los diez llenos devuelve null y quien llama decide qué hacer
 * (no se mete a nadie a la fuerza en un canal lleno).
 */
function primerCanalLibre() {
  const cuenta = ocupacionCanales();
  for (let c = 1; c <= CANALES_TOTAL; c++) {
    if (cuenta[c] < CANAL_CUPO) return c;
  }
  return null;
}

/** Nombre de sala con canal: 'game' + 3 -> 'game#c3'. */
function salaConCanal(sala, canal) {
  return `${sala}#c${canal}`;
}

/** Sala base sin el canal: 'game#c3' -> 'game'. Para las comprobaciones. */
function salaBase(sala) {
  return String(sala || '').split('#')[0];
}

/** playerNames conectados AHORA en un canal. Lo usa la clasificación. */
function jugadoresDelCanal(canal) {
  const nombres = new Set();
  try {
    for (const [, s] of io.of('/').sockets) {
      if (s.playerData && s.playerData.canal === canal && s.authenticatedPlayer) {
        nombres.add(s.authenticatedPlayer);
      }
    }
  } catch (_) {}
  return nombres;
}

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

    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
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
// Nombre de personaje Soulbound admitido. Se declara AQUÍ, antes del primer
// manejador de sockets, porque lo usan las dos partes: el joinRoom (más abajo)
// y las rutas /api/soulbound. El valor viaja al cliente y allí se usa para
// COMPONER UNA RUTA de sprites, así que sin este filtro un "../.." se saldría
// de la carpeta Soulbound.
const NOMBRE_SOULBOUND_VALIDO = /^[A-Za-z0-9_-]{1,40}$/;

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
    ip: clientIp,
    // Canal: se fija AQUÍ, al conectar, y ya no cambia salvo que el jugador lo
    // pida a mano. Ver el bloque de CANALES arriba para el porqué.
    canal: null
  };

  // ── ASIGNACIÓN DE CANAL (una sola vez por conexión) ──────────────────────
  socket.playerData.canal = primerCanalLibre() || CANALES_TOTAL;
  socket.emit('canalAsignado', {
    canal: socket.playerData.canal,
    total: CANALES_TOTAL,
    cupo:  CANAL_CUPO,
    canales: resumenCanales()
  });

  /** Estado de los 10 canales, para pintar el panel. */
  socket.on('canalesEstado', () => {
    socket.emit('canalesEstado', {
      canal: socket.playerData.canal,
      total: CANALES_TOTAL,
      cupo:  CANAL_CUPO,
      canales: resumenCanales()
    });
  });

  /**
   * Cambio de canal a petición del jugador.
   * Se le saca de la sala del canal viejo y se le mete en la del nuevo, para
   * que deje de ver —y de hablar con— a los del canal anterior al instante.
   */
  socket.on('canalCambiar', (data) => {
    try {
      const destino = Number(data && data.canal);
      if (!Number.isInteger(destino) || destino < 1 || destino > CANALES_TOTAL) {
        return socket.emit('canalError', { motivo: 'invalido' });
      }
      if (destino === socket.playerData.canal) {
        return socket.emit('canalCambiado', { canal: destino, canales: resumenCanales() });
      }
      const cuenta = ocupacionCanales();
      if (cuenta[destino] >= CANAL_CUPO) {
        return socket.emit('canalError', { motivo: 'lleno', canal: destino, canales: resumenCanales() });
      }

      // Salir de la sala actual (si estaba en alguna) avisando a los que quedan.
      const salaVieja = socket.playerData.room;
      const base = salaVieja ? salaBase(salaVieja) : null;
      if (salaVieja && rooms[salaVieja]) {
        delete rooms[salaVieja][socket.id];
        socket.leave(salaVieja);
        io.to(salaVieja).emit('playerLeft', { id: socket.id, reason: 'changed_channel' });
        io.to(salaVieja).emit('playerCount', Object.keys(rooms[salaVieja]).length);
      }

      socket.playerData.canal = destino;
      socket.playerData.room  = null;   // el cliente rehará el join en el canal nuevo

      socket.emit('canalCambiado', {
        canal: destino,
        salaBase: base,
        canales: resumenCanales()
      });
    } catch (_) {
      socket.emit('canalError', { motivo: 'error' });
    }
  });

  // ── SANEADO ANTI-INYECCIÓN EN EL CANAL DE SOCKETS ────────────────────────
  // El middleware que limpia las peticiones HTTP (ver sanearClavesMongo, arriba)
  // NO cubre Socket.IO: los mensajes del socket no pasan por Express. Y por aquí
  // entra buena parte del juego —sembrar, regar, cosechar, talar, chat,
  // batallas— con datos que acaban en consultas a la base de datos.
  //
  // Se aplica exactamente la misma regla: se eliminan las claves que empiecen
  // por '$' o que lleven un punto, que es lo que convierte un dato en un
  // operador de Mongo. Los valores no se tocan, así que ningún mensaje legítimo
  // cambia.
  socket.use((paquete, next) => {
    try {
      for (let i = 1; i < paquete.length; i++) {
        const arg = paquete[i];
        if (arg && typeof arg === 'object') sanearClavesMongo(arg, 0);
      }
    } catch (_) { /* nunca debe cortar el mensaje */ }
    next();
  });

  // Eventos de recolección de agua
  socket.on('collectWater', async (data) => {
    try {
      const { playerName } = data;
      // Misma laguna que en assertCropOwner: el `&&` dejaba pasar a cualquiera
      // que no hubiera emitido joinRoom, y también a los sockets anónimos.
      // Se reutiliza el guardián único (está declarado más abajo en este mismo
      // ámbito, así que el hoisting lo hace visible aquí).
      if (!assertCropOwner(playerName, 'collectWaterError')) return;
      const result = await waterCollectionController.collectWater(playerName);
      socket.emit('collectWaterSuccess', result);
    } catch (error) {
      socket.emit('collectWaterError', { error: error.message });
    }
  });

  socket.on('getWaterCollectionStatus', async (data) => {
    try {
      const { playerName } = data;
      // No tenía NINGUNA comprobación: se podía consultar el estado de
      // recolección de agua de cualquier jugador con solo poner su nombre.
      if (!assertCropOwner(playerName, 'waterStatusError')) return;
      const status = await waterCollectionController.getWaterCollectionStatus(playerName);
      socket.emit('waterCollectionStatus', status);
    } catch (error) {
      socket.emit('waterStatusError', { error: error.message });
    }
  });

  // Eventos de cultivos COMPLETOS
  socket.emit('cropConfig', cropController.getCropConfig());

  // Helper interno: verifica que el userId del evento coincide con el jugador autenticado
  /**
   * ¿El `userId` del mensaje es de quien lo manda?
   *
   * AGUJERO REPARADO (2026-08-11): la comprobación era
   *     if (socket.authenticatedPlayer && socket.authenticatedPlayer !== userId)
   * o sea que se SALTABA cuando `authenticatedPlayer` valía null. Y ese campo
   * arranca SIEMPRE en null (lo pone el middleware de io.use) y solo se rellena
   * dentro de joinRoom. Bastaba con conectar el socket y NO emitir joinRoom
   * para que todas estas comprobaciones devolvieran true: desde ahí se podía
   * sembrar, regar, cosechar y talar cultivos de CUALQUIER jugador pasando su
   * userId. Un socket anónimo (sin sesión) tenía exactamente el mismo poder.
   *
   * Ahora hay que DEMOSTRAR la identidad: sin sesión no se pasa, y el userId
   * tiene que coincidir con la dirección del token o con el nombre de jugador
   * ya verificado en joinRoom. El cliente manda `userId: this.currentAccount`,
   * que es la dirección de la cartera, así que la comparación natural es con
   * `authenticatedAddress`.
   */
  function assertCropOwner(userId, emitEvent, plotId = null) {
    const fallar = (motivo) => {
      const payload = { error: 'No autorizado: ' + motivo };
      if (plotId !== null) payload.plotId = plotId;
      socket.emit(emitEvent, payload);
      console.warn(`🚫 Socket ${socket.id} rechazado en '${emitEvent}': ${motivo} (userId=${userId})`);
      return false;
    };

    if (!userId) return fallar('falta el userId');

    // 1) Sin sesión válida no se toca nada.
    if (!socket.authenticatedAddress) return fallar('socket sin sesión');

    const pedido = String(userId).toLowerCase();

    // 2) Coincide con la dirección del token (el caso normal).
    if (pedido === String(socket.authenticatedAddress).toLowerCase()) return true;

    // 3) O con el nombre de jugador que joinRoom ya verificó contra la BD.
    if (socket.authenticatedPlayer &&
        pedido === String(socket.authenticatedPlayer).toLowerCase()) return true;

    return fallar('el userId no pertenece a este socket');
  }

  // Consulta previa (sin efectos secundarios) para que el cliente sepa si
  // está bloqueado ANTES de gastar una transacción de blockchain.
  socket.on('checkPlantLock', (data) => {
    const { userId } = data || {};
    if (!assertCropOwner(userId, 'plantLockStatus')) return;
    const estado = isPlantLocked(userId);
    socket.emit('plantLockStatus', estado);
  });

  // ── COMPROBACIÓN PREVIA DE SIEMBRA                        (2026-08-05) ──
  // El cliente QUEMA la semilla en la cadena antes de mandar 'plantSeed'. Si el
  // servidor la rechazaba después (bloqueo antispam, cuadro ocupado, nivel
  // insuficiente…), la semilla ya no existía y no se sembraba nada: el jugador
  // la perdía. Esto le deja preguntar ANTES, sin efectos secundarios, para que
  // no llegue a quemarla si de todos modos se le va a decir que no.
  //
  // Ojo: usa isPlantLocked, que solo LEE. checkAndTrackPlantSpam sí registra el
  // intento, así que llamarlo aquí penalizaría al jugador por preguntar.
  socket.on('plantCheck', async (data, ack) => {
    const responder = (r) => { if (typeof ack === 'function') ack(r); };
    try {
      const { userId, plotId } = data || {};
      if (!assertCropOwner(userId, 'plantError', plotId)) {
        return responder({ ok: false, error: 'not_your_plot' });
      }

      const bloqueo = isPlantLocked(userId);
      if (bloqueo.locked) {
        const min = Math.ceil(bloqueo.secondsRemaining / 60);
        return responder({
          ok: false,
          error: `Planting is temporarily locked. Try again in ${min} minute(s).`
        });
      }

      return responder({ ok: true });
    } catch (e) {
      // Ante la duda se deja pasar: esto es una ayuda, no la validación real
      // (la de verdad sigue estando en 'plantSeed').
      return responder({ ok: true });
    }
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
    const { room: salaPedida, username, lastScene, nivel, petLevel, dogName, soulbound } = data;

    if (!salaPedida || !username) {
      socket.emit("error", { message: "Datos de sala inválidos" });
      return;
    }

    // EL CANAL SE AÑADE AQUÍ, EN EL SERVIDOR, NO LO ELIGE EL CLIENTE.
    // El cliente sigue pidiendo 'game' o 'tienda' como toda la vida; el
    // servidor lo convierte en 'game#c3' según el canal que le asignó al
    // conectar. De este modo:
    //   · el chat y el movimiento (que ya usaban io.to(room)) quedan separados
    //     por canal sin tocar una línea de esa lógica;
    //   · un cliente manipulado no puede colarse en el canal que le apetezca,
    //     porque el número no viaja en el mensaje.
    // A partir de aquí `room` es la sala completa, con canal, y el resto del
    // manejador funciona exactamente igual que antes.
    const canal = socket.playerData.canal || 1;
    const room  = salaConCanal(salaBase(salaPedida), canal);

    console.log(`🔵 joinRoom: ${socket.id} -> ${room}, último escena: ${lastScene}`);

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
      // Identidad REAL del socket (no la que diga el cliente): la usa el
      // submenú de jugador (perfil / verificador / reporte) para saber a quién
      // se está señalando sin que nadie pueda suplantar a otro.
      address:    socket.authenticatedAddress || null,
      playerName: socket.authenticatedPlayer  || null,
      direction: 'right',
      directionx: 'stop_right',
      // Nivel del personaje y de la mascota ya desde el JOIN.
      // Antes solo viajaban dentro de playerMove, así que un jugador que
      // entraba y se quedaba QUIETO nunca emitía nada y los demás lo veían sin
      // nivel hasta que se dignara a moverse.
      nivel:    Number.isFinite(Number(nivel))    ? Number(nivel)    : 0,
      petLevel: Number.isFinite(Number(petLevel)) ? Number(petLevel) : 1,
      dogName:  typeof dogName === 'string' ? dogName : '',
      // Personaje Soulbound de ESTE jugador. Viaja en el join para que los
      // demás lo vean con su aspecto correcto desde el primer momento, incluso
      // si se queda quieto y nunca llega a emitir un playerMove.
      // Se valida aquí porque el cliente lo usa para COMPONER UNA RUTA de
      // sprites: sin filtro, un "../.." se saldría de la carpeta Soulbound.
      soulbound: NOMBRE_SOULBOUND_VALIDO.test(String(soulbound || '')) ? String(soulbound) : null,
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
    const room = socket.playerData && socket.playerData.room;
    /* Igual que en el chat: si el socket se movió pero el servidor no le conoce
       sala, es que hay que rehacer el join. Con un freno para no soltar un
       aviso por cada paquete de movimiento (llegan varios por segundo). */
    if (!room || !rooms[room] || !rooms[room][socket.id]) {
      const ahora = Date.now();
      if (ahora - (socket._avisoRejoin || 0) > 3000) {
        socket._avisoRejoin = ahora;
        socket.emit('rejoinRequired', { motivo: 'sin_sala' });
      }
      return;
    }
    
    rooms[room][socket.id] = {
      ...rooms[room][socket.id],
      ...data,
      isMoving: data.isMoving || false,
      // La identidad NO se toma de `data`: si no, cualquiera podría mandar
      // otra address/playerName en playerMove y suplantar a otro jugador en el
      // submenú de perfil/reporte.
      id:         socket.id,
      address:    socket.authenticatedAddress || rooms[room][socket.id].address || null,
      playerName: socket.authenticatedPlayer  || rooms[room][socket.id].playerName || null,
      lastUpdate: Date.now()
    };

    socket.to(room).emit("playerMoved", rooms[room][socket.id]);
  });

  // Cambio de personaje Soulbound en caliente.
  //
  // playerMove ya arrastra el campo `soulbound` del registro de la sala, así
  // que un jugador que se mueve propaga su cambio solo. Este evento cubre el
  // caso que se quedaría colgado: cambiar de personaje QUIETO — los demás lo
  // seguirían viendo con el anterior hasta que diera un paso.
  socket.on('cambioSoulbound', (data) => {
    try {
      const room = socket.playerData && socket.playerData.room;
      if (!room || !rooms[room] || !rooms[room][socket.id]) return;
      const id = String((data && data.soulbound) || '');
      if (!NOMBRE_SOULBOUND_VALIDO.test(id)) return;
      rooms[room][socket.id].soulbound = id;
      socket.to(room).emit('cambioSoulbound', { id: socket.id, soulbound: id });
    } catch (_) {}
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
      const room = socket.playerData && socket.playerData.room;
      /* FUERA DE LA SALA = SE LE DICE, NO SE TIRA EL MENSAJE EN SILENCIO.

         FALLO QUE ESTO ARREGLA — "intento hablar, dice que no encuentra el
         servidor y ya no se recupera": tras una reconexión el socket es NUEVO y
         el servidor no le conoce ninguna sala hasta que el cliente vuelve a
         hacer joinRoom. Si el cliente no lo hacía (porque la escena estaba
         pausada, o porque `window.activeScene` estaba a null en ese momento),
         el socket se quedaba conectado pero MUDO: los mensajes se descartaban
         aquí sin decir nada y los demás jugadores no se veían.

         Ahora se le contesta `rejoinRequired`; el cliente rehace el join y
         vuelve a la sala solo. */
      if (!room) {
        socket.emit('rejoinRequired', { motivo: 'sin_sala' });
        socket.emit('chatError', { msg: 'Reconnecting to the room… try again in a second.' });
        return;
      }
      
      const now = Date.now();
      if (now - (socket.chatLastSent || 0) < 1000) {
        socket.emit('chatError', { msg: 'Demasiados mensajes. Espera un momento.' });
        return;
      }
      socket.chatLastSent = now;

      // SUPLANTACIÓN REPARADA (2026-08-11): el nombre que se mostraba salía de
      // `payload.usernamex`, o sea del propio mensaje. Cualquiera podía mandar
      // el nombre de otro jugador y hablar por él en el chat público. El nombre
      // ahora sale de `socket.playerData`, que lo rellenó joinRoom tras
      // verificarlo contra la base de datos; el del cuerpo se ignora.
      const playerName = escapeHtml(socket.playerData.username || '---');

      // RECORTE SEGURO PARA EMOJIS (2026-08-05): un emoji ocupa dos unidades
      // UTF-16 (a veces más, si lleva modificadores). Con .slice(0, 500) a
      // secas, un mensaje justo en el límite se cortaba por la mitad de un
      // emoji y llegaba un carácter roto. Recortando por PUNTOS DE CÓDIGO
      // ([...cadena]) el emoji entra entero o no entra.
      const crudo = String(payload.text || '').trim();
      const recortado = [...crudo].slice(0, 300).join('');
      const text = escapeHtml(recortado);
      if (!text) return;

      const message = {
        id: socket.id,
        playerName,
        text,
        ts: new Date().toISOString(),
        room: room
      };

      const historial = historialDe(room);
      historial.push(message);
      if (historial.length > MAX_HISTORY) historial.shift();

      io.to(room).emit('chatMessage', message);
    } catch (e) {
      console.error('chatMessage error:', e);
    }
  });

  socket.on('requestHistory', () => {
    try {
      /* El historial es el de SU sala. Si todavía no ha entrado en ninguna
         —pasa justo después de una reconexión— se le dice que rehaga el join
         en vez de mandarle una lista vacía sin explicación. */
      const room = socket.playerData && socket.playerData.room;
      if (!room) { socket.emit('rejoinRequired', { motivo: 'sin_sala' }); return; }
      socket.emit('chatHistory', historialDe(room).slice(-MAX_HISTORY));
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
      connectSrc: ["'self'", "http://localhost:*", "http://127.0.0.1:*", "ws://localhost:*", "ws://127.0.0.1:*", "https://*.grasslandforest.com", "wss://*.grasslandforest.com"],
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

// =============================================================================
// SANEADO ANTI-INYECCIÓN DE MONGO
// -----------------------------------------------------------------------------
// VULNERABILIDAD QUE ESTO CIERRA (clase entera, no un caso concreto):
//
// express.json() acepta CUALQUIER JSON, así que un campo que el código espera
// como texto puede llegar como objeto. Si ese valor termina dentro de un filtro
// de Mongo, el atacante deja de mandar un dato y pasa a mandar un OPERADOR:
//
//     { "playerName": { "$ne": null } }   → "cualquier jugador"
//     { "address":    { "$gt": "" } }     → coincide con todos
//     { "nonce":      { "$regex": "^a" } } → adivinar valores letra a letra
//
// Con eso se pueden saltar comprobaciones de propiedad, leer datos ajenos o
// hacer un ataque de fuerza bruta sobre un nonce. El servidor no traía ninguna
// defensa general contra esto (no hay express-mongo-sanitize instalado) y sí
// tiene decenas de consultas construidas a partir del cuerpo de la petición.
//
// Este middleware quita, de forma recursiva, cualquier clave que empiece por
// '$' (operadores) o que contenga un punto (rutas anidadas, usadas para escribir
// campos que no tocan). Los VALORES no se tocan: un texto sigue llegando tal
// cual, así que nada del juego cambia — ninguna petición legítima del cliente
// usa claves con '$' o '.'.
//
// El límite de profundidad evita que un JSON muy anidado consuma CPU aquí.
function sanearClavesMongo(obj, profundidad) {
  if (!obj || typeof obj !== 'object' || profundidad > 8) return 0;
  let quitadas = 0;

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) quitadas += sanearClavesMongo(obj[i], profundidad + 1);
    return quitadas;
  }

  for (const clave of Object.keys(obj)) {
    if (clave.charCodeAt(0) === 36 /* $ */ || clave.indexOf('.') !== -1) {
      delete obj[clave];
      quitadas++;
      continue;
    }
    quitadas += sanearClavesMongo(obj[clave], profundidad + 1);
  }
  return quitadas;
}

app.use((req, res, next) => {
  try {
    let quitadas = 0;
    // req.query y req.params son de solo lectura en Express 5; se sanean in situ
    // solo si se puede. El cuerpo es el vector que de verdad importa.
    quitadas += sanearClavesMongo(req.body, 0);
    quitadas += sanearClavesMongo(req.query, 0);

    if (quitadas > 0) {
      console.warn(`🛡️  Petición saneada: ${quitadas} clave(s) con '$' o '.' eliminadas — ${req.method} ${req.path} desde ${req.ip}`);
    }
  } catch (_) { /* nunca debe tumbar la petición */ }
  next();
});

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
// FIX: '*' como string ya no es válido en Express 5 / path-to-regexp 8+ (tira
// "PathError: Missing parameter name at index 1: *" y el servidor no arranca).
// Con una RegExp real (/.*/), evitamos el parser de rutas de string y funciona
// igual en Express 4 y 5, sin depender de qué versión resuelva tu npm install.
app.options(/.*/, cors(corsOptions));

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

// --- FUNCIONES DE COOKIES ---
// FIX: la versión anterior forzaba domain:'127.0.0.1' en cualquier entorno que
// NO fuera exactamente NODE_ENV==='production'. Si el proceso arranca en un
// host real sin NODE_ENV=production seteada explícitamente, cae en la rama de
// "desarrollo" y el navegador recibe un Set-Cookie con Domain=127.0.0.1 desde
// un host que NO es 127.0.0.1 → lo descarta silenciosamente (no es un error
// visible, la cookie simplemente nunca se guarda). El login parece exitoso
// porque igual puedes leer el JSON de respuesta, pero la sesión nunca queda
// guardada, y /api/auth/me falla siempre con "Authentication required".
function setCookieOptions(maxAgeSeconds, csrf = false) {
  const isProd = NODE_ENV === 'production';
  const sameSite = COOKIE_SAMESITE === 'none' ? 'None'
                  : COOKIE_SAMESITE === 'strict' ? 'Strict'
                  : 'Lax';

  const opts = {
    httpOnly: !csrf,
    secure: isProd,
    sameSite,
    maxAge: (maxAgeSeconds || 0) * 1000,
    path: '/',
  };

  // 'SameSite=None' exige 'Secure' obligatoriamente o el navegador la descarta.
  if (opts.sameSite === 'None') {
    opts.secure = true;
  }

  if (isProd) {
    // Solo fija Domain si te lo dieron explícitamente por env var. Si el
    // login, el juego y la API viven en subdominios de grasslandforest.com,
    // pon COOKIE_DOMAIN=.grasslandforest.com para que la misma cookie de
    // sesión sea válida en todos ellos (incluyendo game.grasslandforest.com).
    if (COOKIE_DOMAIN) {
      opts.domain = COOKIE_DOMAIN;
    }
  } else {
    // Solo en desarrollo LOCAL real usamos 127.0.0.1 explícito.
    opts.domain = '127.0.0.1';
    opts.secure = false;
    opts.sameSite = 'Lax';
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

  // 🍪 LOG DE DIAGNÓSTICO — esto es lo que necesitas mirar en los logs de Railway.
  // Muestra exactamente qué le llegó al servidor en esta petición: si el
  // Cookie header viene vacío, el navegador NUNCA mandó la cookie (bloqueo del
  // navegador / SameSite / third-party); si viene pero sin "session=", algo la
  // está limpiando antes; si viene con "session=" pero igual falla más abajo,
  // ya es un problema de verificación del JWT, no de transporte de la cookie.
  console.log('🍪 [authMiddleware] Cookie header crudo:', req.headers.cookie || '(vacío — el navegador no mandó ninguna cookie)');
  console.log('🍪 [authMiddleware] req.cookies parseadas:', req.cookies);
  console.log('🍪 [authMiddleware] Origin:', req.headers.origin || '(sin Origin)', '| Referer:', req.headers.referer || '(sin Referer)');
  
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
      console.log('❌ No se encontró token de autenticación (ni cookie "session" ni header Authorization)');
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
      const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
      
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
      // GATE: whitelist/baneos también para sesiones YA iniciadas (si no, quien
      // entra directo al juego con la cookie guardada se salta el control).
      return enforceGameAccess(req, res, next);

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

// ═══════════════════════════════════════════════════════════════════════════
// RELOJ DEL MUNDO — ciclo día/noche
//
// El reloj vive AQUÍ, no en el cliente. El navegador solo pregunta la hora una
// vez cada media hora y entremedias la extrapola con un cronómetro monótono
// (performance.now), no con Date.now(): cambiar la hora del sistema operativo
// no adelanta ni retrasa el ciclo, y tocar variables de JS solo desincroniza
// el HUD de ese jugador hasta la siguiente sincronización.
//
// DURACIÓN: 6 h reales de día + 6 h reales de noche = ciclo de 12 h.
// Ese ciclo se muestra como un día de 24 h en el reloj del HUD, o sea
// 1 hora de juego = 30 minutos reales. Amanece a las 06:00 y anochece a las
// 18:00 del reloj del juego.
//
// Para cambiar la duración solo se tocan estas dos constantes.
const CICLO_DIA_MS   = 6 * 60 * 60 * 1000;
const CICLO_NOCHE_MS = 3 * 60 * 60 * 1000;   // la noche dura la mitad que el dia

const CICLO_TOTAL_MS = CICLO_DIA_MS + CICLO_NOCHE_MS;

// Origen fijo del ciclo. Es una fecha constante a propósito: si se usara la
// hora de arranque del servidor, cada reinicio movería el amanecer y dos
// instancias detrás de un balanceador irían desincronizadas.
const CICLO_EPOCA_MS = Date.UTC(2024, 0, 1, 0, 0, 0);

function estadoDelMundo(ahoraMs) {
  let t = (ahoraMs - CICLO_EPOCA_MS) % CICLO_TOTAL_MS;
  if (t < 0) t += CICLO_TOTAL_MS;

  const esDia = t < CICLO_DIA_MS;
  const msParaCambio = esDia ? (CICLO_DIA_MS - t) : (CICLO_TOTAL_MS - t);

  // El día se reparte sobre 06:00→18:00 y la noche sobre 18:00→06:00. Se
  // calcula por fase, no sobre el ciclo entero, para que siga cuadrando si
  // algún día el día y la noche dejan de durar lo mismo.
  let minutos;
  if (esDia) {
    minutos = 360 + (t / CICLO_DIA_MS) * 720;
  } else {
    minutos = (1080 + ((t - CICLO_DIA_MS) / CICLO_NOCHE_MS) * 720) % 1440;
  }
  minutos = Math.floor(minutos) % 1440;
  const hora = Math.floor(minutos / 60);
  const minuto = minutos % 60;

  return {
    ok: true,
    ahora: ahoraMs,
    epocaMs: CICLO_EPOCA_MS,
    fase: esDia ? 'dia' : 'noche',
    esDia,
    hora,
    minuto,
    horaTexto: String(hora).padStart(2, '0') + ':' + String(minuto).padStart(2, '0'),
    progresoCiclo: t / CICLO_TOTAL_MS,
    msParaCambio,
    cicloMs: CICLO_TOTAL_MS,
    diaMs: CICLO_DIA_MS,
    nocheMs: CICLO_NOCHE_MS
  };
}

// Pública a propósito: es la misma hora para todo el mundo y no depende de la
// sesión, así que el HUD puede pintarla antes incluso de que el jugador entre.
app.get('/api/world/time', apiLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  return res.json(estadoDelMundo(Date.now()));
});

// CSRF token endpoint
app.get('/api/auth/csrf-token', (req, res) => {
  // REUTILIZAR el token existente si la cookie ya tiene uno válido (64 hex).
  // Antes se generaba SIEMPRE uno nuevo en cada GET, rotando la cookie y
  // desincronizándola del header X-CSRF-Token que el cliente ya tenía → error
  // 'csrf_token_invalid' intermitente ("se desconecta el CSRF"). Un token CSRF
  // estable por sesión es válido y más fiable para el patrón double-submit.
  // (login/refresh SÍ siguen rotándolo a propósito, en el cambio de sesión.)
  const existing = req.cookies && req.cookies['csrf-token'];
  const isValid = typeof existing === 'string' && /^[a-f0-9]{64}$/i.test(existing);
  const csrfToken = isValid ? existing : generateCSRFToken();
  if (!isValid) {
    res.cookie('csrf-token', csrfToken, setCookieOptions(3600, true));
  }
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
    console.log('🍪 [login] Origin:', req.headers.origin || '(sin Origin)', '| Cookie header entrante:', req.headers.cookie || '(vacío)');
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

    // El timestamp del token lo genera el NAVEGADOR, así que no sirve como
    // control de frescura: si el reloj del usuario va atrasado o adelantado
    // (desfases de varios minutos son habituales en Windows), este check
    // rechazaba logins perfectamente válidos con "token_expired" justo
    // después de firmar, y el usuario no tenía forma de arreglarlo desde la
    // web. La frescura REAL ya la garantiza el nonce con el reloj del
    // SERVIDOR: es de un solo uso, lo fechamos nosotros en nonceTimestamp y
    // unas líneas más arriba se rechaza si tiene más de 10 minutos. Aquí
    // sólo validamos que el timestamp sea un valor plausible en SEGUNDOS
    // (descarta milisegundos o basura), tolerando el desfase del cliente.
    const now = Math.floor(Date.now() / 1000);
    const MAX_CLOCK_SKEW = parseInt(process.env.AUTH_MAX_CLOCK_SKEW || '86400', 10); // 24 h
    
    if (!Number.isFinite(ts) || ts <= 0 || Math.abs(now - ts) > MAX_CLOCK_SKEW) {
      console.log(`⏰ Timestamp del token fuera de rango (timestamp: ${ts}, ahora: ${now}, desfase: ${now - ts}s)`);
      return res.status(401).json({ 
        error: 'invalid_token_timestamp',
        message: 'Timestamp del token inválido'
      });
    }
    
    if (Math.abs(now - ts) > 60 * 5) {
      console.log(`⚠️  Reloj del cliente desfasado ${now - ts}s respecto al servidor (login permitido: la frescura la controla el nonce)`);
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

    // ── CONTROL DE ACCESO (whitelist / baneos) ──────────────────────────────
    // Tras verificar la firma, comprobar si esta wallet puede entrar. Los
    // admins pasan siempre. Baneado → 403 banned + reason + date. Sin WL (modo
    // whitelist) → 403 not_whitelisted. El login del juego muestra el mensaje.
    try {
      const access = await checkGameAccess(lcAddress);
      if (!access.allowed) {
        if (access.error === 'banned') {
          console.log(`⛔ Login bloqueado (baneado): ${lcAddress.substring(0, 10)}…`);
          return res.status(403).json({ error: 'banned', reason: access.reason || '', date: access.date || null });
        }
        if (access.error === 'suspended') {
          console.log(`⛔ Login bloqueado (suspendido): ${lcAddress.substring(0, 10)}…`);
          return res.status(403).json({
            error: 'suspended',
            reason: access.reason || '',
            until: access.date || null,
            date: access.date || null
          });
        }
        console.log(`⛔ Login bloqueado (sin whitelist): ${lcAddress.substring(0, 10)}…`);
        return res.status(403).json({ error: 'not_whitelisted' });
      }
    } catch (accErr) {
      console.warn('⚠️  checkGameAccess falló (se permite el login por defecto):', accErr.message);
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

    console.log('🍪 [login] Seteando cookie "session" con opts:', accessCookieOpts);

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
// LÍMITE DE PETICIONES QUE FALTABA: esta ruta era la ÚNICA del bloque de
// autenticación sin limitador. Verifica un JWT y consulta la base de datos en
// cada llamada, así que sin freno servía tanto para tumbar el servidor a base
// de peticiones como para probar tokens de refresco a ciegas. `apiLimiter` la
// deja en 200 por minuto y por IP, de sobra para el uso real (una renovación
// cada 4,5 minutos por jugador).
app.post('/api/auth/refresh', apiLimiter, async (req, res) => {
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
      payload = jwt.verify(raw, JWT_SECRET, { algorithms: ['HS256'] });
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
        const payload = jwt.verify(raw, JWT_SECRET, { algorithms: ['HS256'] });
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

    // ── NOMBRE ÚNICO, SIN DISTINGUIR MAYÚSCULAS ──────────────────────────
    // La comprobación anterior era una igualdad exacta, o sea SENSIBLE a
    // mayúsculas: "Pepe", "pepe" y "PEPE" se consideraban tres nombres
    // distintos y los tres podían coexistir. Eso es el vector clásico de
    // suplantación — en el chat y en la clasificación nadie distingue a
    // "Kuro" de "kuro".
    //
    // Ahora se compara con una expresión regular anclada e insensible a
    // mayúsculas. Se escapan los metacaracteres del nombre: sin eso, un nombre
    // con '(' o '*' rompería la consulta, y uno construido a mala idea podría
    // colgar el servidor con un patrón catastrófico.
    const nombreEscapado = String(playerName).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const mismoNombre = { $regex: '^' + nombreEscapado + '$', $options: 'i' };

    const [existingAuth, existingGamePlayer] = await Promise.all([
      PlayerAuth.findOne({ playerName: mismoNombre, address: { $ne: address } }).lean(),
      GamePlayer.findOne({ playerName: mismoNombre, address: { $ne: address } }).lean()
    ]);

    // Mensajes en inglés, como el resto de la interfaz del juego. `code` va
    // aparte para que el cliente pueda reaccionar sin depender del texto.
    if (existingAuth || existingGamePlayer) {
      return res.status(409).json({
        error: 'name_taken',
        code:  'NAME_TAKEN',
        message: 'That name is already taken. Please choose a different one.'
      });
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

// RESPAWN (ajuste 2026-08-03): antes cada árbol quedaba 300 s (5 min) bloqueado
// y, si la deforestación global llegaba al 100 %, se bloqueaba hasta el año
// 3000 — literalmente siglos. Ahora el respawn base es de 60 s y el 100 % de
// deforestación solo aplica una penalización TEMPORAL (RESPAWN_MAX_SECONDS),
// nunca un bloqueo permanente.
const TREE_TYPE_CONFIG = {
  pinos:     { baseRespawn: 60, respawnMultiplier: 0 },   // 60 segundos = 1 minuto
  arbustos:  { baseRespawn: 60, respawnMultiplier: 0 },
  arbolx:    { baseRespawn: 60, respawnMultiplier: 0 }
};

// Tope duro del respawn (en segundos). Ningún nodo — árbol o mineral — puede
// quedar bloqueado más que esto, pase lo que pase con los porcentajes globales.
const RESPAWN_MAX_SECONDS = 300; // 5 minutos como máximo absoluto

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

      // Deforestación al 100 % ya NO bloquea el árbol para siempre: solo lo
      // penaliza con el respawn máximo. Un bloqueo permanente dejaba el mapa
      // muerto y era lo que el jugador veía como "siglos de respawn".
      let respawnSeconds = config.baseRespawn + (percent * config.respawnMultiplier);
      if (percent >= 100) respawnSeconds = RESPAWN_MAX_SECONDS;
      respawnSeconds = Math.min(RESPAWN_MAX_SECONDS, Math.max(5, respawnSeconds));
      const lockedUntil = new Date(Date.now() + respawnSeconds * 1000);

      await TreeLock.findOneAndUpdate(
        { treeKey },
        { treeType, lockedUntil },
        { upsert: true }
      );

      // Avisar a TODOS los jugadores conectados de que ese árbol acaba de
      // caer. Antes solo se guardaba en Mongo, y el estado del mapa únicamente
      // se leía al entrar a la escena (loadTreeLockStates), así que los demás
      // jugadores seguían viendo el árbol entero durante todo el respawn y solo
      // veían el tronco si recargaban la página.
      try {
        io.emit('treeLocked', { treeKey, treeType, lockedUntil });
      } catch (_) {}

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
  piedra: { baseRespawn: 60, respawnMultiplier: 0 },   // 60s = 1 min (ver RESPAWN_MAX_SECONDS)
  cobre:  { baseRespawn: 60, respawnMultiplier: 0 },
  hierro: { baseRespawn: 60, respawnMultiplier: 0 },
  carbon: { baseRespawn: 60, respawnMultiplier: 0 }
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
 
      // Igual que con los árboles: el agotamiento al 100 % penaliza con el
      // respawn máximo, nunca con un bloqueo permanente.
      let respawnSeconds = config.baseRespawn + (percent * config.respawnMultiplier);
      if (percent >= 100) respawnSeconds = RESPAWN_MAX_SECONDS;
      respawnSeconds = Math.min(RESPAWN_MAX_SECONDS, Math.max(5, respawnSeconds));
      const lockedUntil = new Date(Date.now() + respawnSeconds * 1000);

      await MineLock.findOneAndUpdate(
        { mineKey },
        { mineralType, lockedUntil },
        { upsert: true, new: true }
      );

      // Mismo caso que los árboles: los demás jugadores tienen que ver el
      // mineral picado en el momento, no solo si recargan la página.
      try {
        io.emit('mineLocked', { mineKey, mineralType, lockedUntil });
      } catch (_) {}

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

// =============================================================================
// RECOLECCIÓN SERVER-AUTHORITATIVE (anti-trampa de talar/minar)
// -----------------------------------------------------------------------------
// Problema: hoy el CLIENTE decide la recompensa y pide al relay que la acuñe →
// un tramposo podría acuñar madera/minerales sin trabajar. Solución: que el
// SERVIDOR valide el nodo (árbol/mineral), aplique el bloqueo (respawn = tope
// económico), DECIDA la recompensa y la ACUÑE él mismo. El relay, además,
// rechaza que el cliente acuñe directamente los "tipos de recolección".
//
// SEGURIDAD DE DESPLIEGUE: todo esto está detrás del flag `GATHER_ENFORCE`
// (env, apagado por defecto). Mientras esté apagado, NADA cambia (el endpoint
// existe pero el relay no bloquea, así que el juego sigue como está). Actívalo
// (`GATHER_ENFORCE=true`) SOLO tras cablear el cliente para que llame a
// /api/gather/claim en vez de acuñar, y probarlo en staging.
// =============================================================================
const GATHER_ENFORCE = String(process.env.GATHER_ENFORCE || '').toLowerCase() === 'true';

// nodeKey (sprite) → tipo de nodo, y tipo de nodo → item que suelta.
function gatherNodeTypeFromKey(key) {
  const k = String(key || '');
  if (k.startsWith('sprite_pinos'))    return { kind: 'tree', type: 'pinos' };
  if (k.startsWith('sprite_arbustos')) return { kind: 'tree', type: 'arbustos' };
  if (k.startsWith('sprite_arbolx'))   return { kind: 'tree', type: 'arbolx' };
  if (k.includes('minar_piedra'))      return { kind: 'mine', type: 'piedra' };
  if (k.includes('minar_cobre'))       return { kind: 'mine', type: 'cobre' };
  if (k.includes('minar_hierro'))      return { kind: 'mine', type: 'hierro' };
  if (k.includes('carbon'))            return { kind: 'mine', type: 'carbon' };
  return null;
}
// OJO CON LOS NOMBRES: el `tipo` tiene que ser EXACTAMENTE el de
// ItemDefinitions en el cliente. Las maderas llevan ESPACIOS ("madera pinos"),
// no guion bajo; aquí estaban con guion bajo, así que el modo servidor habría
// acuñado a una tabla distinta de la que usa el inventario del jugador.
const GATHER_REWARD_TIPO = {
  pinos: 'madera pinos', arbolx: 'madera seca', arbustos: 'madera con hojas',
  piedra: 'mineral_piedra', cobre: 'mineral_cobre', hierro: 'mineral_hierro', carbon: 'carbon'
};
// Conjunto de tipos que SOLO el servidor puede acuñar (recolección).
const GATHER_TIPOS = new Set(Object.values(GATHER_REWARD_TIPO));

// El servidor decide la recompensa (misma idea que el cliente, pero autoritativa):
// herramienta baja (madera) → menos probabilidad; alta → +cantidad. Puede dar 0.
// BOTÍN 1-3 POR SUERTE (2026-08-03): talar un árbol o picar un mineral entrega
// entre 1 y 3 unidades. La herramienta inclina la suerte (mejor herramienta =
// más probabilidad de 2 o 3), pero el rango sigue siendo 1..3 en todos los
// casos. Debe coincidir con rollGatherAmount() del cliente (GameScene.js).
function rollGatherAmount(toolId) {
  const t = String(toolId || '').toLowerCase();
  // [prob de 1, prob de 2, prob de 3]
  let pesos = [0.70, 0.25, 0.05];              // sin herramienta reconocida
  if (t.includes('_madera'))      pesos = [0.70, 0.25, 0.05];
  else if (t.includes('_piedra')) pesos = [0.55, 0.33, 0.12];
  else if (t.includes('_cobre'))  pesos = [0.42, 0.38, 0.20];
  else if (t.includes('_hierro')) pesos = [0.30, 0.40, 0.30];

  const r = Math.random();
  if (r < pesos[0]) return 1;
  if (r < pesos[0] + pesos[1]) return 2;
  return 3;
}

function decideGatherReward(nodeType, toolId) {
  const tipo = GATHER_REWARD_TIPO[nodeType];
  if (!tipo) return { tipo: null, quantity: 0 };
  const t = String(toolId || '').toLowerCase();
  // La herramienta de madera todavía puede fallar del todo; las demás siempre
  // dan algo. Cuando da, la cantidad es 1-3 según la suerte.
  const prob = t.includes('_madera') ? 0.6 : 1.0;
  if (Math.random() > prob) return { tipo, quantity: 0 }; // falló (herramienta baja)
  return { tipo, quantity: rollGatherAmount(toolId) };
}

function gatherGasPrice() {
  // Precio de gas fijo si está configurado; si no, un mínimo seguro.
  if (FIXED_GAS_PRICE_GWEI !== null) return ethers.parseUnits(String(FIXED_GAS_PRICE_GWEI), 'gwei');
  return ethers.parseUnits(String(MIN_GAS_PRICE_GWEI), 'gwei');
}

// Acuña `quantity` de `tipo` para `address`: si el jugador ya tiene una factura
// activa de ese tipo con cupo, la aumenta; si no, crea una nueva. Devuelve
// { id, manualId, cantidad } o null.
async function mintGatherReward(address, tipo, quantity) {
  if (!relayerWallet || quantity <= 0) return null;
  const c = new ethers.Contract(CONTRACTS.ITEMS_CONTRACT.address, CONTRACTS.ITEMS_CONTRACT.abi, relayerWallet);
  const gasPrice = gatherGasPrice();

  // Misma red de seguridad que en el relay: si la tabla del tipo no existe o se
  // quedó sin cupo, prepararla antes de acuñar (ver ensureItemTipoOnChain).
  await ensureItemTipoOnChain(c, tipo, quantity);

  // Límite por factura del tipo (para saber si podemos aumentar una existente).
  let perInvoiceLimit = 50;
  try {
    const ts = await c.getTipoStats(tipo);
    const pil = Number(ts.perInvoiceLimit ?? ts[2] ?? 0);
    if (pil > 0) perInvoiceLimit = pil;
  } catch (_) {}

  // Buscar una factura activa del tipo con cupo.
  let target = null;
  try {
    const snap = await c.getUserInventorySnapshot(address);
    for (const inv of snap) {
      if (inv.active && String(inv.tipo) === tipo && Number(inv.cantidad) + quantity <= perInvoiceLimit) {
        target = { id: Number(inv.id), manualId: inv.manualId, cantidad: Number(inv.cantidad) };
        break;
      }
    }
  } catch (e) { console.warn('⚠️ gather: no se pudo leer inventario on-chain:', e.message); }

  const nonce = await relayerNonceManager.getNextNonce();
  try {
    if (target) {
      const tx = await c.increaseInvoiceQuantity(target.id, quantity, { gasPrice, nonce });
      await tx.wait();
      return { id: target.id, manualId: target.manualId, cantidad: target.cantidad + quantity };
    } else {
      const manualId = ('g' + tipo.replace(/[^a-z0-9]/gi, '').slice(0, 10) + Date.now().toString(36) + Math.random().toString(36).slice(2, 6)).slice(0, 60);
      const tx = await c.createInvoice(address, tipo, quantity, manualId, { gasPrice, nonce });
      const receipt = await tx.wait();
      let newId = null;
      try {
        for (const log of receipt.logs) {
          const p = c.interface.parseLog(log);
          if (p?.name === 'InvoiceCreated') { newId = Number(p.args.id); break; }
        }
      } catch (_) {}
      return { id: newId, manualId, cantidad: quantity };
    }
  } catch (e) {
    // Ante nonce desincronizado, resetear (mismo criterio que el relay).
    console.error('❌ gather mint error:', e.message);
    try { await relayerNonceManager.resetNonce(); } catch (_) {}
    return null;
  }
}

// Cooldown en memoria por jugador (evita spam del endpoint). El tope económico
// REAL es el bloqueo por respawn del nodo.
const _gatherLastByPlayer = new Map();

// POST /api/gather/claim — el cliente lo llama al COMPLETAR una tala/mina.
// Valida el nodo, lo bloquea (respawn), decide y acuña la recompensa.
app.post('/api/gather/claim',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  body('nodeKey').isString().notEmpty(),
  body('toolId').optional().isString(),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const address = req.user.address.toLowerCase();
      const { nodeKey, toolId } = req.body;

      const node = gatherNodeTypeFromKey(nodeKey);
      if (!node) return res.status(400).json({ error: 'invalid_node' });

      // Cooldown por jugador (200ms) — anti-spam.
      const now = Date.now();
      const last = _gatherLastByPlayer.get(address) || 0;
      if (now - last < 200) return res.status(429).json({ error: 'too_fast' });
      _gatherLastByPlayer.set(address, now);

      // El nodo no debe estar ya bloqueado (en respawn).
      // 60 s, igual que TREE_TYPE_CONFIG / MINERAL_TYPE_CONFIG.
      const respawnSec = 60;
      if (node.kind === 'tree') {
        const lock = await TreeLock.findOne({ treeKey: nodeKey });
        if (lock && lock.lockedUntil && lock.lockedUntil > new Date()) {
          return res.status(409).json({ error: 'node_locked', lockedUntil: lock.lockedUntil });
        }
      } else {
        const lock = await MineLock.findOne({ mineKey: nodeKey });
        if (lock && lock.lockedUntil && lock.lockedUntil > new Date()) {
          return res.status(409).json({ error: 'node_locked', lockedUntil: lock.lockedUntil });
        }
      }

      // Bloquear el nodo (respawn) — tope económico.
      const lockedUntil = new Date(now + respawnSec * 1000);
      if (node.kind === 'tree') {
        await TreeLock.findOneAndUpdate({ treeKey: nodeKey }, { treeKey: nodeKey, treeType: node.type, lockedUntil }, { upsert: true });
      } else {
        await MineLock.findOneAndUpdate({ mineKey: nodeKey }, { mineKey: nodeKey, mineralType: node.type, lockedUntil }, { upsert: true });
      }

      // Decidir y acuñar la recompensa (server-authoritative).
      const reward = decideGatherReward(node.type, toolId);
      let minted = null;
      if (reward.tipo && reward.quantity > 0) {
        minted = await mintGatherReward(address, reward.tipo, reward.quantity);
      }

      return res.json({
        ok: true,
        locked: true,
        lockedUntil,
        reward: minted ? { tipo: reward.tipo, quantity: reward.quantity, invoiceId: minted.id, manualId: minted.manualId, newTotal: minted.cantidad } : null
      });
    } catch (e) {
      console.error('❌ Error en /api/gather/claim:', e);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }
);



// =============================================================================
// CONTROL DE ACCESO — endpoints admin (usados por puerta_login.html)
// Protegidos: exigen sesión de una wallet admin (env ADMIN_ADDRESSES o isAdmin
// on-chain). GET lee la config; POST la reemplaza (modo, whitelist, baneos).
// =============================================================================
app.get('/api/access', apiLimiter, authMiddleware, requireAdmin, async (req, res) => {
  try {
    const ac = await getAccessControl();
    return res.json({ mode: ac.mode, whitelist: ac.whitelist || [], banned: ac.banned || [] });
  } catch (e) {
    console.error('Error GET /api/access:', e);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

app.post('/api/access', apiLimiter, authMiddleware, csrfProtection, requireAdmin, async (req, res) => {
  try {
    const { mode, whitelist, banned } = req.body || {};
    const update = {};
    if (mode === 'all' || mode === 'whitelist') update.mode = mode;
    if (Array.isArray(whitelist)) {
      update.whitelist = [...new Set(
        whitelist.map(a => String(a).toLowerCase().trim()).filter(a => /^0x[a-f0-9]{40}$/.test(a))
      )];
    }
    if (Array.isArray(banned)) {
      update.banned = banned
        .filter(b => b && b.address && /^0x[a-f0-9]{40}$/.test(String(b.address).toLowerCase().trim()))
        .map(b => ({
          address: String(b.address).toLowerCase().trim(),
          reason: String(b.reason || '').slice(0, 300),
          date: b.date ? new Date(b.date) : new Date()
        }));
    }
    await AccessControl.findOneAndUpdate({ _id: 'config' }, { $set: update }, { upsert: true });
    // Sin esto, un baneo tardaría hasta 30s (TTL de la caché) en hacer efecto.
    invalidateAccessCache();
    const ac = await getAccessControl();
    return res.json({ ok: true, mode: ac.mode, whitelist: ac.whitelist || [], banned: ac.banned || [] });
  } catch (e) {
    console.error('Error POST /api/access:', e);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

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
      
      // ── ENVÍO, CON LA COLA COMO RED DE SEGURIDAD ─────────────────────────
      // La cola (addToQueue + startQueueProcessor) existía completa desde hacía
      // tiempo pero NADIE la llamaba: era código muerto. Aquí se activa.
      //
      // El camino feliz NO cambia: se intenta enviar en el acto y el cliente
      // sigue recibiendo su txHash igual que siempre. Lo que cambia es el
      // fallo: si el envío se cae por algo TRANSITORIO (nodo RPC caído, nonce
      // pisado, gas mal calculado en una avalancha de transacciones), en vez de
      // devolver un 500 y perder la transacción, se encola y el procesador la
      // reintenta con espera creciente (5 s, 10 s, 15 s).
      //
      // Así la cola absorbe justo lo que tiene que absorber — los picos de
      // transacciones masivas y las caídas del nodo — sin tocar el contrato de
      // la API cuando todo va bien.
      let result;
      try {
        result = await relayManager.processTransaction(transactionData);
      } catch (envioError) {
        if (relayManager.shouldRetry(envioError)) {
          const queueId = await relayManager.addToQueue(transactionData);
          console.warn(`🕓 Envío fallido por causa transitoria — encolado para reintento: ${envioError.message}`);

          return res.status(202).json({
            success: true,
            queued: true,
            queueId,
            message: 'Transaction queued for retry',
            reason: envioError.message
          });
        }
        throw envioError;   // error real del contrato: sube al catch de abajo
      }

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
/**
 * Autenticación de administrador. Admite DOS formas:
 *
 *   1. CARTERA ADMIN (la recomendada, la que usan admin.html y misiones.html):
 *      el admin entra con su wallet por el flujo normal de /api/auth/login
 *      (nonce + firma) y queda con la cookie de sesión. Aquí se comprueba que
 *      la dirección de esa sesión sea admin — por ADMIN_ADDRESSES o por el
 *      isAdmin() del contrato. No hay que pegar ningún token a mano.
 *
 *   2. Bearer JWT con role 'admin' (lo de antes). Se mantiene para no romper
 *      nada que ya lo estuviera usando.
 */
const adminAuth = async (req, res, next) => {
  // ── 1. Cartera admin por cookie de sesión ────────────────────────────────
  try {
    const sessionToken = req.cookies && req.cookies.session;
    if (sessionToken) {
      const decoded = jwt.verify(sessionToken, JWT_SECRET, { algorithms: ['HS256'] });
      const addr = String(decoded.address || '').toLowerCase();
      if (addr && await isAdminAddress(addr)) {
        req.admin = { address: addr, via: 'wallet', role: 'admin' };
        req.user  = req.user || { address: addr };
        return next();
      }
      // Sesión válida pero de alguien que no es admin: se dice claramente.
      if (addr) {
        console.warn(`🚫 Acceso admin denegado a ${addr.slice(0, 10)}…`);
        return res.status(403).json({
          error: 'not_admin',
          message: 'Esta cartera no es administradora',
          address: addr
        });
      }
    }
  } catch (_) { /* cookie ausente o inválida: se prueba el Bearer */ }

  // ── 2. Bearer JWT de admin (compatibilidad) ──────────────────────────────
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'admin_auth_required',
      message: 'Conecta la cartera de administrador'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

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
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    
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

      // ── PROTECCIÓN CONTRA BORRAR UNA COMPRA DEL MARKET ────────────────────
      // El juego manda SIEMPRE el inventario entero, así que un guardado con
      // una copia vieja borra lo que el market metió mientras tanto. Aquí se
      // compara cuándo escribió el market con cuándo cargó el cliente su copia.
      //
      // `inventoryLoadedAt` lo manda el cliente. Si no viene (cliente antiguo,
      // todavía sin actualizar) se aplica un margen de seguridad: si el market
      // tocó el inventario en los últimos 10 minutos, tampoco se pisa. Es
      // preferible perder unos segundos de cambios del juego —que se rehacen
      // solos al recoger o craftear— que perder un ítem comprado con dinero.
      let inventarioObsoleto = false;
      try {
        const gpActual = await GamePlayer.findOne({ playerName }).select('marketWriteAt').lean();
        const marketAt = gpActual && gpActual.marketWriteAt ? new Date(gpActual.marketWriteAt).getTime() : 0;

        if (marketAt > 0) {
          const cargadoEn = Date.parse(req.body && req.body.inventoryLoadedAt);
          if (Number.isFinite(cargadoEn)) {
            inventarioObsoleto = marketAt > cargadoEn;
          } else {
            inventarioObsoleto = (Date.now() - marketAt) < 10 * 60 * 1000;
          }
        }
      } catch (e) {
        console.warn('⚠️ save: no se pudo comprobar marketWriteAt:', e.message);
      }

      if (inventarioObsoleto) {
        // NO se tocan inventario ni baúl: manda lo que hay en la base de datos.
        delete update.inventory;
        delete update.chest;
        console.log(`🛡️  save de ${playerName}: inventario NO sobrescrito (el market escribió después de que el cliente cargara)`);
      } else {
        // Sobrescribir con los arrays ya validados
        if (inventory) update.inventory = inventory;
        if (chest) update.chest = chest;
      }

      // El cliente no debe poder escribir esta marca a mano.
      delete update.marketWriteAt;

      // ── REGLA DE NOMBRE ÚNICO (personaje y mascota) ─────────────────────
      // Ambos nombres nacen como '---'. El jugador puede fijar cada uno UNA
      // sola vez: cuando el valor guardado ya NO es '---', cualquier intento
      // de cambiarlo se ignora (se conserva el existente). Validación en
      // servidor para que no dependa del cliente.
      //
      // Nombres que se rechazaron por estar ya cogidos. Viaja en la respuesta
      // para que el cliente pueda avisar al jugador (mensajes en inglés).
      const nombresRechazados = [];
      try {
        // NOMBRES CON NÚMEROS Y HASTA 15 CARACTERES (2026-08-04).
        // Antes solo se admitían letras y 10 caracteres, así que "Ana99" o
        // "Jugador2026" se quedaban en "Ana" y "Jugador". Ahora entran letras
        // Y dígitos (siguen fuera espacios, símbolos y etiquetas HTML, que es
        // lo que de verdad importa para no romper nada ni permitir inyección).
        // El límite debe coincidir con el del cliente (GameScene/tiendajuego).
        const sanitizeOneTimeName = (raw) => {
          if (typeof raw !== 'string') return null;
          let s = raw.normalize('NFC').trim().replace(/<[^>]*>/g, '');
          try { s = s.replace(/[^\p{L}\p{Nd}]/gu, ''); }
          catch (e) { s = s.replace(/[^A-Za-z0-9ÁÉÍÓÚáéíóúÑñÜü]/g, ''); }
          return s.slice(0, 15);
        };

        const existingGP = await GamePlayer.findOne({ playerName }).lean();

        for (const field of ['Username', 'petName']) {
          // (nombresRechazados se declara fuera del try, más arriba)
          if (update[field] === undefined) continue;

          const current = existingGP && typeof existingGP[field] === 'string'
            ? existingGP[field] : '---';

          if (current && current !== '---') {
            // Nombre ya fijado: inmutable, conservar el existente.
            if (update[field] !== current) {
              console.log(`🔒 ${field} ya fijado para ${playerName} ('${current}') — cambio ignorado`);
            }
            update[field] = current;
            continue;
          }

          // Aún en '---': permitir fijarlo una vez, sanitizado.
          const clean = sanitizeOneTimeName(update[field]);
          if (!clean) {
            // Vacío o inválido: mantener '---' (no cuenta como fijado)
            update[field] = '---';
          } else {
            // ── NOMBRE ÚNICO ENTRE JUGADORES ────────────────────────────
            // Faltaba por completo: este bloque sanitizaba el nombre y lo
            // hacía inmutable, pero NUNCA miraba si otro jugador ya lo tenía.
            // Dos cuentas podían llamarse igual — y con `petName` igual, que
            // es lo que se muestra en las batallas y en la clasificación.
            //
            // La comparación no distingue mayúsculas a propósito: "Kuro" y
            // "kuro" son el mismo nombre para cualquiera que los lea. Se
            // escapan los metacaracteres para que un nombre con símbolos no
            // rompa la consulta.
            const esc = clean.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const yaExiste = await GamePlayer.findOne({
              [field]: { $regex: '^' + esc + '$', $options: 'i' },
              playerName: { $ne: playerName }
            }).select('_id').lean();

            if (yaExiste) {
              // No se fija: se deja en '---' para que el jugador pueda
              // reintentar con otro. El aviso viaja en la respuesta.
              update[field] = '---';
              nombresRechazados.push({
                field: field,
                requested: clean,
                code: 'NAME_TAKEN',
                message: field === 'petName'
                  ? 'That pet name is already taken. Please choose a different one.'
                  : 'That username is already taken. Please choose a different one.'
              });
              console.log(`🚫 ${field} '${clean}' rechazado para ${playerName}: ya lo tiene otro jugador`);
            } else {
              update[field] = clean;
              console.log(`✅ ${field} fijado para ${playerName}: '${clean}' (definitivo)`);
            }
          }
        }
      } catch (nameErr) {
        console.warn('⚠️  No se pudo aplicar la regla de nombre único:', nameErr.message);
        // Ante cualquier duda, no permitir cambios de nombre en esta petición
        delete update.Username;
        delete update.petName;
      }

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
          // ── EXPERIENCIA: SE QUEDA LA MAYOR, NUNCA SE RETROCEDE ────────────
          // BUG QUE ESTO ARREGLA — "el personaje no pasa de nivel 4":
          //
          // Antes esto era `update.nivel_exp = pStats.exp`, o sea que la cadena
          // se imponía SIEMPRE. El problema es que la exp del cliente viaja a la
          // cadena por _syncExp(), que no hace nada si `_statsReady` es false, y
          // la escritura on-chain puede además fallar (hay caminos que lo
          // marcan como `exp_chain_failed`). Cuando eso pasa, `pStats.exp` deja
          // de crecer… y CADA guardado devolvía al jugador a ese valor viejo.
          // La experiencia quedaba congelada y con ella el nivel. Nivel 4 son
          // 1600 de exp acumulada con la curva del juego: justo donde se
          // quedaban clavados.
          //
          // La experiencia solo SUBE: nunca hay una razón legítima para que
          // baje. Así que se guarda la mayor de las dos. Si la cadena va por
          // delante (otro dispositivo), gana la cadena; si el cliente va por
          // delante (escritura pendiente o fallida), gana el cliente y su
          // progreso no se pierde — el siguiente _syncExp lo empujará.
          //
          // Es la misma regla de convergencia que ya usan las vitales con la
          // regeneración fantasma: el que solo suma, manda cuando va por
          // delante.
          if (pStats.invoiceIds && pStats.invoiceIds.exp) {
            const expCadena  = Math.max(0, Math.round(Number(pStats.exp) || 0));
            const expCliente = Math.max(0, Math.round(Number(update.nivel_exp) || 0));
            update.nivel_exp = Math.max(expCadena, expCliente);

            if (expCliente > expCadena) {
              console.log(`📈 ${playerName}: exp del cliente (${expCliente}) por delante de la cadena (${expCadena}) — se conserva la del cliente`);
            }
          }
        }
      } catch (psErr) {
        console.warn('⚠️  No se pudo leer PlayerStats para save:', psErr.message);
      }

      // ── EL TUTORIAL Y LAS HABILIDADES SOLO SUBEN ─────────────────────────
      // BUG QUE ESTO ARREGLA — "el tutorial retrocede al entrar y salir de la
      // tienda" y "las skills se ponen a cero solas":
      //
      // El juego tiene TRES escenas que llaman a este endpoint (GameScene,
      // tiendajuego y LoadingScenegame) y cada una guarda TODO su estado, no
      // solo lo que cambió. Cuando dos de ellas se solapan —cosa que pasa en
      // cada cambio de escena, porque el guardado del que se va no se espera— la
      // que llega segunda puede traer una copia más vieja y pisar el progreso.
      //
      // Estos tres campos comparten una propiedad que lo resuelve de raíz: no
      // existe ninguna jugada legítima que los haga BAJAR. El tutorial avanza
      // 0…7 → 20 → 21 → 22 (y ≥8 significa "terminado" para las cuentas
      // antiguas), y las habilidades solo suman experiencia. Así que aquí se
      // conserva siempre el valor más alto entre lo guardado y lo que llega.
      //
      // Es la misma regla que ya se aplicaba a `nivel_exp` unas líneas más
      // arriba, extendida a todo lo que es progreso acumulado.
      // ── CAMPOS QUE EL CLIENTE NO PUEDE ESCRIBIR ──────────────────────────
      // VULNERABILIDAD QUE ESTO CIERRA: /api/save hace
      // `Object.assign({}, req.body)`, así que TODO campo del esquema que llegue
      // en el cuerpo se guardaba. Dos de ellos tienen consecuencias reales:
      //
      //   • `nivel`    → decide vida y ataque en las batallas PvP
      //                  (battleStatsForLevel) y la rareza de las cartas
      //                  (pesosPorNivel). Mandar {"nivel":150} daba 1.880 de
      //                  vida y 310 de ataque contra los 128/18 de un jugador
      //                  legítimo. Ahora se CALCULA desde la experiencia, que
      //                  está respaldada por el contrato.
      //
      //   • `petLevel` → lo calcula el servidor tras cada batalla
      //                  (computePetLevel a partir de victorias y combates).
      //                  Que el cliente pudiera sobrescribirlo dejaba el
      //                  contador en manos del jugador.
      //
      // Los dos se quitan del cuerpo ANTES de tocar la base de datos.
      delete update.petLevel;
      // Mismo motivo que petLevel: estos los decide el servidor. `petMode`
      // manda sobre a quién atacan los animales, `petHealth` sobre con cuánta
      // vida entra la mascota a las batallas, y el trío de la muerte sobre lo
      // que cuesta revivir. Todos se escriben solo por sus endpoints.
      delete update.petHealth;
      delete update.petMode;
      delete update.petDiedAt;
      delete update.isGhost;
      delete update.deathCount;
      delete update.deathWindowAt;
      delete update.petLastHitAt;
      {
        const expParaNivel = (update.nivel_exp !== undefined)
          ? update.nivel_exp
          : null;
        if (expParaNivel !== null) {
          update.nivel = nivelPorExperiencia(expParaNivel);
        } else {
          delete update.nivel;   // sin experiencia que lo justifique, no se toca
        }
      }

      try {
        // `nivel` NO va en esta lista: ya no lo escribe el cliente, se deriva de
        // la experiencia unas líneas más arriba. Y como la experiencia solo
        // sube, el nivel derivado ya es monótono por construcción. Dejarlo aquí
        // además congelaría para siempre el nivel inflado de cualquier cuenta
        // que hubiera abusado del fallo antiguo; así se corrige sola en el
        // siguiente guardado.
        const CAMPOS_MONOTONOS = [
          'tutorial',
          'agricultura', 'agricultura_exp',
          'mineria',     'mineria_exp',
          'deforestacion', 'deforestacion_exp',
          'pesca',   'pesca_exp',
          'cocina',  'cocina_exp',
          'fuerza',  'fuerza_exp'
        ];

        const previo = await GamePlayer.findOne({ playerName })
          .select(CAMPOS_MONOTONOS.join(' ')).lean();

        if (previo) {
          for (const campo of CAMPOS_MONOTONOS) {
            if (update[campo] === undefined) continue;      // no se toca lo que no llega

            const entrante = Number(update[campo]);
            const guardado = Number(previo[campo]);

            if (!Number.isFinite(entrante)) { delete update[campo]; continue; }
            if (!Number.isFinite(guardado)) continue;

            if (entrante < guardado) {
              console.log(`⏪ ${playerName}: se ignora ${campo}=${entrante} (guardado ${guardado} — este campo no retrocede)`);
              update[campo] = guardado;
            }
          }
        }
      } catch (monoErr) {
        console.warn('⚠️  No se pudo aplicar la regla de progreso monótono:', monoErr.message);
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

      // Tiempo jugado: cada guardado suma el hueco desde el anterior. Es la
      // única señal periódica que ya existía mientras el jugador está dentro.
      // No bloquea la respuesta: si falla, solo se pierde ese tramo.
      registrarTiempoJugado(playerName, address).catch(() => {});

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

      // Nombres que se pidieron pero ya los tenía otro jugador. El cliente los
      // usa para mostrar el aviso; los mensajes vienen ya redactados en inglés
      // desde el servidor, así que no hay que traducir nada en el cliente.
      if (nombresRechazados.length) response.nameConflicts = nombresRechazados;

      // Avisa al cliente de que su inventario quedó obsoleto y debe recargarlo:
      // el market metió algo mientras tanto y su copia ya no vale.
      if (inventarioObsoleto) response.inventoryStale = true;

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

// Devuelve el turno del pozo cuando el intercambio de baldes on-chain no llegó
// a confirmarse (ver refundCollection). Sin esto, una transacción fallida le
// costaba al jugador una de las 5 recolecciones del día.
app.post('/api/water/collect/refund',
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

      const result = await waterCollectionController.refundCollection(playerName);
      res.json(result);
    } catch (error) {
      console.error('Error devolviendo la recolección de agua:', error);
      res.status(400).json({ success: false, error: error.message });
    }
  }
);


// =============================================================================
// MASCOTA (VIDA Y MODO) Y MUERTE DEL JUGADOR
// -----------------------------------------------------------------------------
// QUÉ DECIDE EL SERVIDOR Y POR QUÉ
//
//   · petMode      — de él depende a quién atacan los animales. Si lo escribiera
//                    el cliente, bastaría con ponerlo en 'attack' para que nada
//                    tocara jamás al personaje.
//   · petHealth    — con ella entra la mascota a las batallas PvP/PvE.
//   · deathCount   — decide el precio de revivir. En el cliente, todo el mundo
//                    reviviría siempre por 30 de plata.
//
// LA PLATA VIVE EN LA CADENA. Cobrar el revivir es bajar el número en Mongo y
// apuntar la deuda con `marcarPendienteDeCadena`, exactamente igual que hace
// /api/stats/consume. El liquidador agrupa y escribe. Inventarse un descuento
// por otro lado dejaría la cadena desincronizada.
// =============================================================================

const PET_VIDA_MAX      = 100;
// Cuánto cura cada poción del alquimista.
const PET_POCIONES      = { pocion_mascota: 40, pocion_mascota_grande: 100 };
const PET_ITEM_REVIVIR  = 'elixir_revivir';
// Con cuánta vida vuelve la mascota tras el elixir: no vuelve al 100, revivir
// no puede ser mejor que cuidarla.
const PET_VIDA_AL_REVIVIR = 50;
// Tope de daño por petición. Los animales son decoración del cliente, así que
// el mordisco lo reporta él; lo que no puede es reportar 5.000 de golpe.
const PET_DANO_MAX_POR_GOLPE = 12;
// Un mordisco como mucho cada tanto, por mascota.
const PET_DANO_INTERVALO_MS  = 700;

// Lo que le quita al JUGADOR un mordisco (lo cobra /api/stats/consume).
const DANO_MORDISCO_ANIMAL = 6;

const REVIVIR_BASE_PLATA   = 30;
const REVIVIR_TOPE_PLATA   = 480;
const REVIVIR_VENTANA_MS   = 24 * 60 * 60 * 1000;
// Al revivir se vuelve con la vida LLENA. Estaba en 50 y el jugador
// esperaba, con razón, volver entero después de pagar.
const REVIVIR_VIDA         = 100;

/**
 * Precio de revivir según cuántas veces hayas muerto en la ventana de 24 h.
 * 30 la primera, y el doble cada vez, con tope para que no se vuelva absurdo.
 */
function precioRevivir(muertes) {
  const n = Math.max(0, Number(muertes) || 0);
  return Math.min(REVIVIR_BASE_PLATA * Math.pow(2, n), REVIVIR_TOPE_PLATA);
}

/**
 * Si ya pasaron 24 h desde la primera muerte de la racha, el contador vuelve a
 * cero y el precio a 30. Devuelve true si ha cambiado algo.
 *
 * Es una ventana rodante desde la PRIMERA muerte, no un día de calendario: el
 * jugador dijo "si ya se cumplieron las 24 horas", no "a medianoche".
 */
function normalizarVentanaMuertes(gp) {
  const ahora = Date.now();
  const ini = gp.deathWindowAt ? new Date(gp.deathWindowAt).getTime() : 0;
  if (ini && (ahora - ini) < REVIVIR_VENTANA_MS) return false;
  if (!ini && !gp.deathCount) return false;
  gp.deathWindowAt = null;
  gp.deathCount = 0;
  return true;
}

/** El GamePlayer de quien hace la petición, o null si no cuadra la sesión. */
async function jugadorDeLaSesion(req) {
  const address = String((req.user && req.user.address) || '').toLowerCase();
  if (!address) return null;
  const auth = await PlayerAuth.findOne({ address }).lean().exec();
  if (!auth || !auth.playerName) return null;
  return GamePlayer.findOne({ playerName: auth.playerName }).exec();
}

/** Respuesta común: todo lo que el cliente necesita para pintar el estado. */
function estadoVivo(gp) {
  const salud = Math.max(0, Math.min(PET_VIDA_MAX, Number(gp.petHealth ?? PET_VIDA_MAX)));
  return {
    ok: true,
    pet: {
      health: salud,
      maxHealth: PET_VIDA_MAX,
      mode: gp.petMode === 'attack' ? 'attack' : 'passive',
      alive: salud > 0
    },
    player: {
      ghost: !!gp.isGhost,
      deaths: Math.max(0, Number(gp.deathCount) || 0),
      reviveCost: precioRevivir(gp.deathCount),
      windowEndsAt: gp.deathWindowAt
        ? new Date(new Date(gp.deathWindowAt).getTime() + REVIVIR_VENTANA_MS).toISOString()
        : null
    }
  };
}

// ── GET /api/pet/state ──────────────────────────────────────────────────────
// Estado de la mascota Y de la muerte del jugador en una sola llamada: el
// cliente los necesita juntos y así no hay dos viajes en cada cambio de escena.
app.get('/api/pet/state', apiLimiter, authMiddleware, async (req, res) => {
  try {
    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });
    if (normalizarVentanaMuertes(gp)) await gp.save();
    return res.json(estadoVivo(gp));
  } catch (err) {
    console.error('GET /api/pet/state:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/pet/mode ──────────────────────────────────────────────────────
// body: { mode: 'passive' | 'attack' }
app.post('/api/pet/mode', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const modo = String((req.body && req.body.mode) || '').toLowerCase();
    if (modo !== 'passive' && modo !== 'attack') {
      return res.status(400).json({ error: 'modo_invalido' });
    }
    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });

    // Una mascota muerta no puede ponerse a pelear.
    if (modo === 'attack' && (Number(gp.petHealth) || 0) <= 0) {
      return res.status(409).json({ error: 'mascota_muerta', ...estadoVivo(gp) });
    }
    gp.petMode = modo;
    await gp.save();
    console.log(`🐕 ${gp.playerName}: mascota en modo ${modo}`);
    return res.json(estadoVivo(gp));
  } catch (err) {
    console.error('POST /api/pet/mode:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/pet/damage ────────────────────────────────────────────────────
// body: { amount }   Un animal ha mordido a la mascota.
app.post('/api/pet/damage', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });

    const salud = Math.max(0, Math.min(PET_VIDA_MAX, Number(gp.petHealth ?? PET_VIDA_MAX)));
    if (salud <= 0) return res.json(estadoVivo(gp));   // ya estaba muerta

    // Ritmo mínimo entre mordiscos: sin esto, un cliente modificado podría
    // mandar mil peticiones seguidas. Va en un campo del esquema a propósito:
    // una propiedad suelta en el documento no se guarda, así que el límite se
    // habría perdido entre peticiones y no habría limitado nada.
    const ahora = Date.now();
    const ultimo = gp.petLastHitAt ? new Date(gp.petLastHitAt).getTime() : 0;
    if (ultimo && (ahora - ultimo) < PET_DANO_INTERVALO_MS) {
      return res.json(estadoVivo(gp));
    }
    gp.petLastHitAt = new Date(ahora);

    const dano = Math.max(1, Math.min(PET_DANO_MAX_POR_GOLPE,
                                      Math.round(Number(req.body && req.body.amount) || 1)));
    const nueva = Math.max(0, salud - dano);
    gp.petHealth = nueva;
    if (nueva === 0) {
      gp.petDiedAt = new Date();
      // Una mascota muerta no sigue en modo ataque: si no, al revivirla se
      // pondría a pelear sola sin que el jugador lo haya pedido.
      gp.petMode = 'passive';
      console.log(`💀 ${gp.playerName}: la mascota ha muerto`);
    }
    await gp.save();
    return res.json(estadoVivo(gp));
  } catch (err) {
    console.error('POST /api/pet/damage:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/pet/heal ──────────────────────────────────────────────────────
// body: { itemId }   Usa una poción del inventario para curar a la mascota.
app.post('/api/pet/heal', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const itemId = String((req.body && req.body.itemId) || '');
    const cura = PET_POCIONES[itemId];
    if (!cura) return res.status(400).json({ error: 'item_invalido' });

    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });

    const salud = Math.max(0, Math.min(PET_VIDA_MAX, Number(gp.petHealth ?? PET_VIDA_MAX)));
    if (salud <= 0) {
      return res.status(409).json({ error: 'mascota_muerta', ...estadoVivo(gp) });
    }
    if (salud >= PET_VIDA_MAX) {
      return res.status(409).json({ error: 'mascota_llena', ...estadoVivo(gp) });
    }

    // La poción se descuenta del inventario GUARDADO. Si el cliente todavía no
    // ha guardado la compra, responde `inventario_desfasado` y él guarda y
    // reintenta — mejor eso que curar sin gastar nada.
    if (contarEnSlots(gp.inventory, itemId) + contarEnSlots(gp.chest, itemId) < 1) {
      return res.status(409).json({ error: 'inventario_desfasado', itemId });
    }
    const r = descontarDeSlots(gp.chest, gp.inventory, itemId, 1);
    if (r.descontadas < 1) {
      return res.status(409).json({ error: 'inventario_desfasado', itemId });
    }
    gp.inventory = r.inventory;
    gp.chest     = r.chest;
    gp.markModified('inventory');
    gp.markModified('chest');
    gp.petHealth = Math.min(PET_VIDA_MAX, salud + cura);
    await gp.save();
    console.log(`🧪 ${gp.playerName}: ${itemId} → mascota ${salud}→${gp.petHealth}`);
    return res.json(estadoVivo(gp));
  } catch (err) {
    console.error('POST /api/pet/heal:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/pet/revive ────────────────────────────────────────────────────
// Gasta un elixir del alquimista y devuelve la mascota a la vida.
app.post('/api/pet/revive', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });

    const salud = Math.max(0, Number(gp.petHealth) || 0);
    if (salud > 0) {
      return res.status(409).json({ error: 'mascota_viva', ...estadoVivo(gp) });
    }
    if (contarEnSlots(gp.inventory, PET_ITEM_REVIVIR) +
        contarEnSlots(gp.chest, PET_ITEM_REVIVIR) < 1) {
      return res.status(409).json({ error: 'falta_elixir', itemId: PET_ITEM_REVIVIR });
    }
    const r = descontarDeSlots(gp.chest, gp.inventory, PET_ITEM_REVIVIR, 1);
    if (r.descontadas < 1) {
      return res.status(409).json({ error: 'falta_elixir', itemId: PET_ITEM_REVIVIR });
    }
    gp.inventory = r.inventory;
    gp.chest     = r.chest;
    gp.markModified('inventory');
    gp.markModified('chest');
    gp.petHealth = PET_VIDA_AL_REVIVIR;
    gp.petDiedAt = null;
    gp.petMode   = 'passive';
    await gp.save();
    console.log(`✨ ${gp.playerName}: mascota revivida al ${PET_VIDA_AL_REVIVIR}%`);
    return res.json(estadoVivo(gp));
  } catch (err) {
    console.error('POST /api/pet/revive:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/player/death ──────────────────────────────────────────────────
// El personaje se ha quedado sin vida: pasa a fantasma. El servidor comprueba
// que de verdad está a 0 antes de creérselo — así nadie se declara muerto para
// forzar nada raro.
app.post('/api/player/death', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });
    if (gp.isGhost) return res.json(estadoVivo(gp));

    const stats = await PlayerStats.findOne({ playerName: gp.playerName }).exec();
    const vida = stats ? Math.max(0, Number(stats.vida) || 0) : 0;
    if (vida > 0) {
      return res.status(409).json({ error: 'sigue_vivo', vida, ...estadoVivo(gp) });
    }

    normalizarVentanaMuertes(gp);
    if (!gp.deathWindowAt) gp.deathWindowAt = new Date();
    gp.deathCount = Math.max(0, Number(gp.deathCount) || 0) + 1;
    gp.isGhost = true;
    await gp.save();

    // Se para el reloj de la vida: un muerto no se cura solo esperando.
    if (stats && !stats.vidaCongelada) {
      stats.vidaCongelada = true;
      try { await stats.save(); } catch (e) {
        console.warn('⚠️  no se pudo congelar la vida:', e.message);
      }
    }
    console.log(`👻 ${gp.playerName} ha muerto (${gp.deathCount} en 24 h) — ` +
                `revivir cuesta ${precioRevivir(gp.deathCount - 1)} de plata`);
    return res.json(estadoVivo(gp));
  } catch (err) {
    console.error('POST /api/player/death:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/player/revive ─────────────────────────────────────────────────
// Paga en plata y vuelve a la vida. El precio lo pone el servidor.
app.post('/api/player/revive', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });
    if (!gp.isGhost) return res.status(409).json({ error: 'no_estas_muerto', ...estadoVivo(gp) });

    normalizarVentanaMuertes(gp);
    // El precio es el de las muertes ANTERIORES a esta: la primera muerte del
    // día cuesta 30, no 60.
    const precio = precioRevivir(Math.max(0, (Number(gp.deathCount) || 1) - 1));

    const stats = await PlayerStats.findOne({ playerName: gp.playerName }).exec();
    if (!stats) return res.status(409).json({ error: 'sin_stats' });

    const plata = Math.max(0, Math.round(Number(stats.plata) || 0));
    if (plata < precio) {
      return res.status(409).json({ error: 'plata_insuficiente', precio, plata, ...estadoVivo(gp) });
    }

    // Cobro: mismo camino que /api/stats/consume. Se baja en Mongo, que es la
    // fuente autoritativa del saldo, y se apunta la deuda con la cadena; el
    // liquidador agrupa y escribe la factura.
    stats.plata = clampStat('plata', plata - precio);
    stats.vida  = clampStat('vida', REVIVIR_VIDA);
    stats.vidaCongelada = false;          // vuelve a correr el reloj de la vida
    /* Y se pone el reloj a cero AHORA: si no, los tics que pasaron mientras
       estaba muerto se cobrarían de golpe en la primera lectura y el que acaba
       de revivir con el 100 % no lo notaría, pero el que reviva con menos vería
       un salto raro. */
    stats.lastVitalRegen = new Date();
    marcarPendienteDeCadena(stats, ['plata', 'vida']);
    await stats.save();

    gp.isGhost = false;
    await gp.save();

    console.log(`💖 ${gp.playerName} revive por ${precio} de plata ` +
                `(le quedan ${stats.plata}) — vida al ${REVIVIR_VIDA}%`);
    return res.json({
      ...estadoVivo(gp),
      paid: precio,
      stats: buildStatsResponse(stats)
    });
  } catch (err) {
    console.error('POST /api/player/revive:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});


// ── POST /api/crops/crow ────────────────────────────────────────────────────
// EL CUERVO HAMBRIENTO SE METE EN UNA PARCELA.
//
// Lo que pasa lo decide el SERVIDOR, no el navegador:
//
//   · cultivo LISTO para cosechar  → se lo come. El cultivo pasa a `isDead`,
//     que es el mismo estado en el que queda una cosecha que se pudre por
//     abandono: al recogerla da la recompensa mala en vez de la buena. Se ha
//     preferido eso a borrarla del todo porque perder la parcela entera por un
//     pájaro es demasiado castigo, y el estado ya existía en el juego.
//     (Para que la destruya del todo, aquí bastaría con un deleteOne.)
//
//   · cultivo TODAVÍA CRECIENDO   → no se lo puede comer, pero lo pisotea y lo
//     RETRASA: se le alarga la duración del crecimiento. Con tope, para que
//     picotazo tras picotazo no acabe tardando un día.
//
// HASTA DÓNDE LLEGA LA VALIDACIÓN: el cuervo es un sprite del cliente, así que
// es él quien avisa de que ha picoteado. El servidor comprueba de quién es la
// parcela, en qué estado está, cuánto retrasa y cada cuánto se admite. Lo que
// no puede evitar es que un cliente modificado NO avise nunca — pero eso solo
// le ahorra molestias a quien lo haga, no le da nada a cambio.
const CUERVO_RETRASO_PCT   = 0.25;        // cuánto retrasa un picotazo
const CUERVO_RETRASO_TOPE  = 1.60;        // nunca más del 60% sobre lo original
const CUERVO_INTERVALO_MS  = 45 * 1000;   // uno por jugador y rato
const _cuervoUltimo = new Map();

app.post('/api/crops/crow', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });

    const ahora = Date.now();
    const ultimo = _cuervoUltimo.get(gp.playerName) || 0;
    if (ahora - ultimo < CUERVO_INTERVALO_MS) {
      return res.json({ ok: true, resultado: 'demasiado_pronto' });
    }

    const plotId = String((req.body && req.body.plotId) || '').slice(0, 60);
    if (!plotId) return res.status(400).json({ error: 'falta_plotId' });

    /* Se incluyen también las MUERTAS: una planta seca en la parcela es
       comida para un cuervo igual que una buena, y el jugador se quejó de que
       esas no desaparecían. Solo se excluyen las ya recogidas, que ya no
       existen sobre el terreno. */
    const crop = await UserCrop.findOne({
      userId: gp.playerName, plotId, isHarvested: false
    }).exec();
    if (!crop) return res.json({ ok: true, resultado: 'nada_que_picar' });

    _cuervoUltimo.set(gp.playerName, ahora);

    if (crop.isCompleted || crop.isDead) {
      /* SE LA COME DE VERDAD: la parcela queda VACÍA.

         Antes solo se marcaba `isDead`, y eso deja la planta ahí, seca pero
         visible; el jugador veía al cuervo picotear y la cosecha seguía en su
         sitio. Ahora se borra el cultivo y el cliente limpia la parcela con
         resetPlot(), igual que al recoger. */
      await UserCrop.deleteOne({ _id: crop._id });
      console.log(`🐦 Un cuervo se comió el cultivo de ${gp.playerName} en ${plotId}` +
                  (crop.isDead ? ' (estaba seco)' : ' (estaba listo)'));
      return res.json({ ok: true, resultado: 'comida', plotId, vaciada: true });
    }

    const original = Number(crop.growthDurationOriginal) || Number(crop.growthDuration) || 0;
    if (!crop.growthDurationOriginal) crop.growthDurationOriginal = original;
    const tope  = Math.round(original * CUERVO_RETRASO_TOPE);
    const nueva = Math.min(tope, Math.round(crop.growthDuration * (1 + CUERVO_RETRASO_PCT)));
    const retrasado = nueva > crop.growthDuration;
    crop.growthDuration = nueva;
    await crop.save();
    console.log(`🐦 Un cuervo pisoteó el cultivo de ${gp.playerName} en ${plotId}` +
                (retrasado ? ` (crece en ${nueva} en vez de ${original})` : ' (ya al tope)'));
    return res.json({
      ok: true, resultado: retrasado ? 'retrasada' : 'ya_al_tope',
      plotId, growthDuration: nueva
    });
  } catch (err) {
    console.error('POST /api/crops/crow:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});


// =============================================================================
// EL ALQUIMISTA
// -----------------------------------------------------------------------------
// Vende pociones para la mascota y el elixir para revivirla.
//
// POR QUÉ TIENE SU PROPIO ENDPOINT Y NO PASA POR LA TIENDA: la tienda hace la
// compra desde el CLIENTE, con su propia cola de transacciones on-chain
// (Additemblockchains). Reaprovecharla desde fuera obligaría a meter mano en su
// estado interno. Aquí la compra entera —cobrar la plata, acuñar el ítem y
// meterlo en el inventario— se hace en el servidor con los mismos helpers que
// usan las misiones, que ya están probados.
// =============================================================================

const ALQUIMISTA_CATALOGO = {
  pocion_mascota:        { plata: 45,  cura: 40,  nombre: 'Pet Potion' },
  pocion_mascota_grande: { plata: 110, cura: 100, nombre: 'Great Pet Potion' },
  elixir_revivir:        { plata: 260, revive: true, nombre: 'Revival Elixir' }
};
const ALQUIMISTA_MAX_POR_COMPRA = 5;

// ── GET /api/alchemist/catalog ──────────────────────────────────────────────
app.get('/api/alchemist/catalog', apiLimiter, authMiddleware, async (req, res) => {
  try {
    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });
    const stats = await PlayerStats.findOne({ playerName: gp.playerName }).lean();
    const items = Object.keys(ALQUIMISTA_CATALOGO).map(function (id) {
      const c = ALQUIMISTA_CATALOGO[id];
      return {
        id, name: c.nombre, price: c.plata,
        heals: c.cura || 0, revives: !!c.revive,
        owned: contarEnSlots(gp.inventory, id) + contarEnSlots(gp.chest, id)
      };
    });
    return res.json({
      ok: true, items,
      silver: stats ? Math.max(0, Math.round(Number(stats.plata) || 0)) : 0,
      pet: estadoVivo(gp).pet
    });
  } catch (err) {
    console.error('GET /api/alchemist/catalog:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/alchemist/buy ─────────────────────────────────────────────────
// body: { itemId, qty }
app.post('/api/alchemist/buy', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const itemId = String((req.body && req.body.itemId) || '');
    const cfg = ALQUIMISTA_CATALOGO[itemId];
    if (!cfg) return res.status(400).json({ error: 'item_desconocido' });

    const qty = Math.max(1, Math.min(ALQUIMISTA_MAX_POR_COMPRA,
                                     Math.floor(Number(req.body && req.body.qty) || 1)));

    const gp = await jugadorDeLaSesion(req);
    if (!gp) return res.status(403).json({ error: 'no_autorizado' });

    const stats = await PlayerStats.findOne({ playerName: gp.playerName }).exec();
    if (!stats) return res.status(409).json({ error: 'sin_stats' });

    // EL PRECIO LO PONE EL SERVIDOR. El cliente solo dice qué y cuántos.
    const coste = cfg.plata * qty;
    const plata = Math.max(0, Math.round(Number(stats.plata) || 0));
    if (plata < coste) {
      return res.status(409).json({ error: 'plata_insuficiente', precio: coste, plata });
    }

    // 1) Acuñar el ítem. Si esto falla NO se cobra: primero se entrega.
    const address = String(gp.address || '').toLowerCase();
    let acunado = null;
    const tipo = itemTipoOnChain(itemId);
    if (address && tipo) {
      try { acunado = await mintGatherReward(address, tipo, qty); }
      catch (e) { console.error('❌ alquimista: acuñado falló:', e.message); }
      if (!acunado) {
        return res.status(502).json({ error: 'acunado_fallido', itemId });
      }
    }

    // 2) Meterlo en el inventario guardado.
    const puesto = agregarASlots(gp.inventory, itemId, qty, {
      invoiceId: acunado ? acunado.id : null,
      manualId:  acunado ? acunado.manualId : null
    });
    if (puesto.metidas <= 0) {
      return res.status(409).json({ error: 'inventario_lleno', itemId });
    }
    gp.inventory = puesto.inventory;
    gp.markModified('inventory');
    await gp.save();

    // 3) Cobrar, por el mismo camino que el resto del juego.
    const entregadas = puesto.metidas;
    const cobro = cfg.plata * entregadas;
    stats.plata = clampStat('plata', plata - cobro);
    marcarPendienteDeCadena(stats, ['plata']);
    await stats.save();

    console.log(`⚗️  ${gp.playerName} compró ${entregadas}x ${itemId} por ${cobro} de plata`);
    return res.json({
      ok: true, itemId, qty: entregadas, paid: cobro,
      silver: stats.plata,
      partial: entregadas < qty ? qty - entregadas : 0,
      stats: buildStatsResponse(stats)
    });
  } catch (err) {
    console.error('POST /api/alchemist/buy:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});


// =============================================================================
// CLIMA DEL MUNDO: VIENTO Y LLUVIA
// -----------------------------------------------------------------------------
// El clima es del MUNDO, no de cada navegador: si lo decidiera el cliente, dos
// jugadores en la misma plaza verían cosas distintas. Se decide aquí, se guarda,
// y todos lo leen — igual que la hora (/api/world/time).
//
// Se configura desde climas.html, que exige cartera de administrador.
// =============================================================================

const climaSchema = new mongoose.Schema({
  _id: { type: String, default: 'config' },

  // ── Interruptores ──────────────────────────────────────────────────────
  activo:     { type: Boolean, default: true },   // clima sí/no
  modo:       { type: String, enum: ['auto', 'manual'], default: 'auto' },

  // ── Lo que se ve AHORA (lo que manda en modo manual) ───────────────────
  viento:     { type: Boolean, default: false },
  vientoFuerza: { type: Number, default: 1, min: 0.2, max: 2 },
  lluvia:     { type: Boolean, default: false },
  lluviaFuerza: { type: Number, default: 1, min: 0.2, max: 2 },
  truenos:    { type: Boolean, default: true },
  nieve:      { type: Boolean, default: false },
  nieveFuerza:{ type: Number, default: 1, min: 0.2, max: 2 },

  /* SOLEADO. Entran rayos de sol por la esquina de arriba a la izquierda —de
     donde viene la luz en todo el arte del juego, y de donde caen las sombras.
     No es "lo contrario de llover": despejado es que no pasa nada, y esto es
     que hace un día bueno y se nota. Por eso es su propio interruptor y no un
     hueco entre los demás. */
  soleado:    { type: Boolean, default: false },
  soleadoFuerza: { type: Number, default: 1, min: 0.2, max: 2 },

  /* ESTACIÓN DEL AÑO. Cambia el color de todo el mundo: el otoño lo pone
     ámbar, el invierno azulado y frío. 'auto' la saca del mes real. */
  estacion:   { type: String,
                enum: ['auto', 'primavera', 'verano', 'otono', 'invierno'],
                default: 'auto' },

  /* ── Reglas del modo automático (en minutos y en tanto por uno) ─────────

     LOS TOPES SE HAN SOLTADO. Estaban en 120 y 240 minutos y el panel no
     dejaba escribir más: si el administrador quería una tormenta de 20 min o
     de 8 horas, no podía. Ahora el tope es un día entero, que es lo máximo
     que tiene sentido para algo que se programa a mano. */
  probViento:   { type: Number, default: 0.25, min: 0, max: 1 },
  probLluvia:   { type: Number, default: 0.15, min: 0, max: 1 },
  probNieve:    { type: Number, default: 0.05, min: 0, max: 1 },
  minutosSorteo:{ type: Number, default: 12, min: 1, max: 1440 },
  duracionMin:  { type: Number, default: 2,  min: 1, max: 1440 },
  duracionMax:  { type: Number, default: 6,  min: 1, max: 1440 },

  /* ── COLA DE CLIMAS PROGRAMADOS ─────────────────────────────────────────

     El administrador apunta "lluvia 20 min", luego "tormenta 5 min", luego
     "despejado 30 min" y se van poniendo uno detrás de otro. Cuando acaba lo
     que hay puesto, entra el primero de la cola.

     La cola manda sobre el sorteo automático: mientras haya algo apuntado, el
     azar no pinta nada. Es lo que se espera de una programación. */
  cola: {
    type: [new mongoose.Schema({
      que:          { type: String, enum: ['viento', 'lluvia', 'tormenta',
                                           'nieve', 'soleado', 'despejado'],
                      required: true },
      minutos:      { type: Number, required: true, min: 1, max: 1440 },
      vientoFuerza: { type: Number, default: 1, min: 0.2, max: 2 },
      lluviaFuerza: { type: Number, default: 1, min: 0.2, max: 2 },
      nieveFuerza:  { type: Number, default: 1, min: 0.2, max: 2 },
      soleadoFuerza:{ type: Number, default: 1, min: 0.2, max: 2 },
      truenos:      { type: Boolean, default: true },
      creadoPor:    { type: String, default: null },
      creadoEn:     { type: Date, default: Date.now }
    }, { _id: true, versionKey: false })],
    default: []
  },

  // ── Estado interno del sorteo ──────────────────────────────────────────
  hasta:      { type: Date, default: null },   // cuándo acaba lo de ahora
  proximo:    { type: Date, default: null },   // cuándo se vuelve a sortear
  // Qué se está viendo ahora mismo y de dónde salió, para el panel.
  actual:     { type: String, default: null },
  actualDeCola: { type: Boolean, default: false },
  actualizadoPor: { type: String, default: null },
  updatedAt:  { type: Date, default: Date.now }
}, { versionKey: false });

const Clima = mongoose.model('Clima', climaSchema);

/* EL DOCUMENTO DEL CLIMA SE GUARDA EN MEMORIA.

   /api/world/weather lo consulta CADA JUGADOR cada 45 segundos, y antes cada
   una de esas consultas era una lectura a Mongo de un documento que solo
   escribe este proceso. Con doscientos jugadores eso son cuatro lecturas por
   segundo para leer siempre lo mismo. Como nadie más toca esta colección, el
   documento vivo en memoria ES la verdad, y guardarlo se sigue haciendo con
   d.save() como siempre. */
let _climaCache = null;
let _climaCacheAt = 0;
/* CON CADUCIDAD, no para siempre. Si algún día esto corre en más de un proceso
   (cluster, dos instancias detrás de un balanceador), una caché eterna sería
   PEOR que el problema que arregla: el proceso que no recibió la escritura del
   panel se quedaría sirviendo el clima viejo indefinidamente — justo el fallo
   que se está corrigiendo. Con 5 s se evitan el 99 % de las lecturas y ninguna
   instancia puede ir desfasada más de ese rato. */
const CLIMA_CACHE_MS = 5000;

/** La configuración, creándola con los valores por defecto la primera vez. */
async function climaDoc() {
  if (_climaCache && (Date.now() - _climaCacheAt) < CLIMA_CACHE_MS) return _climaCache;
  let d = await Clima.findById('config').exec();
  if (!d) d = await Clima.create({ _id: 'config' });
  _climaCache = d;
  _climaCacheAt = Date.now();
  return d;
}

/** Número de versión del clima: sube con cada cambio de verdad. */
let climaRev = 1;

/**
 * Pone en el mundo lo que dice una entrada (de la cola o del botón de probar).
 *
 * Un solo sitio para traducir "qué" a los interruptores: antes esta traducción
 * estaba copiada en la ruta de probar, y añadir la nieve habría obligado a
 * tocarla en dos lados.
 */
function climaAplicarEntrada(d, e, ahora) {
  // `== null` y no `||`: con `||`, pasar 0 (la epoca) caeria en Date.now()
  // y el llamante no tendria forma de fijar el reloj. Solo lo notan las
  // pruebas, pero es la clase de trampa que luego cuesta encontrar.
  ahora = (ahora == null) ? Date.now() : ahora;
  d.activo = true;
  d.viento  = (e.que === 'viento' || e.que === 'tormenta');
  d.lluvia  = (e.que === 'lluvia' || e.que === 'tormenta');
  d.nieve   = (e.que === 'nieve');
  /* El sol y el agua no conviven: si entra sol, se va todo lo demás. Un día
     soleado con lluvia cayendo se lee como un fallo, no como un chubasco. */
  d.soleado = (e.que === 'soleado');
  if (d.soleado) { d.viento = false; d.lluvia = false; d.nieve = false; }
  if (e.que === 'despejado') { d.viento = false; d.lluvia = false; d.nieve = false; }
  if (Number.isFinite(Number(e.soleadoFuerza))) d.soleadoFuerza = Number(e.soleadoFuerza);
  if (e.que === 'tormenta') d.truenos = true;
  else if (typeof e.truenos === 'boolean') d.truenos = e.truenos;
  if (Number.isFinite(Number(e.vientoFuerza))) d.vientoFuerza = Number(e.vientoFuerza);
  if (Number.isFinite(Number(e.lluviaFuerza))) d.lluviaFuerza = Number(e.lluviaFuerza);
  if (Number.isFinite(Number(e.nieveFuerza)))  d.nieveFuerza  = Number(e.nieveFuerza);

  const dur = Math.max(1, Math.min(1440, Number(e.minutos) || 5)) * 60000;
  d.hasta   = new Date(ahora + dur);
  d.proximo = new Date(ahora + dur);
  d.actual  = e.que;
  return d;
}

/**
 * Hace avanzar el sorteo del modo automático si toca.
 *
 * Se llama desde la propia consulta en vez de con un temporizador: así no hay
 * un trabajo periódico corriendo para nada cuando no hay nadie jugando, y el
 * resultado es el mismo porque lo único que importa es qué se ve cuando
 * alguien mira.
 */
async function climaAvanzar(d) {
  if (!d.activo) return d;
  const ahora = Date.now();
  // Si algo cambia hay que GUARDARLO, no solo anunciarlo. Ver más abajo.
  let sucio = false;
  // Para avisar solo si de verdad cambia algo: si no, cada consulta soltaría
  // un evento a todos los jugadores para decirles lo mismo.
  const antes = climaHuella(d);

  // ¿Se acabó lo que había?
  const seAcabo = d.hasta && ahora >= new Date(d.hasta).getTime();
  if (seAcabo) {
    d.viento = false;
    d.lluvia = false;
    d.nieve = false;
    d.soleado = false;
    d.hasta = null;
    d.actual = null;
    d.actualDeCola = false;
    sucio = true;
  }

  /* LA COLA VA PRIMERO.

     Si hay algo apuntado y no hay nada en curso, entra el siguiente. Va antes
     del sorteo a propósito: una programación hecha a mano no debe pisarla el
     azar, y funciona igual en automático que en manual — el administrador que
     programa una lista quiere que se cumpla, no que dependa del modo. */
  if (!d.hasta && Array.isArray(d.cola) && d.cola.length) {
    const e = d.cola.shift();
    climaAplicarEntrada(d, e.toObject ? e.toObject() : e, ahora);
    d.actualDeCola = true;
    await d.save();
    if (climaHuella(d) !== antes) { climaRev++; climaEmitir(d); }
    return d;
  }

  if (d.modo !== 'auto') {
    if (seAcabo) {
      await d.save();
      if (climaHuella(d) !== antes) { climaRev++; climaEmitir(d); }
    }
    return d;
  }

  if (!d.proximo || ahora >= new Date(d.proximo).getTime()) {
    sucio = true;
    // Solo se sortea si no hay nada en curso: si no, un sorteo cortaría la
    // tormenta a la mitad.
    if (!d.hasta) {
      const dur = (d.duracionMin +
                   Math.random() * Math.max(0, d.duracionMax - d.duracionMin)) * 60000;
      const r = Math.random();
      if (r < d.probLluvia) {
        d.lluvia = true;
        d.viento = Math.random() < 0.6;      // casi siempre llueve con viento
        d.hasta = new Date(ahora + dur);
        d.actual = d.viento ? 'tormenta' : 'lluvia';
      } else if (r < d.probLluvia + d.probViento) {
        d.viento = true;
        d.lluvia = false;
        d.hasta = new Date(ahora + dur);
        d.actual = 'viento';
      } else if (r < d.probLluvia + d.probViento + (d.probNieve || 0)) {
        d.nieve = true;
        d.viento = Math.random() < 0.4;      // la nieve con poco viento
        d.hasta = new Date(ahora + dur);
        d.actual = 'nieve';
      }
    }
    d.proximo = new Date(ahora + d.minutosSorteo * 60000);
  }
  /* SE GUARDA SI HA CAMBIADO ALGO, PASE POR DONDE PASE.

     FALLO QUE ESTO ARREGLA (tormenta de avisos + base de datos que no avanza):
     el `d.save()` estaba DENTRO del `if` del sorteo. Si lo que había puesto se
     acababa pero todavía no tocaba sortear, se limpiaba el documento EN
     MEMORIA, se avisaba a todos los jugadores… y no se guardaba. En la
     siguiente consulta el documento se leía otra vez de Mongo con el `hasta`
     viejo ya vencido, se volvía a limpiar y se volvía a avisar a todo el mundo.
     Un aviso a todos los jugadores POR CADA CONSULTA, para siempre. */
  if (sucio) await d.save();
  if (climaHuella(d) !== antes) { climaRev++; climaEmitir(d); }
  return d;
}

/**
 * Qué estación es.
 *
 * En 'auto' sale del mes real del servidor, para que el mundo acompañe al año
 * de verdad sin que nadie tenga que tocarlo. El administrador puede clavarla.
 */
function estacionDe(d) {
  if (d.estacion && d.estacion !== 'auto') return d.estacion;
  const m = new Date().getMonth();               // 0 = enero
  if (m <= 1 || m === 11) return 'invierno';
  if (m <= 4) return 'primavera';
  if (m <= 7) return 'verano';
  return 'otono';
}

/** Lo que se le manda al juego. */
function climaPublico(d) {
  const encendido = !!d.activo;
  return {
    ok: true,
    activo: encendido,
    modo: d.modo,
    viento: encendido && !!d.viento,
    vientoFuerza: d.vientoFuerza,
    lluvia: encendido && !!d.lluvia,
    lluviaFuerza: d.lluviaFuerza,
    truenos: encendido && !!d.truenos,
    nieve: encendido && !!d.nieve,
    nieveFuerza: d.nieveFuerza,
    soleado: encendido && !!d.soleado,
    soleadoFuerza: d.soleadoFuerza,
    estacion: estacionDe(d),
    // Cuántos climas quedan apuntados: el juego no necesita la lista, solo
    // saber que hay programación por delante.
    enCola: (d.cola || []).length,
    // Cuándo acaba y cuándo se vuelve a mirar, para que el cliente no pregunte
    // más de lo necesario.
    hasta: d.hasta ? new Date(d.hasta).toISOString() : null,
    proximo: d.proximo ? new Date(d.proximo).toISOString() : null,
    /* NÚMERO DE VERSIÓN. Sirve para una cosa muy concreta: distinguir "el
       servidor dice que no hace nada" de "me están sirviendo una respuesta
       vieja". Si el panel guarda un cambio y el juego sigue viendo el mismo
       `rev`, lo que hay en medio es una caché, no un fallo del clima. */
    rev: climaRev,
    ahora: Date.now()
  };
}

/**
 * Avisa a TODOS los que estén jugando del tiempo que hace AHORA.
 *
 * EL FALLO QUE ARREGLA: el juego solo preguntaba el tiempo cada 3 minutos. Se
 * cambiaba algo en climas.html, se guardaba, y los jugadores seguían con el
 * tiempo viejo hasta que recargaban la página. Ahora el cambio sale empujado
 * por el mismo socket que ya usa el juego y entra al momento; la consulta
 * periódica se queda solo de red de seguridad para quien tenga el socket
 * caído.
 *
 * Va a todo el mundo (io.emit, no io.to): el clima es del MUNDO, no de una
 * sala ni de un canal.
 */
function climaEmitir(d) {
  try {
    // typeof y no `io` a secas: en las pruebas este trozo se ejecuta aislado,
    // sin socket, y `io` a pelo lanzaria ReferenceError y ensuciaria la salida
    // con un aviso por cada llamada.
    if (typeof io !== 'undefined' && io && io.emit) {
      io.emit('worldWeather', climaPublico(d));
    }
  } catch (err) {
    console.warn('🌦️  no se pudo avisar del clima:', err && err.message);
  }
}

/** Lo que de verdad se ve, para saber si hace falta avisar. */
function climaHuella(d) {
  return [d.activo, d.modo, d.viento, d.lluvia, d.truenos, d.nieve, d.soleado,
          d.vientoFuerza, d.lluviaFuerza, d.nieveFuerza, d.soleadoFuerza,
          d.estacion, (d.cola || []).length].join('|');
}

// ── GET /api/world/weather ──────────────────────────────────────────────────
// Público como /api/world/time: lo pide el juego en cada escena.
app.get('/api/world/weather', apiLimiter, async (req, res) => {
  try {
    /* NADIE PUEDE GUARDARSE ESTA RESPUESTA.

       FALLO QUE ESTO ARREGLA — "guardo un clima manual en climas.html, la
       página dice que se aplicó y en el juego no pasa nada": esta ruta
       respondía un 200 normal y corriente, sin cabeceras de caché. Cualquier
       intermediario (Cloudflare delante de api.grasslandforest.com, un proxy,
       el propio navegador) puede guardarse una respuesta así y seguir
       sirviéndola durante minutos. El cliente ya pedía `cache: 'no-store'`,
       pero eso solo manda sobre SU caché, no sobre la del intermediario: quien
       tiene que decirlo es el servidor. `/api/world/time` ya lo hacía. */
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.set('Pragma', 'no-cache');
    const d = await climaAvanzar(await climaDoc());
    return res.json(climaPublico(d));
  } catch (err) {
    console.error('GET /api/world/weather:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── GET /api/admin/weather ──────────────────────────────────────────────────
// La configuración completa, solo para el panel.
app.get('/api/admin/weather', adminAuth, async (req, res) => {
  try {
    const d = await climaAvanzar(await climaDoc());
    // (la cola viaja dentro de `config`, ver más abajo)
    const o = d.toObject();
    delete o._id;
    return res.json({ ok: true, config: o, publico: climaPublico(d) });
  } catch (err) {
    console.error('GET /api/admin/weather:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/admin/weather ─────────────────────────────────────────────────
// Guarda la configuración. Solo se aceptan los campos conocidos y dentro de
// rango: lo que llegue de más se ignora.
const CLIMA_BOOL = ['activo', 'viento', 'lluvia', 'truenos', 'nieve', 'soleado'];
const CLIMA_NUM = {
  vientoFuerza:  [0.2, 2],
  lluviaFuerza:  [0.2, 2],
  nieveFuerza:   [0.2, 2],
  soleadoFuerza: [0.2, 2],
  probViento:    [0, 1],
  probLluvia:    [0, 1],
  probNieve:     [0, 1],
  // Hasta un día entero: el panel ya no recorta lo que se escribe.
  minutosSorteo: [1, 1440],
  duracionMin:   [1, 1440],
  duracionMax:   [1, 1440]
};
const CLIMA_ESTACIONES = ['auto', 'primavera', 'verano', 'otono', 'invierno'];
const CLIMA_QUE = ['viento', 'lluvia', 'tormenta', 'nieve', 'soleado', 'despejado'];

app.post('/api/admin/weather', adminAuth, strictLimiter, csrfProtection, async (req, res) => {
  try {
    const d = await climaDoc();
    const b = req.body || {};

    for (const k of CLIMA_BOOL) {
      if (typeof b[k] === 'boolean') d[k] = b[k];
    }
    for (const [k, [min, max]] of Object.entries(CLIMA_NUM)) {
      if (b[k] === undefined || b[k] === null) continue;
      const n = Number(b[k]);
      if (!Number.isFinite(n)) continue;
      d[k] = Math.min(max, Math.max(min, n));
    }
    if (b.modo === 'auto' || b.modo === 'manual') d.modo = b.modo;
    if (CLIMA_ESTACIONES.indexOf(b.estacion) >= 0) d.estacion = b.estacion;

    // duracionMax nunca por debajo de duracionMin: si no, el sorteo daría
    // duraciones negativas y la tormenta acabaría antes de empezar.
    if (d.duracionMax < d.duracionMin) d.duracionMax = d.duracionMin;

    /* En MANUAL el administrador manda: se borra el reloj del sorteo para que
       lo que ha puesto no se lo lleve por delante el automático dos minutos
       después. */
    if (d.modo === 'manual') { d.hasta = null; d.proximo = null; }

    d.actualizadoPor = (req.user && req.user.address) || null;
    d.updatedAt = new Date();
    await d.save();
    climaRev++;

    console.log(`🌦️  Clima actualizado por ${d.actualizadoPor}: ` +
                `${d.activo ? d.modo : 'apagado'} · viento=${d.viento} lluvia=${d.lluvia}`);
    // Al momento, sin esperar a que nadie pregunte.
    climaEmitir(d);
    const o = d.toObject(); delete o._id;
    return res.json({ ok: true, config: o, publico: climaPublico(d) });
  } catch (err) {
    console.error('POST /api/admin/weather:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

/* ════════════════════ COLA DE CLIMAS PROGRAMADOS ═══════════════════════════

   El administrador apunta "lluvia 20 min", luego "tormenta 5 min", y se van
   poniendo uno detrás de otro conforme acaba lo anterior. Ver climaAvanzar:
   la cola manda sobre el sorteo automático.                                  */

// ── POST /api/admin/weather/queue ───────────────────────────────────────────
// body: { que, minutos, vientoFuerza?, lluviaFuerza?, nieveFuerza?, truenos?,
//         alPrincipio? }
app.post('/api/admin/weather/queue', adminAuth, strictLimiter, csrfProtection, async (req, res) => {
  try {
    const b = req.body || {};
    const que = String(b.que || '').toLowerCase();
    if (CLIMA_QUE.indexOf(que) < 0) return res.status(400).json({ error: 'que_invalido' });

    const minutos = Math.floor(Number(b.minutos));
    if (!Number.isFinite(minutos) || minutos < 1 || minutos > 1440) {
      return res.status(400).json({ error: 'minutos_invalidos', min: 1, max: 1440 });
    }

    const d = await climaDoc();
    if (!Array.isArray(d.cola)) d.cola = [];
    // Un tope sano: la cola es una lista de trabajo, no un almacén.
    if (d.cola.length >= 40) return res.status(409).json({ error: 'cola_llena', max: 40 });

    const nl = (v, def) => {
      const n = Number(v);
      return Number.isFinite(n) ? Math.min(2, Math.max(0.2, n)) : def;
    };
    const entrada = {
      que, minutos,
      vientoFuerza: nl(b.vientoFuerza, d.vientoFuerza),
      lluviaFuerza: nl(b.lluviaFuerza, d.lluviaFuerza),
      nieveFuerza:  nl(b.nieveFuerza,  d.nieveFuerza),
      soleadoFuerza: nl(b.soleadoFuerza, d.soleadoFuerza),
      truenos: typeof b.truenos === 'boolean' ? b.truenos : !!d.truenos,
      creadoPor: (req.user && req.user.address) || null,
      creadoEn: new Date()
    };
    if (b.alPrincipio) d.cola.unshift(entrada); else d.cola.push(entrada);

    d.actualizadoPor = (req.user && req.user.address) || null;
    await d.save();
    console.log(`🌦️  En cola: ${que} ${minutos} min (${d.cola.length} esperando)`);

    /* Si no hay nada puesto ahora mismo, que entre YA en vez de esperar a que
       alguien consulte: el administrador acaba de programarlo y quiere verlo. */
    const tras = await climaAvanzar(d);
    climaEmitir(tras);
    return res.json({ ok: true, cola: tras.cola, publico: climaPublico(tras) });
  } catch (err) {
    console.error('POST /api/admin/weather/queue:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── DELETE /api/admin/weather/queue/:id ─────────────────────────────────────
// Quita una entrada. Con id = 'all' se vacía la cola entera.
app.delete('/api/admin/weather/queue/:id', adminAuth, strictLimiter, csrfProtection, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const d = await climaDoc();
    if (!Array.isArray(d.cola)) d.cola = [];

    if (id === 'all') {
      d.cola = [];
    } else {
      const antes = d.cola.length;
      d.cola = d.cola.filter(e => String(e._id) !== id);
      if (d.cola.length === antes) return res.status(404).json({ error: 'no_esta_en_la_cola' });
    }
    d.actualizadoPor = (req.user && req.user.address) || null;
    await d.save();
    climaEmitir(d);
    return res.json({ ok: true, cola: d.cola, publico: climaPublico(d) });
  } catch (err) {
    console.error('DELETE /api/admin/weather/queue:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/admin/weather/queue/next ──────────────────────────────────────
// Corta lo que hay puesto y salta al siguiente de la cola.
app.post('/api/admin/weather/queue/next', adminAuth, strictLimiter, csrfProtection, async (req, res) => {
  try {
    const d = await climaDoc();
    d.hasta = null;                       // se da por acabado lo de ahora
    const tras = await climaAvanzar(d);
    climaEmitir(tras);
    return res.json({ ok: true, cola: tras.cola, publico: climaPublico(tras) });
  } catch (err) {
    console.error('POST /api/admin/weather/queue/next:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/admin/weather/test ────────────────────────────────────────────
// Lanza algo AHORA sin tocar la configuración: para probarlo desde el panel.
app.post('/api/admin/weather/test', adminAuth, strictLimiter, csrfProtection, async (req, res) => {
  try {
    const d = await climaDoc();
    const que = String((req.body && req.body.que) || '').toLowerCase();
    // Hasta un día entero. Antes el tope eran 60 minutos y el panel mandaba
    // siempre 4: no había forma de pedir "lluvia durante 20 minutos".
    const minutos = Math.min(1440, Math.max(1, Number(req.body && req.body.minutos) || 3));
    if (CLIMA_QUE.indexOf(que) < 0) return res.status(400).json({ error: 'que_invalido' });

    climaAplicarEntrada(d, {
      que: que, minutos: minutos,
      vientoFuerza: req.body && req.body.vientoFuerza,
      lluviaFuerza: req.body && req.body.lluviaFuerza,
      nieveFuerza:  req.body && req.body.nieveFuerza,
      soleadoFuerza: req.body && req.body.soleadoFuerza,
      truenos:      req.body && req.body.truenos
    });
    d.actualDeCola = false;
    // "Despejado" no tiene sentido que caduque a un rato y vuelva lo anterior.
    if (que === 'despejado') { d.hasta = null; d.proximo = null; }
    d.actualizadoPor = (req.user && req.user.address) || null;
    await d.save();
    climaRev++;
    console.log(`🌦️  Prueba de clima: ${que} durante ${minutos} min`);
    climaEmitir(d);
    return res.json({ ok: true, publico: climaPublico(d) });
  } catch (err) {
    console.error('POST /api/admin/weather/test:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// Misiones diarias
// FIX: ':date?' (parámetro opcional al final) usa una sintaxis que solo
// entiende el path-to-regexp viejo que trae Express 4 (0.1.x). En Express 5
// (path-to-regexp 8.x) esa misma sintaxis lanza un error real al arrancar
// ("Unexpected ? at index..."), y la alternativa moderna con llaves
// ("{/:date}") es al revés: no explota en Express 4, pero tampoco matchea
// nada ahí (queda en 404 silencioso). No hay una sola sintaxis que sirva
// igual en ambas versiones, así que se registran dos rutas simples (sin
// parámetro opcional) apuntando al mismo handler — eso sí es idéntico en
// las dos.
async function getDailyMissionsHandler(req, res) {
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
app.get('/api/missions/daily/:npcId', apiLimiter, authMiddleware, getDailyMissionsHandler);
app.get('/api/missions/daily/:npcId/:date', apiLimiter, authMiddleware, getDailyMissionsHandler);

// ============================================================================
// POST /api/missions/daily/complete — ENTREGAR UNA MISIÓN        (2026-08-05)
// ----------------------------------------------------------------------------
// ESTA RUTA NO EXISTÍA. El cliente (GameScene.completeMission) llevaba desde
// siempre llamándola al pulsar "HAND IN", así que el botón SIEMPRE respondía
// 404 → "Error completing mission. Please try again.".
//
// Y lo peor: el cliente quitaba los ítems del inventario ANTES de llamar y los
// guardaba con /api/save. Como la llamada fallaba después, el jugador perdía
// los materiales y no recibía nada (justo lo que se ve en las capturas: 5/5 →
// 1/5 y ninguna recompensa).
//
// La ruta nueva es SERVIDOR-AUTORITATIVA de principio a fin:
//   1. valida la misión y que no esté ya entregada,
//   2. comprueba los materiales en el inventario GUARDADO (no en el que dice
//      el cliente),
//   3. los QUEMA en la cadena (burnItemOnChain) y los descuenta de Mongo,
//   4. paga la experiencia en su factura (applyStatOnChain) y ACUÑA el ítem de
//      recompensa,
//   5. marca el progreso del día.
// Si algo falla antes del paso 3 no se toca nada. El cliente ya no borra nada
// por su cuenta: recarga el inventario desde aquí.
// ============================================================================

// itemId del juego → `tipo` del contrato. Copia EXACTA de ItemDefinitions en
// Scenes/GameScene.js: si aquí se pusiera 'madera_pinos' en vez de
// 'madera pinos', el servidor buscaría facturas que no existen y creería que el
// jugador no tiene nada.
const ITEM_TIPO_MAP = {
  Semillax: 'bolsa zanahorias', Semillax1: 'bolsa de tomates',
  Semillax2: 'bolsa de trigo',  Semillax3: 'bolsa de calabazas',
  Semillax4: 'bolsa_de_fresas',

  Regaderax: 'Regaderax', Tijerasx: 'Tijerasx',

  mineral_piedra: 'mineral_piedra', mineral_cobre: 'mineral_cobre',
  mineral_hierro: 'mineral_hierro', carbon: 'carbon',

  palo: 'palo', tablon_de_madera: 'tablon_de_madera',
  madera_pinos: 'madera pinos', madera_con_hojas: 'madera con hojas',
  madera_seca: 'madera seca',

  balde_vacio: 'balde_vacio', balde_con_agua: 'balde_con_agua',

  hacha_de_madera: 'hacha de madera', hacha_de_piedra: 'hacha de piedra',
  hacha_de_cobre:  'hacha de cobre',  hacha_de_hierro: 'hacha de hierro',
  pico_de_madera:  'pico de madera',  pico_de_piedra:  'pico de piedra',
  pico_de_cobre:   'pico de cobre',   pico_de_hierro:  'pico de hierro',

  zanahoria_buena: 'zanahoria_buena', zanahoria_corta: 'zanahoria_corta', zanahoria_mala: 'zanahoria_mala',
  tomate_buena:    'tomate_buena',    tomate_corta:    'tomate_corta',    tomate_mala:    'tomate_mala',
  trigo_buena:     'trigo_buena',     trigo_corta:     'trigo_corta',     trigo_mala:     'trigo_mala',
  calabaza_buena:  'calabaza_buena',  calabaza_corta:  'calabaza_corta',  calabaza_mala:  'calabaza_mala',
  fresa_buena:     'fresa_buena',     fresa_corta:     'fresa_corta',     fresa_mala:     'fresa_mala',

  // Alquimista: pociones para la mascota y elixir para revivirla. Al estar
  // aqui, sus tablas on-chain se aprovisionan solas como las de cualquier
  // otro item del juego.
  pocion_mascota:        'pocion_mascota',
  pocion_mascota_grande: 'pocion_mascota_grande',
  elixir_revivir:        'elixir_revivir',
};

function itemTipoOnChain(itemId) {
  return ITEM_TIPO_MAP[String(itemId || '')] || null;
}

// Tope de stack por ítem (mismo criterio que ItemDefinitions.maxStack). Se usa
// para repartir la recompensa entre casillas del inventario guardado.
const ITEM_MAX_STACK = {
  Semillax: 50, Semillax1: 50, Semillax2: 50, Semillax3: 50, Semillax4: 50,

  // Pociones del alquimista: se apilan poco, son consumibles caros.
  pocion_mascota: 20, pocion_mascota_grande: 10, elixir_revivir: 5,
  Regaderax: 1, Tijerasx: 1,
  mineral_piedra: 20, mineral_cobre: 20, mineral_hierro: 20, carbon: 20,
  palo: 20, tablon_de_madera: 20,
  madera_pinos: 50, madera_con_hojas: 50, madera_seca: 50,
  balde_vacio: 5, balde_con_agua: 5,
  hacha_de_madera: 5, hacha_de_piedra: 5, hacha_de_cobre: 5, hacha_de_hierro: 5,
  pico_de_madera: 5, pico_de_piedra: 5, pico_de_cobre: 5, pico_de_hierro: 5,
  zanahoria_buena: 20, zanahoria_corta: 20, zanahoria_mala: 20,
  tomate_buena: 20, tomate_corta: 20, tomate_mala: 20,
  trigo_buena: 20, trigo_corta: 20, trigo_mala: 20,
  calabaza_buena: 20, calabaza_corta: 20, calabaza_mala: 20,
  fresa_buena: 20, fresa_corta: 20, fresa_mala: 20,
};

// =============================================================================
// CUPO DE LAS TABLAS DE ÍTEM EN EL CONTRATO
// -----------------------------------------------------------------------------
// BUG QUE ESTO ARREGLA — "al minar carbón fallan las transacciones":
//
// En el ItemContract cada `tipo` (carbon, mineral_hierro, "madera pinos"…) es
// una TABLA con dos topes: `limit` (cuántas unidades pueden existir en total en
// todo el juego) y `perInvoiceLimit` (cuántas caben en una sola factura). Si la
// tabla no está dada de alta o se quedó sin cupo, `createInvoice` trunca la
// cantidad y `increaseInvoiceQuantity` revierte con ExceedsTipoLimit.
//
// Para las barras del jugador (vida, agua, comida, oro, plata, exp) esto ya se
// vigilaba con ensureStatTipo() — de hecho fue justo el fallo que dejaba a la
// gente con "agua 12 %". Para los ÍTEMS no lo vigilaba NADIE. Los tipos que se
// dieron de alta a mano al desplegar funcionan; los que se quedaron fuera (o los
// que agoten su cupo con el tiempo) fallan siempre, y desde el juego se ve como
// "Could not confirm the on-chain transaction" cada vez que se pica ese
// mineral. El carbón es el caso que se nota porque solo sale de dos rocas.
//
// Aquí se hace lo mismo que con las barras: antes de firmar una acuñación, se
// mira la tabla y, si hace falta, el relayer (que es admin del contrato) la
// prepara con setLimit. Es idempotente y se cachea, así que en marcha normal no
// añade ni una lectura.
//
// SEGURIDAD: solo se preparan tipos de la LISTA BLANCA (los valores de
// ITEM_TIPO_MAP, que son los ítems reales del juego). Un cliente manipulado que
// pida acuñar un tipo inventado no consigue que se le dé de alta: la
// transacción sigue su curso y revierte como antes.
// =============================================================================
const ITEM_TIPO_CACHE_TTL_MS = 5 * 60 * 1000;
const ITEM_TIPO_HEADROOM     = 1_000_000;  // unidades libres que se quieren tener
const ITEM_TIPO_RAISE_FACTOR = 10;         // al ampliar se deja headroom × esto
const _itemTipoCache = new Map();          // tipo → { at: ms, ok: bool }
let _tiposItemPermitidos = null;

function tiposDeItemPermitidos() {
  if (!_tiposItemPermitidos) {
    _tiposItemPermitidos = new Set(Object.values(ITEM_TIPO_MAP));
  }
  return _tiposItemPermitidos;
}

/** maxStack del ítem cuyo `tipo` on-chain es el dado (50 por defecto). */
function stackMaximoDelTipo(tipo) {
  for (const [itemId, t] of Object.entries(ITEM_TIPO_MAP)) {
    if (t === tipo) return Number(ITEM_MAX_STACK[itemId]) || 50;
  }
  return 50;
}

/**
 * Se asegura de que la tabla `tipo` exista y tenga cupo para acuñar `cantidad`.
 * No lanza nunca: si algo falla, se registra y la transacción sigue su camino
 * (fallará como fallaba antes, pero no por culpa de esta comprobación).
 */
async function ensureItemTipoOnChain(contract, tipo, cantidad) {
  if (!relayerWallet || !tipo) return;
  if (!tiposDeItemPermitidos().has(tipo)) return;      // lista blanca
  if (typeof contract.getTipoStats !== 'function') return;

  const cache = _itemTipoCache.get(tipo);
  if (cache && cache.ok && (Date.now() - cache.at) < ITEM_TIPO_CACHE_TTL_MS) return;

  const perInvoiceObjetivo = Math.max(stackMaximoDelTipo(tipo), 50);
  const necesitaAhora      = Math.max(Number(cantidad) || 0, 1);

  let info;
  try {
    const ts = await contract.getTipoStats(tipo);
    info = {
      totalQuantity:   Number(ts.totalQuantity   ?? ts[0] ?? 0),
      limit:           Number(ts.limit           ?? ts[1] ?? 0),
      perInvoiceLimit: Number(ts.perInvoiceLimit ?? ts[2] ?? 0),
      exists:          Boolean(ts.exists !== undefined ? ts.exists : ts[5])
    };
  } catch (e) {
    console.warn(`⚠️  ensureItemTipoOnChain[${tipo}]: getTipoStats falló:`, e.message);
    return;
  }

  const libre            = info.limit > info.totalQuantity ? info.limit - info.totalQuantity : 0;
  const faltaPerInvoice  = info.perInvoiceLimit < perInvoiceObjetivo;
  const faltaCupoGlobal  = libre < Math.max(necesitaAhora, ITEM_TIPO_HEADROOM / 100);

  if (info.exists && !faltaPerInvoice && !faltaCupoGlobal) {
    _itemTipoCache.set(tipo, { at: Date.now(), ok: true });
    return;
  }

  if (typeof contract.setLimit !== 'function') {
    console.warn(`⚠️  Tabla [${tipo}] corta y el ABI no expone setLimit — no se puede ampliar`);
    return;
  }

  const nuevoPerInvoice = Math.max(perInvoiceObjetivo, info.perInvoiceLimit);
  const nuevoLimit      = Math.max(
    info.limit,
    info.totalQuantity + ITEM_TIPO_HEADROOM * ITEM_TIPO_RAISE_FACTOR,
    nuevoPerInvoice
  );

  try {
    const nonce = await relayerNonceManager.getNextNonce();
    console.log(
      `🧾 setLimit[${tipo}]: limit ${info.limit}→${nuevoLimit}, ` +
      `perInvoice ${info.perInvoiceLimit}→${nuevoPerInvoice}` +
      (info.exists ? '' : ' (tabla NUEVA — nunca se había dado de alta)')
    );
    const tx = await contract.setLimit(tipo, nuevoLimit, nuevoPerInvoice, {
      gasPrice: gatherGasPrice(), nonce
    });
    await tx.wait();
    console.log(`✅ Tabla de ítem [${tipo}] lista: limit=${nuevoLimit} perInvoice=${nuevoPerInvoice}`);
    _itemTipoCache.set(tipo, { at: Date.now(), ok: true });
  } catch (e) {
    // Lo más probable: el relayer no es admin del contrato. Se avisa claro,
    // porque es una intervención manual (setLimit desde el owner).
    console.error(
      `❌ setLimit[${tipo}] falló (¿el relayer es admin del ItemContract?):`, e.message
    );
    try { await relayerNonceManager.resetNonce(); } catch (_) {}
    _itemTipoCache.set(tipo, { at: Date.now(), ok: false });
  }
}

/**
 * Extrae el `tipo` y la cantidad de la transacción que va a firmar el relay y,
 * si es una acuñación, prepara su tabla. Cualquier otra función pasa de largo.
 */
async function ensureItemTipoParaTransaccion(contract, functionName, parameters) {
  try {
    const args = Array.isArray(parameters) ? parameters : Object.values(parameters || {});
    let tipo = null;
    let cantidad = 0;

    if (functionName === 'createInvoice') {
      // createInvoice(owner, tipo, cantidad, manualId)
      tipo     = String(args[1] || '');
      cantidad = Number(args[2]) || 0;
    } else if (functionName === 'increaseInvoiceQuantity') {
      // increaseInvoiceQuantity(id, cantidad) → el tipo hay que leerlo
      cantidad = Number(args[1]) || 0;
      const id = Number(args[0]);
      if (id > 0) {
        try {
          const inv = await contract.getInvoice(id);
          tipo = String(inv.tipo || '');
        } catch (_) { /* si no se puede leer, se sigue sin preparar nada */ }
      }
    } else {
      return;
    }

    if (tipo) await ensureItemTipoOnChain(contract, tipo, cantidad);
  } catch (e) {
    console.warn('⚠️  ensureItemTipoParaTransaccion:', e.message);
  }
}

// itemId "suelto" de una misión → id real del inventario. Copia del
// MISSION_ITEM_MAP del cliente, para que panel y servidor no discrepen.
const MISSION_ITEM_ALIASES = {
  zanahoria: 'zanahoria_buena', carrot: 'zanahoria_buena',
  tomate: 'tomate_buena',       tomato: 'tomate_buena',
  trigo: 'trigo_buena',         wheat:  'trigo_buena',
  calabaza: 'calabaza_buena',   pumpkin:'calabaza_buena',
  fresa: 'fresa_buena',         strawberry: 'fresa_buena',
  piedra: 'mineral_piedra',     stone:  'mineral_piedra',
  cobre: 'mineral_cobre',       copper: 'mineral_cobre',
  hierro: 'mineral_hierro',     iron:   'mineral_hierro',
  carbon: 'carbon',             coal:   'carbon',
  madera: 'madera_pinos',       wood:   'madera_pinos',
};

function resolveMissionItemId(itemId) {
  const raw = String(itemId || '').trim();
  return MISSION_ITEM_ALIASES[raw] || MISSION_ITEM_ALIASES[raw.toLowerCase()] || raw;
}

/** Suma cuántas unidades de `itemId` hay en un array guardado (inventory/chest). */
function contarEnSlots(slots, itemId) {
  if (!Array.isArray(slots)) return 0;
  const objetivo = String(itemId).toLowerCase();
  let total = 0;
  for (const s of slots) {
    if (!s || !s.objeto) continue;
    if (String(s.objeto).toLowerCase() !== objetivo) continue;
    total += Math.max(0, parseInt(s.cantidad, 10) || 0);
  }
  return total;
}

// OJO CON LA FORMA DE ESTOS ARRAYS. `GamePlayer.inventory` / `.chest` NO son
// listas de 40 y 7 posiciones: /api/save descarta las casillas sin IDX y sin
// Manualid, así que lo que queda guardado es una lista DISPERSA en la que cada
// entrada lleva su número de casilla en `id`. Por eso "buscar una casilla
// libre" es buscar un número de casilla que no esté usado, no un hueco `null`.
const INV_SLOTS   = 40;
const CHEST_SLOTS = 7;

/**
 * Descuenta `cantidad` unidades de `itemId` de los arrays guardados
 * (primero el cofre/quickslots y luego el inventario, igual que el cliente).
 * Las casillas que quedan a cero se ELIMINAN de la lista, para que su número
 * vuelva a estar libre y no arrastren el IDX de una factura ya quemada.
 *
 * @returns {{descontadas:number, inventory:Array, chest:Array}} listas nuevas
 */
function descontarDeSlots(chest, inventory, itemId, cantidad) {
  const objetivo = String(itemId).toLowerCase();
  let restante = cantidad;

  const barrer = (arr) => {
    if (!Array.isArray(arr)) return [];
    const salida = [];
    for (const s of arr) {
      if (!s || !s.objeto || restante <= 0 || String(s.objeto).toLowerCase() !== objetivo) {
        salida.push(s);
        continue;
      }
      const hay = Math.max(0, parseInt(s.cantidad, 10) || 0);
      if (hay <= 0) continue; // casilla basura: se tira
      const quitar = Math.min(hay, restante);
      restante -= quitar;
      const quedan = hay - quitar;
      if (quedan > 0) { s.cantidad = quedan; salida.push(s); }
      // quedan === 0 → la entrada desaparece y su número de casilla se libera
    }
    return salida;
  };

  const chestOut = barrer(chest);
  const invOut   = barrer(inventory);
  return { descontadas: cantidad - restante, inventory: invOut, chest: chestOut };
}

/**
 * Mete `cantidad` unidades de `itemId` en el inventario guardado: primero
 * completa stacks del mismo ítem y luego ocupa números de casilla libres.
 *
 * @returns {{metidas:number, inventory:Array}}
 */
function agregarASlots(inventory, itemId, cantidad, { invoiceId = null, manualId = null } = {}) {
  const lista = Array.isArray(inventory) ? inventory.slice() : [];
  if (cantidad <= 0) return { metidas: 0, inventory: lista };

  const maxStack = ITEM_MAX_STACK[itemId] || 20;
  const objetivo = String(itemId).toLowerCase();
  let restante = cantidad;

  // 1) Completar stacks que ya existen de ese ítem.
  for (const s of lista) {
    if (restante <= 0) break;
    if (!s || !s.objeto || String(s.objeto).toLowerCase() !== objetivo) continue;
    const hay = Math.max(0, parseInt(s.cantidad, 10) || 0);
    const hueco = maxStack - hay;
    if (hueco <= 0) continue;
    const meter = Math.min(hueco, restante);
    s.cantidad = hay + meter;
    restante  -= meter;
  }

  /* 2) Abrir stacks nuevos en los números de casilla que estén libres.

     QUÉ CUENTA COMO OCUPADA — Y EL FALLO QUE ARREGLA.

     "Mi inventario tiene como 3 espacios, ¿por qué dice que la bolsa está
     llena?". Una casilla se daba por ocupada con solo tener `objeto` puesto,
     sin mirar la CANTIDAD. Una entrada con `objeto` y `cantidad: 0` es una
     casilla vacía: el juego la pinta vacía y el jugador ve hueco, pero aquí
     bloqueaba el número de casilla y la recompensa se perdía con un
     'inventory_full' que no era verdad.

     Esas entradas basura salen de cualquier camino que deje el contador a cero
     sin borrar la entrada — y el cliente también escribe el inventario, así que
     no basta con arreglar quien lo vacía aquí.

     Ahora: ocupada = tiene objeto Y cantidad > 0. Y al abrir un stack nuevo, si
     ya existe una entrada basura con ese número, se REESCRIBE en vez de añadir
     otra; si no, se acumularían dos entradas con el mismo id y el juego pintaría
     una casilla encima de la otra. */
  const util = (x) => !!(x && x.objeto && (parseInt(x.cantidad, 10) || 0) > 0);
  const ocupadas = new Set(lista.filter(util).map(x => Number(x.id)));

  for (let i = 0; i < INV_SLOTS && restante > 0; i++) {
    if (ocupadas.has(i)) continue;
    const meter = Math.min(maxStack, restante);
    const nueva = {
      id: i,
      IDX: invoiceId,
      Manualid: manualId,
      objeto: itemId,
      cantidad: meter,
      tipo: 'inventario'
    };
    const basura = lista.findIndex(x => x && Number(x.id) === i && !util(x));
    if (basura >= 0) lista[basura] = nueva; else lista.push(nueva);
    ocupadas.add(i);
    restante -= meter;
  }

  /* Y de paso se barre lo que quede vacío: mantenerlo no sirve para nada y es
     lo que ha ido llenando la bolsa de fantasmas. Las entradas SIN `objeto` se
     respetan, que son las casillas normales que el cliente guarda vacías. */
  const limpia = lista.filter(x => !x || !x.objeto || util(x));

  return { metidas: cantidad - restante, inventory: limpia };
}

app.post('/api/missions/daily/complete',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  body('npcId').isString().notEmpty(),
  body('missionId').isString().notEmpty(),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const address = req.user.address.toLowerCase();
      const auth = await PlayerAuth.findOne({ address }).exec();
      if (!auth || !auth.playerName) return res.status(404).json({ error: 'player_not_found' });
      const playerName = auth.playerName;

      const npcId     = String(req.body.npcId);
      const missionId = String(req.body.missionId);
      const day       = /^\d{4}-\d{2}-\d{2}$/.test(String(req.body.day || ''))
        ? String(req.body.day)
        : new Date().toISOString().split('T')[0];

      if (!MISSION_NPCS.includes(npcId)) return res.status(400).json({ error: 'invalid_npc' });

      // ── 1. La misión existe hoy ──────────────────────────────────────────
      const daily = await DailyMission.findOne({ npcId, day }).lean();
      if (!daily) return res.status(404).json({ error: 'no_missions_today' });

      const mission = (daily.missions || []).find(m => m.missionId === missionId);
      if (!mission) return res.status(404).json({ error: 'mission_not_found' });

      // ── 2. ¿Ya estaba entregada? ─────────────────────────────────────────
      let progress = await UserDailyProgress.findOne({ playerName, npcId, day });
      if (!progress) progress = new UserDailyProgress({ playerName, npcId, day, completedMissions: [], completedCount: 0 });

      if ((progress.completedMissions || []).some(m => m.missionId === missionId)) {
        return res.status(409).json({ error: 'already_completed', completedCount: progress.completedCount });
      }

      // ── 3. ¿Tiene los materiales? (según el inventario GUARDADO) ─────────
      const gp = await GamePlayer.findOne({ playerName });
      if (!gp) return res.status(404).json({ error: 'player_not_found' });

      const itemId   = resolveMissionItemId(mission.itemId);
      const pedido   = Math.max(1, parseInt(mission.requiredAmount, 10) || 1);
      // Copias propias: mongoose no detecta mutaciones dentro de un Array
      // suelto, así que se trabaja aparte y al final se reasigna + markModified.
      let inventory = Array.isArray(gp.inventory) ? gp.inventory.map(s => ({ ...s })) : [];
      let chest     = Array.isArray(gp.chest)     ? gp.chest.map(s => ({ ...s }))     : [];

      const tiene = contarEnSlots(inventory, itemId) + contarEnSlots(chest, itemId);
      if (tiene < pedido) {
        return res.status(400).json({
          error: 'not_enough_items',
          message: `No tienes los items requeridos (${itemId})`,
          itemId, required: pedido, have: tiene
        });
      }

      // ── 4. Quemar los materiales EN LA CADENA ────────────────────────────
      // Primero la cadena y solo después Mongo: si la quema falla, el jugador
      // conserva sus materiales y la misión sigue sin entregar.
      const tipoEntrega = itemTipoOnChain(itemId);
      if (tipoEntrega) {
        const quemadas = await burnItemOnChain(address, tipoEntrega, pedido);
        if (quemadas < pedido) {
          console.error(`❌ misión ${missionId}: solo se quemaron ${quemadas}/${pedido} de ${tipoEntrega}`);
          // Lo ya quemado se descuenta igualmente del inventario guardado, para
          // que Mongo no muestre unos ítems que en la cadena ya no existen.
          if (quemadas > 0) {
            const parcial = descontarDeSlots(chest, inventory, itemId, quemadas);
            gp.inventory = parcial.inventory; gp.chest = parcial.chest;
            gp.markModified('inventory'); gp.markModified('chest');
            await gp.save();
          }
          return res.status(502).json({ error: 'burn_failed', burned: quemadas, required: pedido });
        }
      } else {
        console.warn(`⚠️  misión ${missionId}: '${itemId}' no tiene tipo on-chain, se descuenta solo en BD`);
      }

      const gasto = descontarDeSlots(chest, inventory, itemId, pedido);
      inventory = gasto.inventory;
      chest     = gasto.chest;

      // ── 5. Recompensas ───────────────────────────────────────────────────
      const expReward = Math.max(0, parseInt(mission.expReward, 10) || 0);
      const rewardId  = mission.rewardItemId ? String(mission.rewardItemId) : null;
      const rewardQty = rewardId ? Math.max(1, parseInt(mission.rewardAmount, 10) || 1) : 0;

      const avisos = [];

      // 5a. Experiencia — a su factura (misma vía que el resto del juego).
      let expTotal = Math.max(0, Math.round(Number(gp.nivel_exp || 0)));
      if (expReward > 0) {
        expTotal += expReward;
        gp.nivel_exp = expTotal;
        try {
          const statsDoc = await PlayerStats.findOne({ playerName });
          if (statsDoc) {
            const contract = getStatsContract();
            const invId    = statsDoc.invoiceIds && statsDoc.invoiceIds.exp;
            if (contract && invId) {
              const gasPrice = await getSafeGasPriceStats();
              const r = await applyStatOnChain(contract, 'exp', invId, expTotal, gasPrice);
              statsDoc.exp = r.ok ? expTotal : clampStat('exp', r.chainQty ?? statsDoc.exp);
              if (!r.ok) avisos.push('exp_chain_failed');
            } else {
              statsDoc.exp = expTotal; // sin factura todavía: la creará /sync
            }
            await statsDoc.save();
          }
        } catch (e) {
          console.warn('⚠️  misión: no se pudo llevar la exp a la cadena:', e.message);
          avisos.push('exp_chain_failed');
        }
      }

      // 5a-bis. MONEDAS — misma vía que la experiencia: se suma al total del
      // jugador y se lleva a su factura on-chain. No se "acuñan" como los
      // ítems porque el oro y la plata son estadísticas con factura, no
      // objetos de inventario.
      const oroPremio   = Math.max(0, parseInt(mission.goldReward,   10) || 0);
      const plataPremio = Math.max(0, parseInt(mission.silverReward, 10) || 0);

      // LO PROMETIDO vs LO ENTREGADO.
      // Antes la respuesta devolvía `oroPremio`/`plataPremio` —lo que la misión
      // DECÍA pagar— pasara lo que pasara por debajo. Si la entrega fallaba
      // (sin PlayerStats, sin factura, la cadena rechazando), el jugador veía
      // "success" y un aviso de recompensa que nunca llegó a su saldo: "me
      // quita los requisitos y no me da nada". Ahora se cuenta lo que de
      // verdad se sumó y es ESO lo que se responde.
      let oroEntregado = 0, plataEntregado = 0;

      if (oroPremio > 0 || plataPremio > 0) {
        try {
          // SI NO EXISTE EL DOCUMENTO, SE CREA.
          // Antes un findOne a secas: si el jugador todavía no tenía fila en
          // PlayerStats (cuenta nueva, o creada antes de que existiera esta
          // colección) el premio se descartaba con un 'stats_missing' y el
          // jugador se quedaba sin nada tras haber entregado los materiales.
          // Crearla con los valores por defecto es exactamente lo que hace
          // /sync la primera vez, así que no inventa nada: solo evita perder
          // la recompensa por un documento que aún no estaba.
          let statsDoc = await PlayerStats.findOne({ playerName });
          if (!statsDoc) {
            statsDoc = new PlayerStats({ playerName, address });
            await statsDoc.save();
            console.log(`ℹ️  misión: PlayerStats creado al vuelo para ${playerName}`);
          }
          if (statsDoc) {
            const contract = getStatsContract();
            const gasPrice = (contract) ? await getSafeGasPriceStats() : null;

            for (const [clave, cantidad] of [['oro', oroPremio], ['plata', plataPremio]]) {
              if (cantidad <= 0) continue;

              const total = Math.max(0, Math.round(Number(statsDoc[clave] || 0))) + cantidad;
              const invId = statsDoc.invoiceIds && statsDoc.invoiceIds[clave];

              if (contract && invId) {
                const r = await applyStatOnChain(contract, clave, invId, total, gasPrice);
                statsDoc[clave] = r.ok ? total : (r.chainQty ?? statsDoc[clave]);
                if (!r.ok) avisos.push(clave + '_chain_failed');
              } else {
                // Sin factura todavía: se guarda en Mongo y /sync la creará.
                statsDoc[clave] = total;
              }

              // Solo cuenta como entregado si el total subió de verdad.
              const subio = Math.max(0, Math.round(Number(statsDoc[clave] || 0))) >= total;
              if (subio) {
                if (clave === 'oro')   oroEntregado   = cantidad;
                if (clave === 'plata') plataEntregado = cantidad;
              }

              // GamePlayer guarda una copia para el HUD; se mantiene al día.
              if (clave === 'oro')   gp.moneda       = statsDoc.oro;
              if (clave === 'plata') gp.moneda_plata = statsDoc.plata;
            }
            await statsDoc.save();
          } else {
            avisos.push('stats_missing');
          }
        } catch (e) {
          console.warn('⚠️  misión: no se pudieron entregar las monedas:', e.message);
          avisos.push('coins_failed');
        }
      }

      // 5b. Ítem de recompensa — se ACUÑA y luego entra en el inventario.
      let entregadas = 0;
      if (rewardId && rewardQty > 0) {
        const tipoPremio = itemTipoOnChain(rewardId);
        let acunado = null;
        if (tipoPremio) {
          acunado = await mintGatherReward(address, tipoPremio, rewardQty);
          if (!acunado) avisos.push('reward_mint_failed');
        }
        if (!tipoPremio || acunado) {
          const puesto = agregarASlots(inventory, rewardId, rewardQty, {
            invoiceId: acunado ? acunado.id : null,
            manualId:  acunado ? acunado.manualId : null
          });
          inventory  = puesto.inventory;
          entregadas = puesto.metidas;
          if (entregadas < rewardQty) avisos.push('inventory_full');
        } else {
          // El acuñado falló: la misión se da por entregada (los materiales ya
          // se quemaron) pero el ítem NO llega. Antes esto pasaba en silencio.
          console.error(`❌ misión ${missionId}: no se pudo acuñar la recompensa ` +
                        `${rewardQty}x ${rewardId} (tipo ${tipoPremio}) para ${playerName}`);
        }
      }

      gp.inventory = inventory;
      gp.chest     = chest;
      gp.misiones  = Math.max(0, Number(gp.misiones || 0)) + 1;
      gp.markModified('inventory');
      gp.markModified('chest');
      await gp.save();

      // ── 6. Marcar el progreso del día ────────────────────────────────────
      progress.completedMissions.push({ missionId, completedAt: new Date(), claimedReward: true });
      progress.completedCount  = progress.completedMissions.length;
      progress.lastInteraction = new Date();
      await progress.save();

      console.log(`🎯 ${playerName} entregó '${missionId}' (${npcId}/${day}): -${pedido} ${itemId}, +${expReward} exp` +
                  (rewardId ? `, +${entregadas} ${rewardId}` : ''));

      return res.json({
        success: true,
        missionId,
        completedCount: progress.completedCount,
        rewards: {
          exp: expReward,
          item: rewardId ? { id: rewardId, amount: entregadas } : null,
          // Monedas entregadas (0 si la misión no pagaba en esa moneda). El
          // cliente las usa para el aviso de "has recibido…" y para refrescar
          // el HUD sin tener que volver a pedir las estadísticas.
          gold:   oroEntregado,
          silver: plataEntregado,
          // Lo que la misión prometía, para que el cliente pueda avisar de la
          // diferencia en vez de callársela.
          goldPrometido:   oroPremio,
          silverPrometido: plataPremio
        },
        warnings: avisos.length ? avisos : undefined
      });

    } catch (error) {
      console.error('❌ Error completando misión diaria:', error);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }
);
console.log('✅ Missions route: POST /api/missions/daily/complete');

// ============================================================================
// ADMIN: CARGA DE LAS MISIONES DIARIAS (panel misiones.html)
// ============================================================================
// Todo pasa por adminAuth (JWT con role 'admin'), igual que el resto de rutas
// de administración. El panel solo compone el JSON; la validación de verdad
// está aquí, para que un JSON manipulado no meta basura en la colección.

const MISSION_NPCS = ['granjero', 'guardian'];
const MISSION_LANGS = ['en-US', 'en-PH', 'es-419', 'pt-BR', 'zh-CN', 'ko-KR'];

function sanearMisionesDelDia(missions) {
  if (!Array.isArray(missions) || missions.length === 0) {
    throw new Error('missions debe ser una lista con al menos una misión');
  }
  if (missions.length > 10) {
    throw new Error('máximo 10 misiones por NPC y día');
  }

  const limpiarTexto = (v, max = 200) =>
    String(v == null ? '' : v).replace(/<[^>]*>/g, '').trim().slice(0, max);

  const ids = new Set();

  return missions.map((m, i) => {
    const missionId = limpiarTexto(m.missionId, 60) || `m${i + 1}`;
    if (ids.has(missionId)) throw new Error(`missionId repetido: ${missionId}`);
    ids.add(missionId);

    const itemId = limpiarTexto(m.itemId, 60);
    if (!itemId) throw new Error(`la misión ${missionId} no tiene itemId`);

    const requiredAmount = Math.max(1, Math.min(9999, parseInt(m.requiredAmount, 10) || 1));
    const expReward = Math.max(0, Math.min(100000, parseInt(m.expReward, 10) || 0));

    // RECOMPENSA EN MONEDAS. El tope es deliberadamente bajo comparado con la
    // experiencia: el oro son DÓLARES reales (1 oro = 1 USD) y la plata son
    // centavos. Un cero de más en el panel de administración al teclear no
    // puede convertirse en un regalo de miles de dólares, así que se acota
    // aquí, en el servidor, no solo en el formulario.
    const goldReward   = Math.max(0, Math.min(1000,   parseInt(m.goldReward,   10) || 0));
    const silverReward = Math.max(0, Math.min(100000, parseInt(m.silverReward, 10) || 0));

    const salida = { missionId, itemId, requiredAmount, expReward, goldReward, silverReward, texts: {} };

    const rewardItemId = limpiarTexto(m.rewardItemId, 60);
    if (rewardItemId) {
      salida.rewardItemId = rewardItemId;
      salida.rewardAmount = Math.max(1, Math.min(9999, parseInt(m.rewardAmount, 10) || 1));
    }

    const textos = m.texts || {};
    MISSION_LANGS.forEach(lang => {
      const t = textos[lang] || {};
      salida.texts[lang] = {
        title: limpiarTexto(t.title, 80),
        description: limpiarTexto(t.description, 300),
        itemName: limpiarTexto(t.itemName, 80),
        rewardName: limpiarTexto(t.rewardName, 80)
      };
    });

    // NOMBRE BONITO POR DEFECTO (2026-08-03): antes, si el administrador no
    // escribía el nombre visible, se dejaba el identificador crudo y en el
    // panel del juego salía literalmente "madera_tronco". Ahora el respaldo es
    // un nombre legible generado a partir del id ("Madera Tronco").
    const bonito = (id) => String(id || '')
      .replace(/[_-]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .replace(/\b\p{L}/gu, c => c.toUpperCase());

    // Se rellena el nombre visible en TODOS los idiomas que lo dejaron vacío,
    // no solo en inglés: cualquier idioma sin nombre acababa enseñando el id.
    MISSION_LANGS.forEach(lang => {
      if (!salida.texts[lang].itemName) {
        salida.texts[lang].itemName = salida.texts['es-419'].itemName || bonito(itemId);
      }
      if (salida.rewardItemId && !salida.texts[lang].rewardName) {
        salida.texts[lang].rewardName = salida.texts['es-419'].rewardName || bonito(salida.rewardItemId);
      }
    });

    // El inglés es el idioma de respaldo del juego: si falta el título, se
    // rellena con lo que haya en español y, si tampoco hay, con el nombre
    // legible del ítem (nunca con el identificador crudo).
    if (!salida.texts['en-US'].title) {
      salida.texts['en-US'].title = salida.texts['es-419'].title ||
        `Bring ${requiredAmount} ${salida.texts['en-US'].itemName || bonito(itemId)}`;
    }

    return salida;
  });
}

// Leer las misiones de un NPC en un día (para editarlas en el panel)
app.get('/api/admin/missions/daily/:npcId/:day', adminAuth, apiLimiter, async (req, res) => {
  try {
    const { npcId, day } = req.params;
    if (!MISSION_NPCS.includes(npcId)) return res.status(400).json({ error: 'npcId inválido' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return res.status(400).json({ error: 'day debe ser YYYY-MM-DD' });

    const doc = await DailyMission.findOne({ npcId, day }).lean();
    res.json({ success: true, npcId, day, found: !!doc, mission: doc || null });
  } catch (error) {
    console.error('❌ admin missions GET:', error);
    res.status(500).json({ error: 'internal_server_error' });
  }
});

// Días ya cargados de un NPC (para ver de un vistazo qué falta)
app.get('/api/admin/missions/days/:npcId', adminAuth, apiLimiter, async (req, res) => {
  try {
    const { npcId } = req.params;
    if (!MISSION_NPCS.includes(npcId)) return res.status(400).json({ error: 'npcId inválido' });

    const docs = await DailyMission.find({ npcId })
      .sort({ day: -1 }).limit(60)
      .select('day missions dailyResetHour -_id').lean();

    res.json({
      success: true,
      npcId,
      days: docs.map(d => ({ day: d.day, count: d.missions.length, dailyResetHour: d.dailyResetHour }))
    });
  } catch (error) {
    console.error('❌ admin missions days:', error);
    res.status(500).json({ error: 'internal_server_error' });
  }
});

// Crear o reemplazar las misiones de un NPC para un día
app.put('/api/admin/missions/daily', adminAuth, strictLimiter, async (req, res) => {
  try {
    const { npcId, day, missions, dailyResetHour } = req.body || {};

    if (!MISSION_NPCS.includes(npcId)) return res.status(400).json({ error: 'npcId inválido' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day || '')) return res.status(400).json({ error: 'day debe ser YYYY-MM-DD' });

    let limpias;
    try {
      limpias = sanearMisionesDelDia(missions);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    const hora = Math.max(0, Math.min(23, parseInt(dailyResetHour, 10) || 0));

    const doc = await DailyMission.findOneAndUpdate(
      { npcId, day },
      { $set: { missions: limpias, dailyResetHour: hora } },
      { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
    );

    console.log(`📜 Misiones de ${npcId} para ${day} guardadas (${limpias.length}) por admin`);
    res.json({ success: true, npcId, day, count: limpias.length, mission: doc });
  } catch (error) {
    console.error('❌ admin missions PUT:', error);
    res.status(500).json({ error: 'internal_server_error' });
  }
});

// Copiar las misiones de un día a otro (o a varios días seguidos)
app.post('/api/admin/missions/copy', adminAuth, strictLimiter, async (req, res) => {
  try {
    const { npcId, fromDay, toDay, repeatDays } = req.body || {};
    if (!MISSION_NPCS.includes(npcId)) return res.status(400).json({ error: 'npcId inválido' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fromDay || '')) return res.status(400).json({ error: 'fromDay inválido' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(toDay || '')) return res.status(400).json({ error: 'toDay inválido' });

    const origen = await DailyMission.findOne({ npcId, day: fromDay }).lean();
    if (!origen) return res.status(404).json({ error: 'no hay misiones en fromDay' });

    const repeticiones = Math.max(1, Math.min(30, parseInt(repeatDays, 10) || 1));
    const base = new Date(`${toDay}T00:00:00Z`);
    const creados = [];

    for (let i = 0; i < repeticiones; i++) {
      const d = new Date(base.getTime() + i * 86400000).toISOString().slice(0, 10);
      await DailyMission.findOneAndUpdate(
        { npcId, day: d },
        { $set: { missions: origen.missions, dailyResetHour: origen.dailyResetHour } },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
      creados.push(d);
    }

    res.json({ success: true, npcId, from: fromDay, days: creados });
  } catch (error) {
    console.error('❌ admin missions copy:', error);
    res.status(500).json({ error: 'internal_server_error' });
  }
});

// Borrar las misiones de un día
// ============================================================================
// ADMIN: HISTORIAL DE MISIONES  (panel misiones.html)
// ============================================================================
// Quién ha entregado más misiones, con su cuenta, su nombre y su nivel.
//
// De dónde salen los datos:
//   · GamePlayer.misiones      → contador acumulado de misiones entregadas.
//   · UserDailyProgress        → el detalle por día y NPC (para la actividad
//                                reciente y para poder borrar el historial).
//   · PlayerAuth               → la dirección de la cuenta.
//
// Se ordena por el acumulado, que es lo que pide el panel ("quién cumplió
// más"), y se completa con la última entrega para poder ver quién sigue activo.

app.get('/api/admin/missions/history', adminAuth, apiLimiter, async (req, res) => {
  try {
    const limite  = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const buscar  = String(req.query.search || '').trim();

    const filtro = {};
    if (buscar) {
      // Búsqueda por nombre de jugador, nombre visible o dirección. Se escapa
      // el texto: sin esto, un '(' o un '*' del buscador rompería la consulta,
      // y una expresión rebuscada podría bloquear el servidor.
      const esc = buscar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const rx  = new RegExp(esc, 'i');
      filtro.$or = [{ playerName: rx }, { Username: rx }, { address: rx }];
    }

    const jugadores = await GamePlayer.find(filtro)
      .select('playerName Username nivel misiones address updatedAt -_id')
      .sort({ misiones: -1, nivel: -1 })
      .limit(limite)
      .lean();

    const nombres = jugadores.map(j => j.playerName);

    // Última entrega y total de días con actividad, en UNA consulta.
    const actividad = await UserDailyProgress.aggregate([
      { $match: { playerName: { $in: nombres } } },
      { $group: {
          _id: '$playerName',
          ultima: { $max: '$lastInteraction' },
          dias:   { $sum: 1 },
          entregas: { $sum: '$completedCount' }
      } }
    ]);
    const porNombre = new Map(actividad.map(a => [a._id, a]));

    const filas = jugadores.map(j => {
      const a = porNombre.get(j.playerName) || {};
      return {
        playerName: j.playerName,
        username:   j.Username && j.Username !== '---' ? j.Username : null,
        address:    j.address || null,
        nivel:      Number(j.nivel || 0),
        // Acumulado histórico (no se borra al pasar el día).
        misiones:   Number(j.misiones || 0),
        // Lo que queda registrado día a día; es lo que se puede limpiar.
        entregasRegistradas: Number(a.entregas || 0),
        diasConActividad:    Number(a.dias || 0),
        ultimaEntrega:       a.ultima || null
      };
    });

    return res.json({ success: true, total: filas.length, rows: filas });
  } catch (e) {
    console.error('GET /api/admin/missions/history:', e);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// Borrar el historial de UN jugador.
//
// OJO CON EL EFECTO EN EL JUEGO: al borrar su progreso del DÍA DE HOY, ese
// jugador puede volver a entregar las misiones de hoy y cobrarlas otra vez. Es
// lo que se espera de un "limpiar" (deja la cuenta como si no hubiera jugado),
// pero conviene tenerlo presente. El panel lo avisa antes de pedir confirmación.
app.delete('/api/admin/missions/history/:playerName', adminAuth, strictLimiter, async (req, res) => {
  try {
    const playerName = String(req.params.playerName || '').trim();
    if (!playerName) return res.status(400).json({ error: 'playerName requerido' });

    const borrados = await UserDailyProgress.deleteMany({ playerName });
    const upd = await GamePlayer.updateOne({ playerName }, { $set: { misiones: 0 } });

    console.log(`🧹 admin: historial de misiones borrado para ${playerName} ` +
                `(${borrados.deletedCount} registros)`);
    return res.json({
      success: true,
      playerName,
      registrosBorrados: borrados.deletedCount,
      contadorReiniciado: upd.modifiedCount > 0
    });
  } catch (e) {
    console.error('DELETE /api/admin/missions/history/:playerName:', e);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// Borrar el historial COMPLETO. Pide confirm=BORRAR en el cuerpo para que no
// se pueda disparar por accidente con una petición suelta.
app.delete('/api/admin/missions/history', adminAuth, strictLimiter, async (req, res) => {
  try {
    if (String((req.body || {}).confirm || '') !== 'BORRAR') {
      return res.status(400).json({ error: 'confirmacion_requerida' });
    }
    const borrados = await UserDailyProgress.deleteMany({});
    const upd = await GamePlayer.updateMany({ misiones: { $gt: 0 } }, { $set: { misiones: 0 } });

    console.log(`🧹 admin: historial de misiones borrado ENTERO ` +
                `(${borrados.deletedCount} registros, ${upd.modifiedCount} contadores)`);
    return res.json({
      success: true,
      registrosBorrados: borrados.deletedCount,
      contadoresReiniciados: upd.modifiedCount
    });
  } catch (e) {
    console.error('DELETE /api/admin/missions/history:', e);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

console.log('✅ Missions history: GET/DELETE /api/admin/missions/history');

app.delete('/api/admin/missions/daily/:npcId/:day', adminAuth, strictLimiter, async (req, res) => {
  try {
    const { npcId, day } = req.params;
    if (!MISSION_NPCS.includes(npcId)) return res.status(400).json({ error: 'npcId inválido' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return res.status(400).json({ error: 'day debe ser YYYY-MM-DD' });

    const r = await DailyMission.deleteOne({ npcId, day });
    res.json({ success: true, deleted: r.deletedCount });
  } catch (error) {
    console.error('❌ admin missions DELETE:', error);
    res.status(500).json({ error: 'internal_server_error' });
  }
});

console.log('✅ Admin missions routes: GET/PUT/DELETE /api/admin/missions/*');

// =============================================================================
// TIEMPO JUGADO  +  PANEL DE ADMINISTRACIÓN DE JUGADORES
// =============================================================================
//
// NOTA HONESTA SOBRE EL TIEMPO JUGADO: hasta ahora el juego no guardaba en
// ningún sitio cuánto tiempo pasaba dentro cada jugador (solo la fecha de alta
// y el número de inicios de sesión). Esa medición EMPIEZA AQUÍ: el histórico
// anterior a este cambio no existe y no se puede reconstruir. El panel muestra
// las dos cosas por separado: la ANTIGÜEDAD de la cuenta (que sí se sabe desde
// siempre) y el TIEMPO JUGADO medido (que arranca en 0 para todos).
//
// Cómo se mide: el cliente ya llama a /api/save periódicamente mientras juega.
// Cada llamada suma el hueco desde la anterior, con un tope por tramo para que
// una pestaña abierta toda la noche no cuente como partida.

const playtimeSchema = new mongoose.Schema({
  playerName:   { type: String, required: true, unique: true, index: true },
  address:      { type: String, lowercase: true, index: true, default: null },
  segundos:     { type: Number, default: 0 },     // total acumulado
  sesiones:     { type: Number, default: 0 },     // tramos contados
  primeraVez:   { type: Date,   default: Date.now },
  ultimaVez:    { type: Date,   default: Date.now },
}, { collection: 'player_playtime' });
const PlayerPlaytime = mongoose.model('PlayerPlaytime', playtimeSchema);

// Hueco máximo que se cuenta de una tacada. Si entre dos guardados pasan más
// de 5 minutos, se asume que el jugador estuvo ausente (pestaña de fondo,
// se fue a comer) y solo se cuenta un tramo corto.
const PLAYTIME_MAX_GAP_S = 5 * 60;
const PLAYTIME_GAP_FALLBACK_S = 30;

async function registrarTiempoJugado(playerName, address) {
  if (!playerName || playerName === '---') return;
  try {
    const ahora = new Date();
    const doc = await PlayerPlaytime.findOne({ playerName });
    if (!doc) {
      await PlayerPlaytime.create({
        playerName, address: address || null,
        segundos: 0, sesiones: 1, primeraVez: ahora, ultimaVez: ahora
      });
      return;
    }
    const hueco = Math.floor((ahora - new Date(doc.ultimaVez)) / 1000);
    let suma = 0;
    let nuevaSesion = 0;
    if (hueco > 0 && hueco <= PLAYTIME_MAX_GAP_S) {
      suma = hueco;                       // seguía jugando
    } else if (hueco > PLAYTIME_MAX_GAP_S) {
      suma = PLAYTIME_GAP_FALLBACK_S;     // volvió tras una ausencia
      nuevaSesion = 1;
    }
    await PlayerPlaytime.updateOne(
      { playerName },
      {
        $inc: { segundos: suma, sesiones: nuevaSesion },
        $set: { ultimaVez: ahora, ...(address ? { address: address.toLowerCase() } : {}) }
      }
    );
  } catch (e) {
    console.warn('⚠️  No se pudo registrar tiempo jugado:', e.message);
  }
}

function formatearDuracion(segundos) {
  const s = Math.max(0, Math.floor(Number(segundos) || 0));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ── Campos EDITABLES desde el panel ────────────────────────────────────────
// Divididos a propósito en dos grupos:
//   • seguros  → viven solo en Mongo, se escriben directo.
//   • onchain  → son facturas del contrato. Editarlos solo en Mongo los
//     desincronizaría (el siguiente /sync los revertiría), así que se aplican
//     con applyStatOnChain y la factura se mueve de verdad.
const ADMIN_CAMPOS_SEGUROS = [
  'Username', 'petName', 'nivel', 'nivel_exp', 'mundo', 'lenguaje', 'tutorial',
  'posicionplayerx', 'posicionplayery', 'speed', 'misiones', 'petLevel',
  'mineria', 'mineria_exp', 'pesca', 'pesca_exp', 'cocina', 'cocina_exp',
  'deforestacion', 'deforestacion_exp', 'fuerza', 'fuerza_exp',
  'agricultura', 'agricultura_exp'
];
const ADMIN_CAMPOS_ONCHAIN = ['vida', 'agua', 'comida', 'oro', 'plata', 'exp'];

// ── GET /api/admin/players ─────────────────────────────────────────────────
// Lista paginada con búsqueda por dirección o nombre de personaje.
app.get('/api/admin/players', adminAuth, apiLimiter, async (req, res) => {
  try {
    const q      = String(req.query.q || '').trim();
    const limit  = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));
    const page   = Math.max(1, parseInt(req.query.page, 10) || 1);
    const skip   = (page - 1) * limit;

    let filtro = {};
    if (q) {
      // Búsqueda por dirección de cartera O por nombre (playerName o Username).
      const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filtro = { $or: [{ address: rx }, { playerName: rx }, { Username: rx }] };
    }

    const [total, totalGlobal, docs] = await Promise.all([
      GamePlayer.countDocuments(filtro),
      GamePlayer.countDocuments({}),
      GamePlayer.find(filtro)
        .select('playerName Username address nivel nivel_exp petName petLevel createdAt updatedAt tutorial mundo')
        .sort({ createdAt: -1 })
        .skip(skip).limit(limit).lean()
    ]);

    const nombres = docs.map(d => d.playerName);
    const [tiempos, actividades, stats] = await Promise.all([
      PlayerPlaytime.find({ playerName: { $in: nombres } }).lean(),
      UserActivity.find({ playerName: { $in: nombres } }).select('playerName lastLogin loginCount').lean(),
      PlayerStats.find({ playerName: { $in: nombres } }).select('playerName oro plata exp vida agua comida').lean()
    ]);
    const porNombre = (arr) => arr.reduce((m, x) => (m[x.playerName] = x, m), {});
    const mapT = porNombre(tiempos), mapA = porNombre(actividades), mapS = porNombre(stats);

    const ahora = Date.now();
    const players = docs.map(d => {
      const t = mapT[d.playerName], a = mapA[d.playerName], s = mapS[d.playerName];
      const creado = d.createdAt ? new Date(d.createdAt) : null;
      const antiguedadS = creado ? Math.floor((ahora - creado.getTime()) / 1000) : 0;
      return {
        playerName: d.playerName,
        username:   d.Username || '---',
        address:    d.address || null,
        nivel:      d.nivel || 0,
        exp:        d.nivel_exp || 0,
        petName:    d.petName || '---',
        petLevel:   d.petLevel || 1,
        creadoEn:   creado,
        antiguedadSegundos: antiguedadS,
        antiguedad: creado ? formatearDuracion(antiguedadS) : '—',
        jugadoSegundos: t ? t.segundos : 0,
        jugado:     formatearDuracion(t ? t.segundos : 0),
        sesiones:   t ? t.sesiones : 0,
        ultimaVez:  t ? t.ultimaVez : (a ? a.lastLogin : null),
        loginCount: a ? a.loginCount : 0,
        oro:   s ? s.oro : 0,
        plata: s ? s.plata : 0,
        expOnchain: s ? (s.exp || 0) : 0
      };
    });

    return res.json({ players, total, totalGlobal, page, limit, pages: Math.ceil(total / limit) });
  } catch (e) {
    console.error('GET /api/admin/players:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── GET /api/admin/players/:playerName ─────────────────────────────────────
// Ficha completa de un jugador.
app.get('/api/admin/players/:playerName', adminAuth, apiLimiter, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const gp = await GamePlayer.findOne({ playerName }).lean();
    if (!gp) return res.status(404).json({ error: 'player_not_found' });

    const [t, act, st, skills, pet] = await Promise.all([
      PlayerPlaytime.findOne({ playerName }).lean(),
      UserActivity.findOne({ playerName }).lean(),
      PlayerStats.findOne({ playerName }).lean(),
      PlayerSkills.findOne({ playerName }).lean(),
      PlayerPet.findOne({ playerName }).lean()
    ]);

    const creado = gp.createdAt ? new Date(gp.createdAt) : null;
    const antiguedadS = creado ? Math.floor((Date.now() - creado.getTime()) / 1000) : 0;

    return res.json({
      player: gp,
      resumen: {
        creadoEn: creado,
        antiguedad: creado ? formatearDuracion(antiguedadS) : '—',
        jugado: formatearDuracion(t ? t.segundos : 0),
        jugadoSegundos: t ? t.segundos : 0,
        sesiones: t ? t.sesiones : 0,
        ultimaVez: t ? t.ultimaVez : (act ? act.lastLogin : null),
        loginCount: act ? act.loginCount : 0,
        ip: act ? act.ip : null,
        geo: act ? act.geo : null
      },
      stats: st || null,
      skills: skills || null,
      pet: pet || null,
      inventarioCount: Array.isArray(gp.inventory) ? gp.inventory.length : 0,
      cofreCount: Array.isArray(gp.chest) ? gp.chest.length : 0,
      camposEditables: { seguros: ADMIN_CAMPOS_SEGUROS, onchain: ADMIN_CAMPOS_ONCHAIN }
    });
  } catch (e) {
    console.error('GET /api/admin/players/:playerName:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── PATCH /api/admin/players/:playerName ───────────────────────────────────
// Edita campos de la cuenta. Los de contrato pasan por la factura on-chain.
app.patch('/api/admin/players/:playerName', adminAuth, strictLimiter, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const gp = await GamePlayer.findOne({ playerName });
    if (!gp) return res.status(404).json({ error: 'player_not_found' });

    const cambios = req.body && typeof req.body.cambios === 'object' ? req.body.cambios : null;
    if (!cambios) return res.status(400).json({ error: 'sin_cambios' });

    const aplicados = [];
    const errores   = [];

    // 1. Campos que viven solo en Mongo
    const setMongo = {};
    for (const campo of ADMIN_CAMPOS_SEGUROS) {
      if (cambios[campo] === undefined) continue;
      const actual = gp[campo];
      let valor = cambios[campo];
      if (typeof actual === 'number') {
        valor = Number(valor);
        if (!Number.isFinite(valor) || valor < 0) { errores.push({ campo, error: 'valor_invalido' }); continue; }
        valor = Math.floor(valor);
      } else {
        valor = String(valor).slice(0, 64);
      }
      setMongo[campo] = valor;
      aplicados.push({ campo, de: actual, a: valor });
    }
    if (Object.keys(setMongo).length) {
      await GamePlayer.updateOne({ playerName }, { $set: setMongo });
    }

    // 2. Campos que son FACTURAS del contrato
    const pedidosOnchain = ADMIN_CAMPOS_ONCHAIN.filter(c => cambios[c] !== undefined);
    if (pedidosOnchain.length) {
      const doc = await PlayerStats.findOne({ playerName });
      if (!doc) {
        errores.push({ campo: pedidosOnchain.join(','), error: 'sin_stats_todavia_llama_a_sync' });
      } else {
        const contract = getStatsContract();
        const gasPrice = contract ? await getSafeGasPriceStats() : null;
        for (const stat of pedidosOnchain) {
          const nuevo = clampStat(stat, Math.round(Number(cambios[stat])));
          const viejo = Number(doc[stat] || 0);
          if (nuevo === viejo) continue;
          const invId = doc.invoiceIds && doc.invoiceIds[stat];
          if (!contract || !invId) {
            doc[stat] = nuevo;
            aplicados.push({ campo: stat, de: viejo, a: nuevo, nota: 'solo BD (sin factura todavía)' });
            continue;
          }
          const r = await applyStatOnChain(contract, stat, invId, nuevo, gasPrice);
          if (r.ok) {
            doc[stat] = nuevo;
            aplicados.push({ campo: stat, de: viejo, a: nuevo, nota: 'factura on-chain actualizada' });
          } else {
            if (r.chainQty !== null && r.chainQty !== undefined) doc[stat] = clampStat(stat, r.chainQty);
            errores.push({ campo: stat, error: r.error });
          }
        }
        await doc.save();
      }
    }

    console.log(`🛠️  [admin ${req.admin.address || req.admin.role}] editó ${playerName}: ${aplicados.map(a => a.campo).join(', ') || 'nada'}`);
    return res.json({ ok: errores.length === 0, aplicados, errores: errores.length ? errores : undefined });
  } catch (e) {
    console.error('PATCH /api/admin/players:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── DELETE /api/admin/players/:playerName ──────────────────────────────────
// Borra la cuenta de la base de datos. IRREVERSIBLE y exige confirmación
// explícita con el nombre exacto, para que no se vaya una por un clic suelto.
// OJO: NO toca las facturas del contrato — esas viven en la blockchain y no se
// pueden borrar desde aquí; la cuenta se va de Mongo, los activos siguen en la
// cadena a nombre de esa dirección.
app.delete('/api/admin/players/:playerName', adminAuth, strictLimiter, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    const confirmacion = String((req.body && req.body.confirmar) || req.query.confirmar || '');
    if (confirmacion !== playerName) {
      return res.status(400).json({
        error: 'confirmacion_requerida',
        message: 'Manda { "confirmar": "<playerName exacto>" } para borrar.'
      });
    }

    const gp = await GamePlayer.findOne({ playerName }).lean();
    if (!gp) return res.status(404).json({ error: 'player_not_found' });

    const borrados = {};
    const borrar = async (modelo, nombre, filtro) => {
      try { borrados[nombre] = (await modelo.deleteMany(filtro)).deletedCount || 0; }
      catch (e) { borrados[nombre] = `error: ${e.message}`; }
    };

    await borrar(GamePlayer,          'gamePlayer',   { playerName });
    await borrar(PlayerStats,         'stats',        { playerName });
    await borrar(PlayerPlaytime,      'playtime',     { playerName });
    await borrar(PlayerSkills,        'skills',       { playerName });
    await borrar(PlayerPet,           'pet',          { playerName });
    await borrar(UserActivity,        'actividad',    { playerName });
    await borrar(MissionsPlayer,      'misiones',     { playerName });
    await borrar(PlayerNotifications, 'notificaciones', { playerName });
    await borrar(FurnaceState,        'horno',        { playerName });
    if (gp.address) await borrar(PlayerAuth, 'auth', { address: String(gp.address).toLowerCase() });

    console.warn(`🗑️  [admin ${req.admin.address || req.admin.role}] BORRÓ la cuenta ${playerName}`);
    return res.json({
      ok: true, playerName, borrados,
      aviso: 'Las facturas del contrato NO se borran: siguen en la blockchain a nombre de esa dirección.'
    });
  } catch (e) {
    console.error('DELETE /api/admin/players:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── GET /api/admin/overview ────────────────────────────────────────────────
// Números de cabecera del panel.
app.get('/api/admin/overview', adminAuth, apiLimiter, async (req, res) => {
  try {
    const hace24h = new Date(Date.now() - 24 * 3600 * 1000);
    const hace7d  = new Date(Date.now() - 7 * 86400 * 1000);
    const [totalCuentas, nuevas24h, nuevas7d, activos24h, conectados, agg] = await Promise.all([
      GamePlayer.countDocuments({}),
      GamePlayer.countDocuments({ createdAt: { $gte: hace24h } }),
      GamePlayer.countDocuments({ createdAt: { $gte: hace7d } }),
      PlayerPlaytime.countDocuments({ ultimaVez: { $gte: hace24h } }),
      ConnectedUser.countDocuments({}),
      PlayerPlaytime.aggregate([{ $group: { _id: null, total: { $sum: '$segundos' } } }])
    ]);
    const totalSeg = (agg && agg[0] && agg[0].total) || 0;
    return res.json({
      totalCuentas, nuevas24h, nuevas7d, activos24h, conectados,
      tiempoTotalSegundos: totalSeg,
      tiempoTotal: formatearDuracion(totalSeg),
      adminAddress: req.admin.address || null
    });
  } catch (e) {
    console.error('GET /api/admin/overview:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── GET /api/admin/whoami ──────────────────────────────────────────────────
// Lo usa el panel para saber si la cartera conectada es admin.
app.get('/api/admin/whoami', adminAuth, apiLimiter, (req, res) => {
  res.json({ ok: true, address: req.admin.address || null, via: req.admin.via || 'token' });
});

console.log('✅ Admin players routes: /api/admin/players, /api/admin/overview, /api/admin/whoami');

// =============================================================================
// BANDEJA DE ERRORES DEL CLIENTE + FALLOS DE RELAY               (2026-08-11)
// -----------------------------------------------------------------------------
// Da servicio a reporter.html. Todo pasa por adminAuth, o sea que solo entra
// quien tenga sesión con una cartera de administrador — la misma que ya usa
// admin.html. No hay contraseñas ni tokens que guardar en el navegador.
//
// OJO con la diferencia entre las dos colecciones:
//   • ErrorReport        → fallos de JavaScript en el cliente (esto).
//   • Report (más abajo) → denuncias de un jugador contra otro. No se mezclan.
// =============================================================================

// ── GET /api/admin/client-errors ───────────────────────────────────────────
app.get('/api/admin/client-errors', adminAuth, apiLimiter, async (req, res) => {
  try {
    const limite  = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const salto   = Math.max(0, parseInt(req.query.skip, 10) || 0);
    const busca   = String(req.query.q || '').trim().slice(0, 120);
    const tipo    = String(req.query.type || '').trim().slice(0, 40);

    const filtro = {};
    if (tipo) filtro.type = tipo;
    if (busca) {
      // Se escapan los metacaracteres: sin esto una búsqueda con '(' o '*'
      // rompe la consulta, y un patrón malicioso puede colgar el servidor.
      const seguro = busca.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filtro.$or = [
        { message: { $regex: seguro, $options: 'i' } },
        { scene:   { $regex: seguro, $options: 'i' } },
        { file:    { $regex: seguro, $options: 'i' } }
      ];
    }

    const [items, total, tipos] = await Promise.all([
      ErrorReport.find(filtro).sort({ lastSeen: -1 }).skip(salto).limit(limite).lean(),
      ErrorReport.countDocuments(filtro),
      ErrorReport.distinct('type')
    ]);

    // Suma de ocurrencias reales (no de fichas): con la deduplicación una sola
    // ficha puede representar cientos de fallos.
    const agg = await ErrorReport.aggregate([
      { $match: filtro },
      { $group: { _id: null, ocurrencias: { $sum: '$count' } } }
    ]);

    res.json({
      ok: true,
      items, total,
      ocurrencias: (agg[0] && agg[0].ocurrencias) || 0,
      tipos: tipos.filter(Boolean).sort()
    });
  } catch (e) {
    console.error('GET /api/admin/client-errors:', e);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ── DELETE /api/admin/client-errors/:id ────────────────────────────────────
app.delete('/api/admin/client-errors/:id', adminAuth, strictLimiter, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ ok: false, error: 'invalid_id' });
    }
    const r = await ErrorReport.deleteOne({ _id: id });
    res.json({ ok: true, borrados: r.deletedCount || 0 });
  } catch (e) {
    console.error('DELETE /api/admin/client-errors/:id:', e);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ── DELETE /api/admin/client-errors  (vaciar la bandeja) ───────────────────
// Pide confirm=YES en la URL a propósito: es irreversible y no debe poder
// dispararse por un clic accidental ni por una petición suelta.
app.delete('/api/admin/client-errors', adminAuth, strictLimiter, async (req, res) => {
  try {
    if (String(req.query.confirm) !== 'YES') {
      return res.status(400).json({ ok: false, error: 'confirmation_required' });
    }
    const r = await ErrorReport.deleteMany({});
    console.warn(`🗑️  ${req.admin.address} vació la bandeja de errores (${r.deletedCount} fichas)`);
    res.json({ ok: true, borrados: r.deletedCount || 0 });
  } catch (e) {
    console.error('DELETE /api/admin/client-errors:', e);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ── GET /api/admin/relay-failures ──────────────────────────────────────────
// Fallos de relay que NO son un revert del contrato.
//
// Un revert es una respuesta NORMAL de la cadena: el contrato dijo que no
// (sin saldo, sin permiso, requisito incumplido). Eso no es una avería y
// llenaría la bandeja de ruido. Lo que interesa aquí es lo ANORMAL: el nodo
// caído, el nonce pisado, un timeout, el gas mal estimado — cosas que apuntan
// a un problema de infraestructura y que sí hay que mirar.
app.get('/api/admin/relay-failures', adminAuth, apiLimiter, async (req, res) => {
  try {
    const limite = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const salto  = Math.max(0, parseInt(req.query.skip, 10) || 0);

    const patronesDeRevert = /execution reverted|call_exception|revert/i;

    const filtro = {
      status: { $in: ['failed'] },        // 'reverted' queda fuera por definición
      $and: [
        { $or: [ { revertReason: { $in: [null, ''] } }, { revertReason: { $exists: false } } ] },
        { $or: [ { error: { $exists: false } }, { error: { $not: patronesDeRevert } } ] }
      ]
    };

    const [items, total] = await Promise.all([
      RelayedTransaction.find(filtro)
        .sort({ createdAt: -1 }).skip(salto).limit(limite)
        .select('playerName contractName functionName status error txHash createdAt retryCount')
        .lean(),
      RelayedTransaction.countDocuments(filtro)
    ]);

    res.json({ ok: true, items, total });
  } catch (e) {
    console.error('GET /api/admin/relay-failures:', e);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

console.log('✅ Reporter routes: /api/admin/client-errors, /api/admin/relay-failures');

// =============================================================================
// PREFERENCIAS DE GRÁFICOS DEL JUGADOR                           (2026-08-11)
// -----------------------------------------------------------------------------
// Los ajustes de calidad y distancia de visión vivían en localStorage. Pedido:
// nada en el navegador, todo en el servidor. Ventaja real además de la
// preferencia: el jugador conserva su configuración al cambiar de navegador o
// de ordenador, y se puede consultar desde el panel de administración cuando
// alguien reporta que le va lento.
//
// Se guardan POR JUGADOR (no por dispositivo). Es una simplificación asumida:
// si alguien juega en un móvil flojo y en un PC potente tendrá que ajustarlo al
// cambiar. A cambio no hay nada en el navegador, que es lo que se pidió.
// =============================================================================
const graphicsPrefsSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true, index: true },
  // Se validan contra listas cerradas al escribir; aquí solo el tipo.
  calidad: { type: String, default: 'alta' },
  chunks:  { type: Number, default: 12, min: 2, max: 16 },
  updatedAt: { type: Date, default: Date.now }
}, { collection: 'player_graphics_prefs' });
const GraphicsPrefs = mongoose.model('GraphicsPrefs', graphicsPrefsSchema);

const CALIDADES_VALIDAS = ['alta', 'media', 'baja'];

// ── GET /api/graphics/:playerName ──────────────────────────────────────────
app.get('/api/graphics/:playerName', apiLimiter, authMiddleware, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    if (!await requireOwner(req, res, playerName)) return;

    const doc = await GraphicsPrefs.findOne({ playerName }).lean();
    // Sin fila todavía: se devuelven los valores por defecto, no un 404. El
    // cliente no tiene que distinguir "nunca lo configuró" de "no hay nada".
    return res.json({
      ok: true,
      calidad: (doc && CALIDADES_VALIDAS.includes(doc.calidad)) ? doc.calidad : 'alta',
      chunks:  (doc && typeof doc.chunks === 'number') ? doc.chunks : 12
    });
  } catch (err) {
    console.error('GET /api/graphics:', err);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ── POST /api/graphics/:playerName ─────────────────────────────────────────
app.post('/api/graphics/:playerName', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    if (!await requireOwner(req, res, playerName)) return;

    const calidadPedida = String((req.body && req.body.calidad) || '').toLowerCase();
    const calidad = CALIDADES_VALIDAS.includes(calidadPedida) ? calidadPedida : 'alta';
    const chunks  = Math.max(2, Math.min(16, Math.round(Number(req.body && req.body.chunks) || 12)));

    await GraphicsPrefs.findOneAndUpdate(
      { playerName },
      { calidad, chunks, updatedAt: new Date() },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    return res.json({ ok: true, calidad, chunks });
  } catch (err) {
    console.error('POST /api/graphics:', err);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

console.log('✅ Graphics prefs routes: GET/POST /api/graphics/:playerName');


// =============================================================================
// PERFILES PÚBLICOS, VERIFICADORES Y REPORTES ENTRE JUGADORES  (2026-08-03)
// -----------------------------------------------------------------------------
// Da soporte al submenú que sale al hacer CLIC DERECHO sobre otro jugador
// dentro del juego (Profile / Send verifier / Report) y a la consola de
// administración `consola-reportes.html`.
//
//   GET  /api/player/profile/:key      → ficha pública (key = playerName o 0x…)
//   POST /api/verifier/send            → manda un verificador a otro jugador
//   POST /api/verifier/answer          → el jugador responde su verificador
//   POST /api/reports                  → reportar a un jugador
//   GET  /api/admin/reports            → [admin] lista de reportes + filtros
//   GET  /api/admin/reports/:id        → [admin] reporte + ficha del acusado
//   POST /api/admin/reports/:id/warn   → [admin] advertencia al correo/buzón
//   POST /api/admin/reports/:id/ban    → [admin] banear la cartera
//   POST /api/admin/reports/:id/unban  → [admin] quitar el baneo
//   DELETE /api/admin/reports/:id      → [admin] quitar de la lista sin sanción
//   GET  /api/admin/verifiers          → [admin] verificadores enviados
// =============================================================================

// ── Modelos ────────────────────────────────────────────────────────────────
const playerReportSchema = new mongoose.Schema({
  reporterAddress: { type: String, required: true, lowercase: true, index: true },
  reporterName:    { type: String, default: '---' },
  targetAddress:   { type: String, required: true, lowercase: true, index: true },
  targetName:      { type: String, default: '---' },
  reason:          { type: String, required: true },   // categoría
  details:         { type: String, default: '', maxlength: 1000 },
  scene:           { type: String, default: '' },
  posX:            { type: Number, default: 0 },
  posY:            { type: Number, default: 0 },
  status:          { type: String, enum: ['pending', 'warned', 'banned', 'dismissed'], default: 'pending', index: true },
  adminAddress:    { type: String, default: '' },
  adminNote:       { type: String, default: '', maxlength: 1000 },
  handledAt:       { type: Date, default: null }
}, { timestamps: true });
playerReportSchema.index({ createdAt: -1 });
playerReportSchema.index({ targetAddress: 1, createdAt: -1 });
const PlayerReport = mongoose.model('PlayerReport', playerReportSchema);

const verifierSchema = new mongoose.Schema({
  fromAddress: { type: String, required: true, lowercase: true, index: true },
  fromName:    { type: String, default: '---' },
  toAddress:   { type: String, required: true, lowercase: true, index: true },
  toName:      { type: String, default: '---' },
  question:    { type: String, required: true },
  answer:      { type: String, required: true },       // respuesta correcta
  given:       { type: String, default: '' },          // lo que contestó
  status:      { type: String, enum: ['sent', 'passed', 'failed', 'expired'], default: 'sent', index: true },
  expiresAt:   { type: Date, required: true },
  answeredAt:  { type: Date, default: null }
}, { timestamps: true });
verifierSchema.index({ createdAt: -1 });
const PlayerVerifier = mongoose.model('PlayerVerifier', verifierSchema);

// ── SUSPENSIONES TEMPORALES ────────────────────────────────────────────────
// Distinto del baneo de AccessControl, que es permanente y manual. Ésta caduca
// sola: la usa el sistema de verificadores (3 fallos = 3 días fuera) y también
// puede ponerla un administrador desde consola-reportes.html.
const suspensionSchema = new mongoose.Schema({
  address:   { type: String, required: true, lowercase: true, index: true },
  playerName:{ type: String, default: '---' },
  reason:    { type: String, default: '', maxlength: 300 },
  until:     { type: Date, required: true, index: true },
  days:      { type: Number, default: 3 },
  source:    { type: String, enum: ['verifier', 'admin'], default: 'verifier' },
  adminAddress: { type: String, default: '' },
  liftedAt:  { type: Date, default: null }   // != null → levantada a mano
}, { timestamps: true });
suspensionSchema.index({ createdAt: -1 });
const PlayerSuspension = mongoose.model('PlayerSuspension', suspensionSchema);

// Reglas del verificador (2026-08-04, pedido del usuario):
//   • 15 segundos para contestar, y si no se contesta cuenta como fallo.
//   • 3 fallos = 3 días de suspensión de la cuenta.
const VERIFIER_SECONDS       = 15;
const VERIFIER_FAILS_TO_BAN  = 3;
const VERIFIER_SUSPEND_DAYS  = 3;
// Ventana en la que se cuentan los fallos. Sin ella, tres fallos repartidos a
// lo largo de meses acabarían suspendiendo a alguien que no hizo nada raro.
const VERIFIER_FAIL_WINDOW_DAYS = 7;

/**
 * ¿Tiene esta dirección una suspensión activa ahora mismo?
 * @returns {Promise<{active:boolean, until?:Date, reason?:string, id?:string}>}
 */
async function getActiveSuspension(address) {
  const addr = String(address || '').toLowerCase();
  if (!addr) return { active: false };
  const doc = await PlayerSuspension.findOne({
    address: addr,
    liftedAt: null,
    until: { $gt: new Date() }
  }).sort({ until: -1 }).lean();
  if (!doc) return { active: false };
  return { active: true, until: doc.until, reason: doc.reason, id: String(doc._id) };
}

/**
 * Cierra los verificadores que se pasaron de los 15 segundos sin contestar.
 * Se llama de forma perezosa (al enviar uno nuevo, al contestar y al consultar
 * desde la consola de administración) para no depender de un temporizador que
 * se pierda si el proceso se reinicia.
 */
async function caducarVerificadoresVencidos(address) {
  const filtro = { status: 'sent', expiresAt: { $lte: new Date() } };
  if (address) filtro.toAddress = String(address).toLowerCase();
  const vencidos = await PlayerVerifier.find(filtro).lean();
  if (!vencidos.length) return [];
  await PlayerVerifier.updateMany(
    { _id: { $in: vencidos.map(v => v._id) } },
    { $set: { status: 'expired' } }
  );
  return vencidos;
}

/**
 * Cuenta los fallos recientes de un jugador y, si llega al tope, lo suspende.
 * Un verificador NO contestado cuenta igual que uno contestado mal: si no,
 * bastaría con ignorarlos para no ser nunca sancionado.
 * @returns {Promise<{suspended:boolean, fails:number, until?:Date}>}
 */
async function evaluarSuspensionPorVerificadores(address) {
  const addr = String(address || '').toLowerCase();
  if (!addr) return { suspended: false, fails: 0 };

  const desde = new Date(Date.now() - VERIFIER_FAIL_WINDOW_DAYS * 86400000);

  // Si ya está suspendido no se vuelve a suspender (ni se alarga solo).
  const yaSuspendido = await getActiveSuspension(addr);
  if (yaSuspendido.active) {
    const n = await PlayerVerifier.countDocuments({
      toAddress: addr, status: { $in: ['failed', 'expired'] }, createdAt: { $gte: desde }
    });
    return { suspended: true, fails: n, until: yaSuspendido.until };
  }

  // Solo cuentan los fallos POSTERIORES a la última suspensión: al cumplirla,
  // el contador empieza de cero.
  const ultima = await PlayerSuspension.findOne({ address: addr }).sort({ createdAt: -1 }).lean();
  const corte = ultima && ultima.until > desde ? ultima.until : desde;

  const fallos = await PlayerVerifier.countDocuments({
    toAddress: addr,
    status: { $in: ['failed', 'expired'] },
    createdAt: { $gte: corte }
  });

  if (fallos < VERIFIER_FAILS_TO_BAN) return { suspended: false, fails: fallos };

  const until = new Date(Date.now() + VERIFIER_SUSPEND_DAYS * 86400000);
  let playerName = '---';
  try {
    const gp = await GamePlayer.findOne({ address: addr }).lean();
    if (gp && gp.playerName) playerName = gp.playerName;
  } catch (_) {}

  await PlayerSuspension.create({
    address: addr,
    playerName,
    reason: `${fallos} failed verifiers in ${VERIFIER_FAIL_WINDOW_DAYS} days`,
    until,
    days: VERIFIER_SUSPEND_DAYS,
    source: 'verifier'
  });
  invalidateAccessCache();

  console.warn(`⛔ Suspensión automática de ${addr} por ${fallos} verificadores fallidos (hasta ${until.toISOString()})`);

  // Expulsión inmediata si está dentro.
  socketsOfAddress(addr).forEach(s => {
    try {
      s.emit('accountSuspended', {
        reason: `${VERIFIER_FAILS_TO_BAN} failed verifiers`,
        until: until.toISOString(),
        days: VERIFIER_SUSPEND_DAYS
      });
      s.disconnect(true);
    } catch (_) {}
  });

  return { suspended: true, fails: fallos, until };
}

const REPORT_REASONS = [
  'botting', 'cheating', 'harassment', 'scam', 'spam',
  'inappropriate_name', 'exploit_abuse', 'other'
];

// ── Utilidades ─────────────────────────────────────────────────────────────

// Todos los sockets abiertos de una dirección (socket.io v4 expone el Map).
function socketsOfAddress(address) {
  const addr = String(address || '').toLowerCase();
  const out = [];
  if (!addr) return out;
  try {
    for (const s of io.sockets.sockets.values()) {
      if (String(s.authenticatedAddress || '').toLowerCase() === addr) out.push(s);
    }
  } catch (_) {}
  return out;
}

// Ficha pública de un jugador a partir de su address o playerName.
async function buildPlayerProfile(key) {
  const raw = String(key || '').trim();
  if (!raw) return null;

  const esDireccion = /^0x[0-9a-f]{40}$/i.test(raw);
  const gp = esDireccion
    ? await GamePlayer.findOne({ address: raw.toLowerCase() }).lean()
    : await GamePlayer.findOne({ playerName: raw }).lean();
  if (!gp) return null;

  const playerName = gp.playerName;
  const [tiempo, actividad, skills, pet, stats] = await Promise.all([
    PlayerPlaytime.findOne({ playerName }).lean().catch(() => null),
    UserActivity.findOne({ playerName }).lean().catch(() => null),
    PlayerSkills.findOne({ playerName }).lean().catch(() => null),
    PlayerPet.findOne({ playerName }).lean().catch(() => null),
    PlayerStats.findOne({ playerName }).lean().catch(() => null)
  ]);

  const creado = gp.createdAt ? new Date(gp.createdAt) : null;
  const antiguedadS = creado ? Math.floor((Date.now() - creado.getTime()) / 1000) : 0;
  const jugadoS = tiempo ? (tiempo.segundos || 0) : 0;

  // Las skills se devuelven tal cual estén guardadas (el esquema puede variar),
  // sin campos internos de mongo.
  let skillsPub = {};
  if (skills) {
    skillsPub = { ...skills };
    delete skillsPub._id; delete skillsPub.__v;
    delete skillsPub.playerName; delete skillsPub.createdAt; delete skillsPub.updatedAt;
  }

  return {
    playerName,
    username:  gp.Username || '---',
    address:   gp.address || null,
    nivel:     gp.nivel || 0,
    exp:       gp.nivel_exp || 0,
    mundo:     gp.mundo || '',
    petName:   (pet && pet.petName) || gp.petName || '---',
    petLevel:  gp.petLevel || 1,
    creadoEn:  creado,
    creadoTexto: creado ? creado.toISOString() : null,
    antiguedadSegundos: antiguedadS,
    antiguedad: creado ? formatearDuracion(antiguedadS) : '—',
    jugadoSegundos: jugadoS,
    jugado:    formatearDuracion(jugadoS),
    sesiones:  tiempo ? (tiempo.sesiones || 0) : 0,
    ultimaVez: tiempo ? tiempo.ultimaVez : (actividad ? actividad.lastLogin : null),
    loginCount: actividad ? (actividad.loginCount || 0) : 0,
    skills:    skillsPub,
    oro:       stats ? (stats.oro || 0) : 0,
    plata:     stats ? (stats.plata || 0) : 0,
    online:    socketsOfAddress(gp.address).length > 0
  };
}

// ── GET /api/player/profile/:key ───────────────────────────────────────────
// Ficha pública que abre la opción "Profile" del submenú. Cualquier jugador
// autenticado puede consultarla; NO devuelve nada sensible (ni correo, ni
// inventario, ni sesión).
app.get('/api/player/profile/:key', apiLimiter, authMiddleware, async (req, res) => {
  try {
    const perfil = await buildPlayerProfile(req.params.key);
    if (!perfil) return res.status(404).json({ error: 'player_not_found' });
    return res.json({ ok: true, profile: perfil });
  } catch (e) {
    console.error('GET /api/player/profile:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── POST /api/verifier/send ────────────────────────────────────────────────
// "Send verifier": manda al jugador señalado una comprobación rápida de que
// hay una persona al teclado. Se entrega por socket y queda registrada para
// que el administrador vea quién la pasó y quién no.
const _verifierCooldown = new Map(); // address → timestamp
app.post('/api/verifier/send',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [ body('target').isString().notEmpty() ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const fromAddress = String(req.user.address || '').toLowerCase();
      const destino = await buildPlayerProfile(req.body.target);
      if (!destino || !destino.address) return res.status(404).json({ error: 'player_not_found' });
      if (destino.address.toLowerCase() === fromAddress) {
        return res.status(400).json({ error: 'cannot_verify_yourself' });
      }

      // Un verificador por minuto y por remitente (anti-acoso).
      const ahora = Date.now();
      const ultimo = _verifierCooldown.get(fromAddress) || 0;
      if (ahora - ultimo < 60000) {
        return res.status(429).json({ error: 'verifier_cooldown', secondsRemaining: Math.ceil((60000 - (ahora - ultimo)) / 1000) });
      }
      _verifierCooldown.set(fromAddress, ahora);

      // Antes de nada: cerrar los verificadores del destinatario que ya se
      // pasaron de tiempo, para que cuenten como fallo aunque los ignorara.
      await caducarVerificadoresVencidos(destino.address);
      await evaluarSuspensionPorVerificadores(destino.address);

      // Un solo verificador vivo por jugador: si ya tiene uno sin contestar,
      // no se le encima otro (si no, sería trivial reventarle la cuenta a
      // alguien mandándole verificadores en cadena).
      const enCurso = await PlayerVerifier.findOne({
        toAddress: destino.address.toLowerCase(),
        status: 'sent',
        expiresAt: { $gt: new Date() }
      }).lean();
      if (enCurso) {
        return res.status(409).json({ error: 'verifier_already_pending' });
      }

      // Reto sencillo pero distinto cada vez.
      const a = Math.floor(Math.random() * 8) + 2;
      const b = Math.floor(Math.random() * 8) + 2;
      const question = `${a} + ${b} = ?`;
      const answer = String(a + b);

      const yo = await buildPlayerProfile(fromAddress);
      const doc = await PlayerVerifier.create({
        fromAddress,
        fromName: (yo && (yo.username !== '---' ? yo.username : yo.playerName)) || '---',
        toAddress: destino.address.toLowerCase(),
        toName: destino.username !== '---' ? destino.username : destino.playerName,
        question,
        answer,
        // 15 segundos para contestar (VERIFIER_SECONDS)
        expiresAt: new Date(ahora + VERIFIER_SECONDS * 1000)
      });

      const sockets = socketsOfAddress(destino.address);
      sockets.forEach(s => {
        try {
          s.emit('verifierChallenge', {
            id: String(doc._id),
            from: doc.fromName,
            question,
            expiresIn: VERIFIER_SECONDS,
            failsToSuspend: VERIFIER_FAILS_TO_BAN,
            suspendDays: VERIFIER_SUSPEND_DAYS
          });
        } catch (_) {}
      });

      // Al cumplirse el plazo se cierra el reto y se revisa la suspensión, sin
      // esperar a que nadie consulte. (El cierre perezoso de arriba sigue
      // existiendo por si el proceso se reinicia justo en este hueco.)
      setTimeout(async () => {
        try {
          const vigente = await PlayerVerifier.findById(doc._id);
          if (!vigente || vigente.status !== 'sent') return;
          vigente.status = 'expired';
          await vigente.save();
          socketsOfAddress(doc.fromAddress).forEach(s => {
            try { s.emit('verifierResult', { id: String(doc._id), player: doc.toName, status: 'expired' }); } catch (_) {}
          });
          const r = await evaluarSuspensionPorVerificadores(doc.toAddress);
          socketsOfAddress(doc.toAddress).forEach(s => {
            try {
              s.emit('verifierTimeout', {
                id: String(doc._id),
                fails: r.fails,
                failsToSuspend: VERIFIER_FAILS_TO_BAN,
                suspended: r.suspended
              });
            } catch (_) {}
          });
        } catch (e) {
          console.warn('⚠️  No se pudo caducar el verificador:', e.message);
        }
      }, (VERIFIER_SECONDS + 2) * 1000).unref?.();

      return res.json({
        ok: true,
        id: String(doc._id),
        seconds: VERIFIER_SECONDS,
        delivered: sockets.length > 0,
        message: sockets.length > 0
          ? 'Verifier sent'
          : 'Verifier registered — the player is offline right now'
      });
    } catch (e) {
      console.error('POST /api/verifier/send:', e);
      return res.status(500).json({ error: 'internal_error' });
    }
  }
);

// ── POST /api/verifier/answer ──────────────────────────────────────────────
app.post('/api/verifier/answer',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [ body('id').isString().notEmpty(), body('answer').isString() ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const address = String(req.user.address || '').toLowerCase();
      const doc = await PlayerVerifier.findById(req.body.id);
      if (!doc) return res.status(404).json({ error: 'verifier_not_found' });
      if (doc.toAddress !== address) return res.status(403).json({ error: 'not_your_verifier' });
      if (doc.status !== 'sent') return res.status(409).json({ error: 'already_answered' });

      const dado = String(req.body.answer || '').trim();
      const aTiempo = doc.expiresAt.getTime() >= Date.now();
      doc.given = dado.slice(0, 40);
      doc.answeredAt = new Date();
      doc.status = !aTiempo ? 'expired' : (dado === doc.answer ? 'passed' : 'failed');
      await doc.save();

      socketsOfAddress(doc.fromAddress).forEach(s => {
        try {
          s.emit('verifierResult', { id: String(doc._id), player: doc.toName, status: doc.status });
        } catch (_) {}
      });

      // Tras cada fallo (mal contestado o fuera de plazo) se revisa si toca
      // suspender: 3 fallos = 3 días. Si pasa, evaluarSuspension… ya expulsa.
      let sancion = { suspended: false, fails: 0 };
      if (doc.status !== 'passed') {
        sancion = await evaluarSuspensionPorVerificadores(address);
      }

      return res.json({
        ok: true,
        status: doc.status,
        fails: sancion.fails,
        failsToSuspend: VERIFIER_FAILS_TO_BAN,
        suspended: !!sancion.suspended,
        suspendedUntil: sancion.until || null
      });
    } catch (e) {
      console.error('POST /api/verifier/answer:', e);
      return res.status(500).json({ error: 'internal_error' });
    }
  }
);

// ── POST /api/reports ──────────────────────────────────────────────────────
// Un jugador reporta a otro desde el submenú del juego.
app.post('/api/reports',
  apiLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('target').isString().notEmpty(),
    body('reason').isString().notEmpty(),
    body('details').optional().isString().isLength({ max: 1000 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const reporterAddress = String(req.user.address || '').toLowerCase();
      const destino = await buildPlayerProfile(req.body.target);
      if (!destino || !destino.address) return res.status(404).json({ error: 'player_not_found' });
      if (destino.address.toLowerCase() === reporterAddress) {
        return res.status(400).json({ error: 'cannot_report_yourself' });
      }

      const reason = REPORT_REASONS.includes(req.body.reason) ? req.body.reason : 'other';

      // Un mismo jugador no puede reportar al mismo objetivo más de una vez
      // cada 10 minutos (evita inundar la consola de reportes).
      const reciente = await PlayerReport.findOne({
        reporterAddress,
        targetAddress: destino.address.toLowerCase(),
        createdAt: { $gte: new Date(Date.now() - 10 * 60000) }
      }).lean();
      if (reciente) return res.status(429).json({ error: 'report_cooldown' });

      const yo = await buildPlayerProfile(reporterAddress);
      const doc = await PlayerReport.create({
        reporterAddress,
        reporterName: (yo && (yo.username !== '---' ? yo.username : yo.playerName)) || '---',
        targetAddress: destino.address.toLowerCase(),
        targetName: destino.username !== '---' ? destino.username : destino.playerName,
        reason,
        details: String(req.body.details || '').slice(0, 1000),
        scene: String(req.body.scene || '').slice(0, 60),
        posX: Number(req.body.x) || 0,
        posY: Number(req.body.y) || 0
      });

      console.warn(`🚩 Reporte nuevo: ${doc.reporterName} → ${doc.targetName} (${reason})`);
      return res.json({ ok: true, id: String(doc._id) });
    } catch (e) {
      console.error('POST /api/reports:', e);
      return res.status(500).json({ error: 'internal_error' });
    }
  }
);

// ── GET /api/admin/reports ─────────────────────────────────────────────────
app.get('/api/admin/reports', adminAuth, apiLimiter, async (req, res) => {
  try {
    const status = String(req.query.status || '').trim();
    const q      = String(req.query.q || '').trim();
    const limit  = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));
    const page   = Math.max(1, parseInt(req.query.page, 10) || 1);

    const filtro = {};
    if (['pending', 'warned', 'banned', 'dismissed'].includes(status)) filtro.status = status;
    if (q) {
      const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filtro.$or = [
        { targetAddress: rx }, { targetName: rx },
        { reporterAddress: rx }, { reporterName: rx },
        { reason: rx }, { details: rx }
      ];
    }

    const [total, docs, counts, ac] = await Promise.all([
      PlayerReport.countDocuments(filtro),
      PlayerReport.find(filtro).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      PlayerReport.aggregate([{ $group: { _id: '$status', n: { $sum: 1 } } }]),
      getAccessControl()
    ]);

    const baneados = new Set((ac.banned || []).map(b => String(b.address).toLowerCase()));
    const resumen = { pending: 0, warned: 0, banned: 0, dismissed: 0 };
    counts.forEach(c => { if (c._id in resumen) resumen[c._id] = c.n; });

    // Cuántas veces ha sido reportado cada acusado (señal de reincidencia).
    const objetivos = [...new Set(docs.map(d => d.targetAddress))];
    const totales = await PlayerReport.aggregate([
      { $match: { targetAddress: { $in: objetivos } } },
      { $group: { _id: '$targetAddress', n: { $sum: 1 } } }
    ]);
    const mapTotales = totales.reduce((m, x) => (m[x._id] = x.n, m), {});

    const reports = docs.map(d => ({
      id: String(d._id),
      reporterAddress: d.reporterAddress,
      reporterName: d.reporterName,
      targetAddress: d.targetAddress,
      targetName: d.targetName,
      reason: d.reason,
      details: d.details,
      scene: d.scene,
      posX: d.posX, posY: d.posY,
      status: d.status,
      adminAddress: d.adminAddress,
      adminNote: d.adminNote,
      handledAt: d.handledAt,
      createdAt: d.createdAt,
      isBanned: baneados.has(d.targetAddress),
      totalReportsAgainstTarget: mapTotales[d.targetAddress] || 1
    }));

    return res.json({ ok: true, reports, total, page, limit, pages: Math.ceil(total / limit), resumen });
  } catch (e) {
    console.error('GET /api/admin/reports:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── GET /api/admin/reports/:id ─────────────────────────────────────────────
// Reporte + ficha completa del acusado + su historial de reportes/verificadores.
app.get('/api/admin/reports/:id', adminAuth, apiLimiter, async (req, res) => {
  try {
    const doc = await PlayerReport.findById(req.params.id).lean();
    if (!doc) return res.status(404).json({ error: 'report_not_found' });

    const [perfil, historial, verificadores, ac] = await Promise.all([
      buildPlayerProfile(doc.targetAddress),
      PlayerReport.find({ targetAddress: doc.targetAddress }).sort({ createdAt: -1 }).limit(25).lean(),
      PlayerVerifier.find({ toAddress: doc.targetAddress }).sort({ createdAt: -1 }).limit(10).lean(),
      getAccessControl()
    ]);

    const ban = (ac.banned || []).find(b => String(b.address).toLowerCase() === doc.targetAddress);

    return res.json({
      ok: true,
      report: { ...doc, id: String(doc._id) },
      profile: perfil,
      isBanned: !!ban,
      ban: ban || null,
      history: historial.map(h => ({
        id: String(h._id), reason: h.reason, details: h.details,
        status: h.status, reporterName: h.reporterName, createdAt: h.createdAt
      })),
      verifiers: verificadores.map(v => ({
        id: String(v._id), from: v.fromName, status: v.status,
        question: v.question, given: v.given, createdAt: v.createdAt
      }))
    });
  } catch (e) {
    console.error('GET /api/admin/reports/:id:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── POST /api/admin/reports/:id/warn ───────────────────────────────────────
// Advertencia: entra en el buzón del juego y, si hay SMTP configurado
// (WARN_MAIL_* / SMTP_*), también sale por correo electrónico.
app.post('/api/admin/reports/:id/warn', adminAuth, strictLimiter, async (req, res) => {
  try {
    const doc = await PlayerReport.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'report_not_found' });

    const asunto = String(req.body?.subject || 'Official warning — Grassland Forest').slice(0, 140);
    const cuerpo = String(req.body?.body || '').slice(0, 2000) ||
      `Your account was reported for: ${doc.reason}. Repeated violations of the game rules will result in a ban.`;

    // 1) Buzón dentro del juego (siempre).
    let playerName = doc.targetName;
    try {
      const gp = await GamePlayer.findOne({ address: doc.targetAddress }).lean();
      if (gp && gp.playerName) playerName = gp.playerName;
    } catch (_) {}
    try {
      const store = getPlayerMail(playerName);
      store.unshift({
        id: Date.now().toString(),
        subject: asunto,
        body: cuerpo,
        from: 'Moderation',
        date: new Date().toISOString(),
        read: false
      });
    } catch (_) {}

    // 2) Aviso en vivo si está conectado.
    socketsOfAddress(doc.targetAddress).forEach(s => {
      try { s.emit('moderationWarning', { subject: asunto, body: cuerpo }); } catch (_) {}
    });

    // 3) Correo electrónico (solo si hay transporte configurado).
    const envio = await enviarCorreoAdvertencia(doc.targetAddress, asunto, cuerpo);

    doc.status = 'warned';
    doc.adminAddress = req.admin.address || '';
    doc.adminNote = String(req.body?.note || '').slice(0, 1000);
    doc.handledAt = new Date();
    await doc.save();

    return res.json({ ok: true, status: doc.status, email: envio });
  } catch (e) {
    console.error('POST /api/admin/reports/:id/warn:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// Envío de correo: opcional y perezoso. Si no hay nodemailer instalado o no hay
// SMTP configurado, se informa y NO se rompe nada (la advertencia igual llega
// al buzón del juego).
async function enviarCorreoAdvertencia(address, asunto, cuerpo) {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM || user;
  if (!host || !user || !pass) {
    return { sent: false, reason: 'smtp_not_configured' };
  }

  // El correo del jugador solo existe si el juego lo guardó alguna vez.
  let destino = null;
  try {
    const gp = await GamePlayer.findOne({ address: String(address).toLowerCase() }).lean();
    destino = (gp && (gp.email || gp.correo)) || null;
  } catch (_) {}
  if (!destino) return { sent: false, reason: 'player_has_no_email' };

  try {
    const nodemailer = require('nodemailer');
    const transporte = nodemailer.createTransport({
      host,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || '').toLowerCase() === 'true',
      auth: { user, pass }
    });
    await transporte.sendMail({ from, to: destino, subject: asunto, text: cuerpo });
    return { sent: true, to: destino };
  } catch (e) {
    console.warn('⚠️  No se pudo enviar el correo de advertencia:', e.message);
    return { sent: false, reason: e.message };
  }
}

// ── POST /api/admin/reports/:id/ban ────────────────────────────────────────
// Banea la cartera del acusado reutilizando el mismo AccessControl que ya usa
// puerta_login.html, y lo desconecta si está dentro.
app.post('/api/admin/reports/:id/ban', adminAuth, strictLimiter, async (req, res) => {
  try {
    const doc = await PlayerReport.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'report_not_found' });

    const motivo = String(req.body?.reason || `Reported for ${doc.reason}`).slice(0, 300);
    const ac = await getAccessControl();
    const banned = (ac.banned || []).filter(b => String(b.address).toLowerCase() !== doc.targetAddress);
    banned.push({ address: doc.targetAddress, reason: motivo, date: new Date() });

    await AccessControl.findOneAndUpdate({ _id: 'config' }, { $set: { banned } }, { upsert: true });
    invalidateAccessCache();

    // Expulsión inmediata de las sesiones abiertas.
    socketsOfAddress(doc.targetAddress).forEach(s => {
      try { s.emit('accountBanned', { reason: motivo }); s.disconnect(true); } catch (_) {}
    });

    doc.status = 'banned';
    doc.adminAddress = req.admin.address || '';
    doc.adminNote = String(req.body?.note || motivo).slice(0, 1000);
    doc.handledAt = new Date();
    await doc.save();

    console.warn(`⛔ [admin ${req.admin.address}] BANEÓ ${doc.targetAddress} — ${motivo}`);
    return res.json({ ok: true, status: doc.status });
  } catch (e) {
    console.error('POST /api/admin/reports/:id/ban:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── POST /api/admin/reports/:id/unban ──────────────────────────────────────
app.post('/api/admin/reports/:id/unban', adminAuth, strictLimiter, async (req, res) => {
  try {
    const doc = await PlayerReport.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'report_not_found' });

    const ac = await getAccessControl();
    const banned = (ac.banned || []).filter(b => String(b.address).toLowerCase() !== doc.targetAddress);
    await AccessControl.findOneAndUpdate({ _id: 'config' }, { $set: { banned } }, { upsert: true });
    invalidateAccessCache();

    doc.status = 'warned';
    doc.adminAddress = req.admin.address || '';
    doc.handledAt = new Date();
    await doc.save();

    return res.json({ ok: true, status: doc.status });
  } catch (e) {
    console.error('POST /api/admin/reports/:id/unban:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── DELETE /api/admin/reports/:id ──────────────────────────────────────────
// "Quitar de la lista sin hacerle nada": por defecto marca el reporte como
// descartado (queda el rastro). Con ?purge=1 se borra de verdad.
app.delete('/api/admin/reports/:id', adminAuth, strictLimiter, async (req, res) => {
  try {
    const purgar = String(req.query.purge || '') === '1';
    if (purgar) {
      const r = await PlayerReport.findByIdAndDelete(req.params.id);
      if (!r) return res.status(404).json({ error: 'report_not_found' });
      return res.json({ ok: true, deleted: true });
    }
    const doc = await PlayerReport.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'report_not_found' });
    doc.status = 'dismissed';
    doc.adminAddress = req.admin.address || '';
    doc.adminNote = String(req.body?.note || '').slice(0, 1000);
    doc.handledAt = new Date();
    await doc.save();
    return res.json({ ok: true, status: doc.status });
  } catch (e) {
    console.error('DELETE /api/admin/reports/:id:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── GET /api/admin/verifiers ───────────────────────────────────────────────
app.get('/api/admin/verifiers', adminAuth, apiLimiter, async (req, res) => {
  try {
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const docs = await PlayerVerifier.find({}).sort({ createdAt: -1 }).limit(limit).lean();
    return res.json({
      ok: true,
      verifiers: docs.map(v => ({
        id: String(v._id), from: v.fromName, fromAddress: v.fromAddress,
        to: v.toName, toAddress: v.toAddress, question: v.question,
        given: v.given, status: v.status, createdAt: v.createdAt, answeredAt: v.answeredAt
      }))
    });
  } catch (e) {
    console.error('GET /api/admin/verifiers:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── GET /api/admin/suspensions ─────────────────────────────────────────────
// Suspensiones temporales (las automáticas por verificadores y las manuales).
app.get('/api/admin/suspensions', adminAuth, apiLimiter, async (req, res) => {
  try {
    await caducarVerificadoresVencidos();
    const soloActivas = String(req.query.active || '') === '1';
    const filtro = soloActivas ? { liftedAt: null, until: { $gt: new Date() } } : {};
    const docs = await PlayerSuspension.find(filtro).sort({ createdAt: -1 }).limit(200).lean();
    const ahora = Date.now();
    return res.json({
      ok: true,
      rules: {
        seconds: VERIFIER_SECONDS,
        failsToSuspend: VERIFIER_FAILS_TO_BAN,
        suspendDays: VERIFIER_SUSPEND_DAYS,
        failWindowDays: VERIFIER_FAIL_WINDOW_DAYS
      },
      suspensions: docs.map(s => ({
        id: String(s._id),
        address: s.address,
        playerName: s.playerName,
        reason: s.reason,
        until: s.until,
        days: s.days,
        source: s.source,
        adminAddress: s.adminAddress,
        liftedAt: s.liftedAt,
        active: !s.liftedAt && new Date(s.until).getTime() > ahora,
        createdAt: s.createdAt
      }))
    });
  } catch (e) {
    console.error('GET /api/admin/suspensions:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── POST /api/admin/suspensions/:id/lift ───────────────────────────────────
app.post('/api/admin/suspensions/:id/lift', adminAuth, strictLimiter, async (req, res) => {
  try {
    const doc = await PlayerSuspension.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'suspension_not_found' });
    doc.liftedAt = new Date();
    doc.adminAddress = req.admin.address || '';
    await doc.save();
    invalidateAccessCache();
    return res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/admin/suspensions/:id/lift:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── POST /api/admin/reports/:id/suspend ────────────────────────────────────
// Suspensión manual desde el expediente de un reporte.
app.post('/api/admin/reports/:id/suspend', adminAuth, strictLimiter, async (req, res) => {
  try {
    const doc = await PlayerReport.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'report_not_found' });

    const dias = Math.max(1, Math.min(365, parseInt(req.body?.days, 10) || VERIFIER_SUSPEND_DAYS));
    const until = new Date(Date.now() + dias * 86400000);
    const motivo = String(req.body?.reason || `Reported for ${doc.reason}`).slice(0, 300);

    await PlayerSuspension.create({
      address: doc.targetAddress,
      playerName: doc.targetName,
      reason: motivo,
      until,
      days: dias,
      source: 'admin',
      adminAddress: req.admin.address || ''
    });
    invalidateAccessCache();

    socketsOfAddress(doc.targetAddress).forEach(s => {
      try {
        s.emit('accountSuspended', { reason: motivo, until: until.toISOString(), days: dias });
        s.disconnect(true);
      } catch (_) {}
    });

    doc.status = 'warned';
    doc.adminAddress = req.admin.address || '';
    doc.adminNote = `Suspended ${dias} day(s): ${motivo}`.slice(0, 1000);
    doc.handledAt = new Date();
    await doc.save();

    return res.json({ ok: true, until, days: dias });
  } catch (e) {
    console.error('POST /api/admin/reports/:id/suspend:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

console.log('✅ Reportes/verificadores: /api/reports, /api/verifier/*, /api/admin/reports/*');


// =============================================================================
// COMPRA DE DINERO CON TOPE DIARIO  (2026-08-04)
// -----------------------------------------------------------------------------
// Paquetes fijos: 1 = 1 $, 10 = 10 $, 100 = 100 $.
// Cada paquete tiene su PROPIO contador diario de 3 compras. Es decir: gastadas
// las 3 de 1 $, todavía quedan las 3 de 10 $ y las 3 de 100 $ hasta mañana.
// El contador vive en el SERVIDOR (nunca en el cliente) y el día se calcula en
// UTC para que no se pueda reiniciar cambiando la hora del teléfono.
// =============================================================================

const CURRENCY_PACKS = {
  1:   { gold: 1,   usd: 1   },
  10:  { gold: 10,  usd: 10  },
  100: { gold: 100, usd: 100 }
};
const CURRENCY_PACK_DAILY_LIMIT = 3;

const currencyPurchaseSchema = new mongoose.Schema({
  address: { type: String, required: true, lowercase: true, index: true },
  pack:    { type: Number, required: true },            // 1 | 10 | 100
  day:     { type: String, required: true },            // 'YYYY-MM-DD' en UTC
  count:   { type: Number, default: 0, min: 0 },
  lastAt:  { type: Date, default: null }
}, { timestamps: true });
currencyPurchaseSchema.index({ address: 1, pack: 1, day: 1 }, { unique: true });
const CurrencyPurchase = mongoose.model('CurrencyPurchase', currencyPurchaseSchema);

function diaUTC(d) {
  const x = d ? new Date(d) : new Date();
  return x.toISOString().slice(0, 10);
}

/** Cuántas compras quedan hoy de cada paquete. */
async function estadoComprasDelDia(address) {
  const addr = String(address || '').toLowerCase();
  const day = diaUTC();
  const docs = await CurrencyPurchase.find({ address: addr, day }).lean();
  const porPack = docs.reduce((m, d) => (m[d.pack] = d.count, m), {});

  const proximoReinicio = new Date();
  proximoReinicio.setUTCHours(24, 0, 0, 0);

  return {
    day,
    limit: CURRENCY_PACK_DAILY_LIMIT,
    resetsAt: proximoReinicio.toISOString(),
    packs: Object.keys(CURRENCY_PACKS).map(k => {
      const pack = Number(k);
      const usados = porPack[pack] || 0;
      return {
        pack,
        gold: CURRENCY_PACKS[pack].gold,
        usd:  CURRENCY_PACKS[pack].usd,
        used: usados,
        remaining: Math.max(0, CURRENCY_PACK_DAILY_LIMIT - usados)
      };
    })
  };
}

// ── GET /api/currency/purchase/limits ──────────────────────────────────────
app.get('/api/currency/purchase/limits', apiLimiter, authMiddleware, async (req, res) => {
  try {
    return res.json({ ok: true, ...(await estadoComprasDelDia(req.user.address)) });
  } catch (e) {
    console.error('GET /api/currency/purchase/limits:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ── POST /api/currency/purchase ────────────────────────────────────────────
// body: { pack: 1|10|100, txHash?: string }
// El apunte del contador y la acuñación del oro los hace el SERVIDOR. El
// cliente no puede saltarse el tope aunque manipule su copia del juego.
app.post('/api/currency/purchase',
  strictLimiter,
  authMiddleware,
  csrfProtection,
  [ body('pack').isInt(), body('txHash').optional().isString().isLength({ max: 120 }) ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const address = String(req.user.address || '').toLowerCase();
      const pack = parseInt(req.body.pack, 10);
      const cfg = CURRENCY_PACKS[pack];
      if (!cfg) return res.status(400).json({ error: 'invalid_pack' });

      const day = diaUTC();

      // Apunte ATÓMICO: el $inc con la condición del tope evita que dos
      // peticiones a la vez cuelen una compra de más.
      const doc = await CurrencyPurchase.findOneAndUpdate(
        { address, pack, day, count: { $lt: CURRENCY_PACK_DAILY_LIMIT } },
        { $inc: { count: 1 }, $set: { lastAt: new Date() } },
        { new: true, upsert: false }
      );

      let apunte = doc;
      if (!apunte) {
        // O no existía todavía el documento de hoy, o ya llegó al tope.
        const existente = await CurrencyPurchase.findOne({ address, pack, day }).lean();
        if (existente && existente.count >= CURRENCY_PACK_DAILY_LIMIT) {
          const estado = await estadoComprasDelDia(address);
          return res.status(429).json({
            error: 'daily_pack_limit_reached',
            pack,
            limit: CURRENCY_PACK_DAILY_LIMIT,
            resetsAt: estado.resetsAt,
            message: `You already bought the $${cfg.usd} pack ${CURRENCY_PACK_DAILY_LIMIT} times today`
          });
        }
        try {
          apunte = await CurrencyPurchase.create({ address, pack, day, count: 1, lastAt: new Date() });
        } catch (dup) {
          // Carrera con otra petición que lo creó primero: se reintenta el $inc.
          apunte = await CurrencyPurchase.findOneAndUpdate(
            { address, pack, day, count: { $lt: CURRENCY_PACK_DAILY_LIMIT } },
            { $inc: { count: 1 }, $set: { lastAt: new Date() } },
            { new: true }
          );
          if (!apunte) {
            const estado = await estadoComprasDelDia(address);
            return res.status(429).json({
              error: 'daily_pack_limit_reached', pack,
              limit: CURRENCY_PACK_DAILY_LIMIT, resetsAt: estado.resetsAt
            });
          }
        }
      }

      // Acreditar el oro en la factura on-chain del jugador.
      let acreditado = false;
      let errorCredito = null;
      try {
        const gp = await GamePlayer.findOne({ address }).lean();
        if (!gp || !gp.playerName) throw new Error('player_not_found');
        const stats = await PlayerStats.findOne({ playerName: gp.playerName });
        if (!stats) throw new Error('stats_not_found');

        const nuevoOro = Number(stats.oro || 0) + cfg.gold;
        const contract = getStatsContract();
        const gasPrice = await getSafeGasPriceStats();
        const invId = stats.invoiceIds && stats.invoiceIds.oro;

        if (contract && invId) {
          const r = await applyStatOnChain(contract, 'oro', invId, nuevoOro, gasPrice);
          if (!r.ok) throw new Error(r.error || 'onchain_failed');
        }
        stats.oro = nuevoOro;
        await stats.save();
        acreditado = true;
      } catch (e) {
        errorCredito = e.message || String(e);
        console.error('❌ No se pudo acreditar la compra de oro:', errorCredito);
        // El apunte se DESHACE: si no se entregó el oro, esa compra no puede
        // gastar el cupo del día.
        try {
          await CurrencyPurchase.updateOne(
            { address, pack, day, count: { $gt: 0 } },
            { $inc: { count: -1 } }
          );
        } catch (_) {}
      }

      const estado = await estadoComprasDelDia(address);
      if (!acreditado) {
        return res.status(502).json({ error: 'credit_failed', detail: errorCredito, ...estado });
      }

      console.log(`💵 ${address.slice(0, 10)}… compró el paquete de $${cfg.usd} (+${cfg.gold} oro)`);
      return res.json({ ok: true, pack, gold: cfg.gold, usd: cfg.usd, ...estado });
    } catch (e) {
      console.error('POST /api/currency/purchase:', e);
      return res.status(500).json({ error: 'internal_error' });
    }
  }
);

console.log('✅ Compra de dinero: /api/currency/purchase (3/día por paquete)');


// =============================================================================
// CONFIGURACIÓN DE SIEMBRA (editable desde admin.html)          (2026-08-04)
// -----------------------------------------------------------------------------
// Antes, la probabilidad de que un cultivo saliera bien la mandaba el CLIENTE
// (`successChance` en el socket 'plantSeed'), y calcularPosibilidad() del juego
// devolvía siempre 100. Es decir: ni había dificultad, ni se podía cambiar sin
// tocar el código, y además un cliente manipulado podía mandar lo que quisiera.
//
// Ahora manda esta configuración del servidor: dificultad global, ajustes por
// semilla, tiempo de crecimiento y probabilidad de que el cultivo muera.
// =============================================================================

const farmingConfigSchema = new mongoose.Schema({
  _id:            { type: String, default: 'config' },
  successChance:  { type: Number, default: 95, min: 1, max: 100 },   // dificultad global
  perSeed:        { type: Map, of: Number, default: {} },            // Semillax → 20, …
  growthMultiplier:{ type: Number, default: 1, min: 0.1, max: 10 },  // ×tiempo de crecimiento
  waterCostMultiplier: { type: Number, default: 1, min: 0, max: 10 },
  foodCostMultiplier:  { type: Number, default: 1, min: 0, max: 10 },
  deathEnabled:   { type: Boolean, default: true },                  // ¿pueden morir?
  updatedBy:      { type: String, default: '' }
}, { timestamps: true, _id: false });
const FarmingConfig = mongoose.model('FarmingConfig', farmingConfigSchema);

// Caché de 30 s: plantSeed se llama muy a menudo y no puede ir a Mongo cada vez.
const _farmingCache = { doc: null, at: 0 };
async function getFarmingConfig() {
  const ahora = Date.now();
  if (_farmingCache.doc && (ahora - _farmingCache.at) < 30000) return _farmingCache.doc;
  let doc = await FarmingConfig.findById('config').lean();
  if (!doc) {
    await FarmingConfig.create({ _id: 'config' });
    doc = await FarmingConfig.findById('config').lean();
  }
  _farmingCache.doc = doc;
  _farmingCache.at = ahora;
  return doc;
}
function invalidateFarmingCache() { _farmingCache.doc = null; _farmingCache.at = 0; }

/** Probabilidad final de éxito para una semilla, según la configuración. */
async function successChanceParaSemilla(seedType) {
  const cfg = await getFarmingConfig();
  const perSeed = cfg.perSeed || {};
  // Mongoose devuelve el Map como objeto plano con .lean()
  const propia = perSeed instanceof Map ? perSeed.get(seedType) : perSeed[seedType];
  const valor = Number(propia);
  const base = Number.isFinite(valor) && valor > 0 ? valor : Number(cfg.successChance);
  return Math.max(1, Math.min(100, Number.isFinite(base) ? base : 95));
}

// Lo consulta el juego para enseñar la dificultad real antes de sembrar.
app.get('/api/farming-config', apiLimiter, authMiddleware, async (req, res) => {
  try {
    const cfg = await getFarmingConfig();
    const perSeed = cfg.perSeed instanceof Map ? Object.fromEntries(cfg.perSeed) : (cfg.perSeed || {});
    return res.json({
      ok: true,
      successChance: cfg.successChance,
      perSeed,
      growthMultiplier: cfg.growthMultiplier,
      waterCostMultiplier: cfg.waterCostMultiplier,
      foodCostMultiplier: cfg.foodCostMultiplier,
      deathEnabled: cfg.deathEnabled
    });
  } catch (e) {
    console.error('GET /api/farming-config:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/api/admin/farming-config', adminAuth, apiLimiter, async (req, res) => {
  try {
    const cfg = await getFarmingConfig();
    const perSeed = cfg.perSeed instanceof Map ? Object.fromEntries(cfg.perSeed) : (cfg.perSeed || {});
    return res.json({
      ok: true,
      config: {
        successChance: cfg.successChance,
        perSeed,
        growthMultiplier: cfg.growthMultiplier,
        waterCostMultiplier: cfg.waterCostMultiplier,
        foodCostMultiplier: cfg.foodCostMultiplier,
        deathEnabled: cfg.deathEnabled,
        updatedBy: cfg.updatedBy,
        updatedAt: cfg.updatedAt
      },
      seeds: Object.keys(cropController ? cropController.cropTypes : {})
    });
  } catch (e) {
    console.error('GET /api/admin/farming-config:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

app.put('/api/admin/farming-config', adminAuth, strictLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const update = { updatedBy: req.admin.address || '' };

    const num = (v, min, max) => {
      const n = Number(v);
      return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : null;
    };

    const sc = num(b.successChance, 1, 100);
    if (sc !== null) update.successChance = sc;

    const gm = num(b.growthMultiplier, 0.1, 10);
    if (gm !== null) update.growthMultiplier = gm;

    const wm = num(b.waterCostMultiplier, 0, 10);
    if (wm !== null) update.waterCostMultiplier = wm;

    const fm = num(b.foodCostMultiplier, 0, 10);
    if (fm !== null) update.foodCostMultiplier = fm;

    if (typeof b.deathEnabled === 'boolean') update.deathEnabled = b.deathEnabled;

    if (b.perSeed && typeof b.perSeed === 'object') {
      const limpio = {};
      Object.keys(b.perSeed).slice(0, 40).forEach(k => {
        const n = num(b.perSeed[k], 1, 100);
        // 0 / vacío = "sin ajuste propio", se usa la dificultad global.
        if (n !== null && String(b.perSeed[k]).trim() !== '') limpio[String(k).slice(0, 40)] = n;
      });
      update.perSeed = limpio;
    }

    await FarmingConfig.findByIdAndUpdate('config', { $set: update }, { upsert: true });
    invalidateFarmingCache();

    const cfg = await getFarmingConfig();
    const perSeed = cfg.perSeed instanceof Map ? Object.fromEntries(cfg.perSeed) : (cfg.perSeed || {});
    console.log(`🌱 [admin ${req.admin.address}] configuración de siembra actualizada (éxito ${cfg.successChance}%)`);
    return res.json({ ok: true, config: { ...cfg, perSeed } });
  } catch (e) {
    console.error('PUT /api/admin/farming-config:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

console.log('✅ Configuración de siembra: /api/admin/farming-config');


// =============================================================================
// CONFIGURACIÓN DE LA TABLA DE CLASIFICACIÓN (admin.html)       (2026-08-04)
// =============================================================================
const leaderboardConfigSchema = new mongoose.Schema({
  _id:          { type: String, default: 'config' },
  enabled:      { type: Boolean, default: true },
  topSize:      { type: Number, default: 20, min: 3, max: 100 },
  minBattles:   { type: Number, default: 0, min: 0, max: 1000 },
  hideBanned:   { type: Boolean, default: true },
  hideSuspended:{ type: Boolean, default: true },
  hideBots:     { type: Boolean, default: true },
  seasonLabel:  { type: String, default: '', maxlength: 60 },
  updatedBy:    { type: String, default: '' }
}, { timestamps: true, _id: false });
const LeaderboardConfig = mongoose.model('LeaderboardConfig', leaderboardConfigSchema);

const _lbCache = { doc: null, at: 0 };
async function getLeaderboardConfig() {
  const ahora = Date.now();
  if (_lbCache.doc && (ahora - _lbCache.at) < 30000) return _lbCache.doc;
  let doc = await LeaderboardConfig.findById('config').lean();
  if (!doc) {
    await LeaderboardConfig.create({ _id: 'config' });
    doc = await LeaderboardConfig.findById('config').lean();
  }
  _lbCache.doc = doc;
  _lbCache.at = ahora;
  return doc;
}
function invalidateLeaderboardCache() { _lbCache.doc = null; _lbCache.at = 0; }

/**
 * Direcciones que NO deben salir en la clasificación: baneadas y suspendidas.
 * @returns {Promise<Set<string>>} direcciones en minúsculas
 */
async function direccionesExcluidasDeClasificacion(cfg) {
  const fuera = new Set();
  if (cfg.hideBanned) {
    try {
      const ac = await getAccessControlCached();
      (ac.banned || []).forEach(b => fuera.add(String(b.address).toLowerCase()));
    } catch (_) {}
  }
  if (cfg.hideSuspended) {
    try {
      const activas = await PlayerSuspension.find({
        liftedAt: null, until: { $gt: new Date() }
      }).select('address -_id').lean();
      activas.forEach(s => fuera.add(String(s.address).toLowerCase()));
    } catch (_) {}
  }
  return fuera;
}

/**
 * Nombres de jugador excluidos. Hace falta además de las direcciones porque
 * BattleScore guarda `address` solo si la tenía al registrar la puntuación:
 * en las filas antiguas puede estar vacía, y solo con la dirección un baneado
 * seguiría apareciendo en el podio.
 */
async function nombresExcluidosDeClasificacion(direcciones) {
  if (!direcciones || direcciones.size === 0) return new Set();
  try {
    const docs = await GamePlayer.find({ address: { $in: [...direcciones] } })
      .select('playerName -_id').lean();
    return new Set(docs.map(d => d.playerName).filter(Boolean));
  } catch (_) {
    return new Set();
  }
}

app.get('/api/admin/leaderboard-config', adminAuth, apiLimiter, async (req, res) => {
  try {
    const cfg = await getLeaderboardConfig();
    const fuera = await direccionesExcluidasDeClasificacion(cfg);
    return res.json({ ok: true, config: cfg, excludedCount: fuera.size });
  } catch (e) {
    console.error('GET /api/admin/leaderboard-config:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

app.put('/api/admin/leaderboard-config', adminAuth, strictLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const update = { updatedBy: req.admin.address || '' };

    if (typeof b.enabled === 'boolean')       update.enabled = b.enabled;
    if (typeof b.hideBanned === 'boolean')    update.hideBanned = b.hideBanned;
    if (typeof b.hideSuspended === 'boolean') update.hideSuspended = b.hideSuspended;
    if (typeof b.hideBots === 'boolean')      update.hideBots = b.hideBots;

    const ts = parseInt(b.topSize, 10);
    if (Number.isFinite(ts)) update.topSize = Math.max(3, Math.min(100, ts));

    const mb = parseInt(b.minBattles, 10);
    if (Number.isFinite(mb)) update.minBattles = Math.max(0, Math.min(1000, mb));

    if (typeof b.seasonLabel === 'string') update.seasonLabel = b.seasonLabel.slice(0, 60);

    await LeaderboardConfig.findByIdAndUpdate('config', { $set: update }, { upsert: true });
    invalidateLeaderboardCache();

    console.log(`🏆 [admin ${req.admin.address}] configuración de clasificación actualizada`);
    return res.json({ ok: true, config: await getLeaderboardConfig() });
  } catch (e) {
    console.error('PUT /api/admin/leaderboard-config:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

console.log('✅ Configuración de clasificación: /api/admin/leaderboard-config');


// Marketplace P2P — todas las rutas /api/marketplace/* viven en marketplace-routes.js
// (se monta más abajo, después de que PlayerStats esté definido — ver "MARKETPLACE ROUTES MOUNT")

// Error Reports
// `apiLimiter` añadido al conectar el reporte de errores del cliente
// (GameScene.errorReporter). Hasta ahora la ruta no recibía nada porque el
// reportero nunca arrancaba; ahora sí, y un cliente atrapado en un bucle de
// errores podría inundar la colección de reportes él solo. El limitador corta
// eso sin afectar al uso normal, que son unos pocos reportes por sesión.
app.post('/api/report-error', apiLimiter, async (req, res) => {
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

                // ── SIN DUPLICADOS ────────────────────────────────────────
                // Antes esto hacía `new ErrorReport(...).save()`. Como
                // `errorId` es único, el mismo error repetido reventaba con un
                // error de clave duplicada que se tragaba el catch de abajo: no
                // se duplicaba la fila, pero tampoco se registraba que había
                // vuelto a pasar. Los campos `count` y `lastSeen` del esquema
                // estaban ahí sin que nadie los usara.
                //
                // Ahora es un upsert: la primera vez crea la ficha; las
                // siguientes solo suman al contador y actualizan la última vez
                // que se vio. Así la bandeja muestra CADA error UNA sola vez,
                // con cuántas veces ha ocurrido — que es la información que
                // de verdad sirve para priorizar.
                const res$ = await ErrorReport.findOneAndUpdate(
                    { errorId: errorId },
                    {
                        $inc: { count: 1 },
                        $set: {
                            lastSeen: new Date(),
                            // Los datos de la ÚLTIMA vez que ocurrió: si el
                            // mismo fallo aparece ahora en otra escena o a otro
                            // jugador, interesa ver el caso más reciente.
                            scene:      error.scene    || 'unknown',
                            url:        error.url      || 'unknown',
                            userAgent:  error.userAgent|| 'unknown',
                            playerName: error.playerName || 'unknown'
                        },
                        $setOnInsert: {
                            errorId: errorId,
                            type:    error.type || 'unknown',
                            message: (error.message || 'Sin mensaje').substring(0, 800),
                            phaserVersion: error.phaserVersion || 'unknown',
                            timestamp: new Date(error.timestamp || Date.now()),
                            line:   error.line   || 'unknown',
                            column: error.column || 'unknown',
                            file:   error.file   || 'unknown',
                            stack:  error.stack ? error.stack.substring(0, 1500) : undefined
                        }
                    },
                    { upsert: true, new: false, setDefaultsOnInsert: true }
                );

                // `new: false` devuelve el documento ANTERIOR: si es null, esta
                // es la primera vez que se ve este error.
                if (!res$) guardadosNuevos++;
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
// FUGA DE INFORMACIÓN QUE ESTO TAPA: esta ruta era pública y sin límite, y
// devolvía el número exacto de jugadores conectados y los nombres de las salas
// activas. Es justo el reconocimiento previo que busca alguien antes de atacar
// (saber cuándo hay poca gente, qué salas existen). Ahora pide sesión y va
// limitada, igual que el resto de la API.
app.get('/api/socket/status', apiLimiter, authMiddleware, (req, res) => {
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
  // Escala de juego 0..100 (las barras se pintan como `${valor}%` sin dividir).
  // Antes el default era 100000 y, combinado con el piso Math.max del sync,
  // producía barras de "100000%".
  // NOTA: sin validador `max` a propósito — hay documentos viejos con 100000 y
  // un max haría fallar su .save() con error de validación. El recorte se hace
  // con clampStat() al escribir y al responder.
  vida:       { type: Number, default: 100, min: 0 },
  agua:       { type: Number, default: 100, min: 0 },
  comida:     { type: Number, default: 100, min: 0 },

  /* VIDA CONGELADA MIENTRAS ESTÁS MUERTO.

     Quién manda sobre estar muerto es GamePlayer.isGhost, pero la regeneración
     pasiva trabaja sobre ESTE documento y no lee aquél. Antes que hacer una
     lectura cruzada en cada tic —que es el camino caliente, se llama en casi
     todas las rutas— se apunta aquí la misma decisión en el único momento en
     que puede cambiar: al morir y al revivir.

     Sin esto la vida del fantasma trepaba sola desde 0 mientras esperaba a
     pagar el revivir. */
  vidaCongelada: { type: Boolean, default: false },
  oro:        { type: Number, default: 0,      min: 0 },
  plata:      { type: Number, default: 0,      min: 0 },
  // Experiencia del personaje (GamePlayer.nivel_exp). Se lleva al contrato con
  // su propia tabla `exp`, igual que oro y plata.
  exp:        { type: Number, default: 0,      min: 0 },
  invoiceIds: {
    vida:   { type: Number, default: null },
    agua:   { type: Number, default: null },
    comida: { type: Number, default: null },
    oro:    { type: Number, default: null },
    plata:  { type: Number, default: null },
    exp:    { type: Number, default: null },
  },
  manualIds: {
    vida:   { type: String, default: null },
    agua:   { type: String, default: null },
    comida: { type: String, default: null },
    oro:    { type: String, default: null },
    plata:  { type: String, default: null },
    exp:    { type: String, default: null },
  },
  // Marca de tiempo de la ÚLTIMA regeneración pasiva de vitales aplicada.
  // La regeneración se calcula por diferencia de tiempo (ver
  // applyGhostVitalRegen), así que también cuenta el rato que el jugador estuvo
  // DESCONECTADO sin necesidad de ningún temporizador por jugador.
  lastVitalRegen: { type: Date, default: null },
  // DEUDA CON LA CADENA (liquidación agrupada, 2026-08-05).
  // Lista de stats cuyo valor en Mongo ya está cobrado pero todavía no se ha
  // escrito en su factura. El liquidador (liquidarPendientesDeCadena) las
  // convierte en UNA transacción por barra cada minuto. Vive en la BASE DE
  // DATOS a propósito: si el jugador recarga o cierra el navegador, la deuda
  // sigue aquí y se liquida igual — no hay forma de escaparse gastando y
  // recargando la página.
  chainPending:      { type: [String], default: [] },
  chainPendingSince: { type: Date, default: null },

  // ── RESTO FRACCIONARIO DE LOS COSTES ───────────────────────────────────────
  // Las barras vitales son NÚMEROS ENTEROS, pero varias acciones cuestan
  // fracciones: sembrar vale 0,2 de comida y regar 0,5 de agua.
  //
  // BUG QUE ESTO ARREGLA: /consume hacía `Math.round(coste)` y descartaba lo
  // que diera 0. O sea que 0,2 de comida se convertía en 0 y sembrar NUNCA ha
  // costado comida, mientras que 0,5 de agua se redondeaba a 1 y regar costaba
  // el DOBLE de lo definido.
  //
  // Ahora el sobrante se guarda aquí y se arrastra a la siguiente acción:
  // sembrar cinco veces (5 × 0,2) cobra 1 de comida, que es justo lo que la
  // tabla de cultivos quería decir. Vive en la base de datos para que no se
  // pueda tirar recargando la página.
  vitalFractions: {
    vida:   { type: Number, default: 0 },
    agua:   { type: Number, default: 0 },
    comida: { type: Number, default: 0 }
  },

  lastSync:    { type: Date, default: null },
  lastUpdated: { type: Date, default: Date.now },
  createdAt:   { type: Date, default: Date.now },
}, { collection: 'player_stats', timestamps: { createdAt: 'createdAt', updatedAt: 'lastUpdated' } });

const PlayerStats = mongoose.model('PlayerStats', playerStatsSchema);

const STAT_TYPES_LIST    = ['vida', 'agua', 'comida', 'oro', 'plata', 'exp'];

// ⚠️ ESCALA DE LAS VITALES: en el juego las barras se pintan como `${valor}%`
// SIN dividir, así que la escala real de vida/agua/comida es 0..100.
// Antes estos mapas estaban en 100000 y eso causaba DOS bugs:
//   • "100000%": el sync usaba STAT_DEFAULTS_MAP como PISO (Math.max), así que
//     un valor legítimo bajo (0, 1, o tu 34%) saltaba a 100000.
//   • "7%" / "5%" en jugadores nuevos: la factura se creaba pidiendo 100000
//     unidades, lo que agota el cupo (`limit`) del tipo en el contrato; cuando
//     quedaban 7 o 5 disponibles, el jugador nuevo nacía con 7% o 5%.
const VITAL_MAX          = 100;
const STAT_DEFAULTS_MAP  = { vida: VITAL_MAX, agua: VITAL_MAX, comida: VITAL_MAX, oro: 0, plata: 0, exp: 0 };
// Valores con los que se CREA la factura de un jugador nuevo. Separado de
// STAT_DEFAULTS_MAP porque ese mapa actúa como "piso" en el sync — si oro/plata
// tuvieran piso 1000, cada sync regalaría monedas a jugadores que ya gastaron.
const STAT_INITIAL_MAP   = { vida: VITAL_MAX, agua: VITAL_MAX, comida: VITAL_MAX, oro: 1000, plata: 1000, exp: 0 };

const isVitalStat = (stat) => stat === 'vida' || stat === 'agua' || stat === 'comida';
const VITAL_STATS = ['vida', 'agua', 'comida'];
// Acota un stat a su rango válido: las vitales a 0..100; oro/plata/exp solo a >= 0.
function clampStat(stat, value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return 0;
  return isVitalStat(stat) ? Math.min(VITAL_MAX, n) : n;
}

// =============================================================================
// REGENERACIÓN PASIVA DE VITALES — "MODO FANTASMA"            (2026-08-05)
// -----------------------------------------------------------------------------
// Pedido: vida, agua y comida suben cada 3 MINUTOS, esté el jugador conectado
// o no. (Antes era cada minuto; se bajó el ritmo a un tercio.)
//
// Hacerlo con una transacción por tic y por jugador es inviable (miles de
// transacciones al día por cuenta, casi todas para sumar 1). Así que la subida
// se lleva en MODO FANTASMA: vive solo en Mongo y se calcula por DIFERENCIA DE
// TIEMPO contra `lastVitalRegen`. Ventajas:
//
//   • No hace falta ningún temporizador por jugador: el valor correcto se
//     obtiene en el momento en que alguien lo lee.
//   • El tiempo DESCONECTADO cuenta igual que el conectado (es la misma resta).
//   • Cero transacciones mientras solo se regenera.
//
// La cadena se pone al día SOLA en el primer movimiento real del jugador
// (gastar, recargar, sincronizar): applyStatOnChain calcula el delta contra la
// cantidad REAL de la factura, así que al escribir el valor ya regenerado la
// factura salta directamente al número correcto con UNA sola transacción.
//
// Regla de convergencia: el fantasma solo SUMA. Por eso, cuando Mongo va por
// delante de la cadena en una vital, gana Mongo (es regeneración pendiente de
// materializar); cuando va por detrás, gana la cadena (hubo un gasto).
// =============================================================================
// RITMO DE REGENERACIÓN.
// Cada "tic" suma VITAL_REGEN_PER_TICK puntos a cada barra vital.
// El tic dura VITAL_REGEN_TICK_MS: 3 minutos (antes era 1).
// Llenar una barra desde cero pasa de 100 min a 300 min (5 h).
const VITAL_REGEN_TICK_MS   = 3 * 60 * 1000;
const VITAL_REGEN_PER_TICK  = 1;
// Tope de acumulación: aunque la cuenta lleve meses parada, como mucho se
// aplican los tics necesarios para llenar las barras desde cero.
const VITAL_REGEN_MAX_TICKS = Math.ceil(VITAL_MAX / VITAL_REGEN_PER_TICK);

/**
 * Aplica al documento (en memoria, sin guardar ni tocar la cadena) la
 * regeneración acumulada desde `lastVitalRegen`.
 *
 * El reloj avanza SIEMPRE que pase al menos un tic, aunque las barras ya
 * estuvieran llenas; si no, un jugador con todo al 100 % acumularía "crédito"
 * infinito y al gastar se le rellenaría al instante.
 *
 * @returns {{changed:boolean, minutes:number, gain:number}}
 *   `minutes` conserva el nombre por compatibilidad con quien lo lee, pero
 *   ahora cuenta TICS de VITAL_REGEN_TICK_MS, no minutos.
 */
function applyGhostVitalRegen(doc, now = new Date()) {
  if (!doc) return { changed: false, minutes: 0, gain: 0 };

  const ahora = now.getTime();
  if (!doc.lastVitalRegen) {
    // Primera vez que se ve a este jugador: se arranca el reloj, sin regalar nada.
    doc.lastVitalRegen = now;
    return { changed: false, minutes: 0, gain: 0 };
  }

  const desde = new Date(doc.lastVitalRegen).getTime();
  const tics  = Math.floor((ahora - desde) / VITAL_REGEN_TICK_MS);
  if (tics <= 0) return { changed: false, minutes: 0, gain: 0 };

  // El resto NO se pierde: el reloj avanza solo los tics enteros consumidos,
  // así que los segundos sobrantes cuentan para el próximo tic.
  doc.lastVitalRegen = new Date(desde + tics * VITAL_REGEN_TICK_MS);

  const ganancia = Math.min(tics, VITAL_REGEN_MAX_TICKS) * VITAL_REGEN_PER_TICK;
  let changed = false;
  for (const stat of VITAL_STATS) {
    /* MUERTO NO SE CURA SOLO.

       EL FALLO QUE ARREGLA: la regeneración pasiva subía las TRES barras sin
       mirar si el jugador estaba muerto, así que un fantasma veía cómo su vida
       trepaba desde 0 mientras esperaba a pagar el revivir. Además el propio
       vigilante de muerte podía dejar de verla en 0 y sacarlo del estado
       fantasma sin haber pagado.

       Agua y comida sí siguen subiendo: el hambre y la sed no se paran porque
       te hayan mordido, y no dan nada gratis. */
    if (stat === 'vida' && doc.vidaCongelada) continue;
    const actual = clampStat(stat, doc[stat]);
    const nuevo  = clampStat(stat, actual + ganancia);
    if (nuevo !== doc[stat]) { doc[stat] = nuevo; changed = true; }
  }
  return { changed, minutes: tics, gain: ganancia };
}

/**
 * Igual que applyGhostVitalRegen, pero además persiste en Mongo si hubo algún
 * cambio (incluido el avance del reloj). NO manda transacciones: la cadena se
 * pone al día en el siguiente movimiento real.
 */
async function regenerarVitalesEnBD(doc, now = new Date()) {
  const r = applyGhostVitalRegen(doc, now);
  if (r.minutes > 0) {
    try { await doc.save(); }
    catch (e) { console.warn('⚠️  No se pudo guardar la regeneración fantasma:', e.message); }
  }
  return r;
}

// =============================================================================
// LIQUIDACIÓN AGRUPADA DE VITALES — 1 TRANSACCIÓN POR BARRA   (2026-08-05)
// -----------------------------------------------------------------------------
// PROBLEMA de la versión anterior: /consume escribía en la cadena EN EL ACTO,
// una transacción por barra y por golpe. Talar un árbol de 7 golpes = 14
// transacciones, y encima el jugador esperaba cada una. Absurdo: la barra de
// agua es UN número, no hace falta escribirlo 7 veces para bajarlo 7 puntos.
//
// AHORA hay dos tiempos distintos:
//
//   1. COBRO (instantáneo, autoritativo).  /consume comprueba el saldo y lo
//      descuenta en Mongo al momento. El jugador no espera a ninguna cadena, y
//      el servidor ya decidió: si no había saldo, la acción no ocurre.
//
//   2. LIQUIDACIÓN (agrupada, cada minuto). Un trabajador de fondo coge lo que
//      esté marcado en `chainPending` y escribe el valor ACTUAL de cada barra
//      en su factura: UNA transacción por barra, por mucho que el jugador haya
//      dado 50 golpes en ese minuto. applyStatOnChain calcula el delta contra
//      la cantidad real de la factura, así que un solo movimiento la deja en el
//      número correcto.
//
// POR QUÉ LA DEUDA VIVE EN MONGO Y NO EN EL NAVEGADOR: si el jugador recarga la
// página, cierra la pestaña o se le va internet justo después de gastar, la
// marca sigue en la base de datos y el trabajador la liquida igual. No se puede
// "huir" de un consumo recargando el navegador. Y si se reinicia el servidor,
// el arranque hace una pasada de liquidación con lo que quedara pendiente.
// =============================================================================

// Cuánto espera una deuda antes de escribirse en la cadena.
const CHAIN_SETTLE_DELAY_MS   = 60 * 1000;
// Cada cuánto mira el trabajador si hay algo que liquidar.
const CHAIN_SETTLE_TICK_MS    = 20 * 1000;
// Cuántos jugadores se liquidan por ronda (para no saturar el relayer).
const CHAIN_SETTLE_BATCH      = 25;

/** Apunta que estos stats han cambiado en Mongo y deben escribirse en la cadena. */
function marcarPendienteDeCadena(doc, stats) {
  if (!doc) return;
  const lista = new Set(Array.isArray(doc.chainPending) ? doc.chainPending : []);
  let añadido = false;
  for (const s of [].concat(stats || [])) {
    if (STAT_TYPES_LIST.includes(s) && !lista.has(s)) { lista.add(s); añadido = true; }
  }
  if (!añadido) return;
  doc.chainPending = Array.from(lista);
  if (!doc.chainPendingSince) doc.chainPendingSince = new Date();
  doc.markModified('chainPending');
}

/**
 * Escribe en la cadena TODOS los stats pendientes de un jugador: una sola
 * transacción por stat, con el valor que tenga Mongo en este momento.
 *
 * Un stat solo se saca de la lista si su transacción salió bien; si falla
 * (nodo caído, sin cupo) se queda pendiente y se reintenta en la ronda
 * siguiente, así que la deuda nunca se pierde en silencio.
 *
 * @returns {{liquidados:string[], fallidos:string[]}}
 */
async function liquidarPendientesDeCadena(doc) {
  const pendientes = Array.isArray(doc.chainPending) ? doc.chainPending.slice() : [];
  if (!pendientes.length) return { liquidados: [], fallidos: [] };

  const contract = getStatsContract();
  if (!contract) return { liquidados: [], fallidos: pendientes };

  const gasPrice   = await getSafeGasPriceStats();
  const liquidados = [];
  const fallidos   = [];

  for (const stat of pendientes) {
    const invId = doc.invoiceIds && doc.invoiceIds[stat];
    if (!invId) {
      // Todavía no hay factura: la creará /sync con el valor de Mongo, así que
      // esta deuda ya está cubierta y deja de estar pendiente.
      liquidados.push(stat);
      continue;
    }
    const objetivo = clampStat(stat, doc[stat]);
    const r = await applyStatOnChain(contract, stat, invId, objetivo, gasPrice);
    if (r.ok) {
      liquidados.push(stat);
    } else {
      console.error(`❌ liquidación [${stat}] de ${doc.playerName}:`, r.error);
      fallidos.push(stat);
    }
  }

  doc.chainPending      = fallidos;
  doc.chainPendingSince = fallidos.length ? (doc.chainPendingSince || new Date()) : null;
  doc.markModified('chainPending');
  try { await doc.save(); }
  catch (e) { console.warn('⚠️  No se pudo guardar tras liquidar:', e.message); }

  if (liquidados.length) {
    console.log(`⛓️  Liquidado [${liquidados.join(', ')}] de ${doc.playerName} ` +
                `(vida=${doc.vida} agua=${doc.agua} comida=${doc.comida})`);
  }
  return { liquidados, fallidos };
}

// Evita que dos rondas se pisen si una tarda más que el intervalo.
let _liquidacionEnCurso = false;

async function rondaDeLiquidacion({ inmediato = false } = {}) {
  if (_liquidacionEnCurso) return;
  if (!relayerWallet) return;
  _liquidacionEnCurso = true;
  try {
    const limite = new Date(Date.now() - (inmediato ? 0 : CHAIN_SETTLE_DELAY_MS));
    const docs = await PlayerStats.find({
      'chainPending.0':  { $exists: true },
      chainPendingSince: { $lte: limite }
    }).limit(CHAIN_SETTLE_BATCH);

    for (const doc of docs) {
      try { await liquidarPendientesDeCadena(doc); }
      catch (e) { console.error(`❌ Error liquidando ${doc.playerName}:`, e.message); }
    }
  } catch (e) {
    console.error('❌ Error en la ronda de liquidación:', e.message);
  } finally {
    _liquidacionEnCurso = false;
  }
}

// =============================================================================
// REGLA: UNA SOLA FACTURA POR (JUGADOR, STAT)
// =============================================================================
// vida, agua, comida, oro, plata y exp tienen EXACTAMENTE UNA factura por
// jugador en el contrato. El backend es el único que la crea y el único que la
// mueve, siempre con increase/decreaseInvoiceQuantity sobre ESE id.
//
// Reglas que se derivan de eso y que este módulo hace cumplir:
//   1. La factura canónica es la que tiene manualId == buildStatManualId(addr,stat).
//      Si por historia hay más de una factura del mismo tipo para el jugador,
//      el sync las CONSOLIDA (fungibles: se mueve el saldo a la canónica;
//      vitales: se queman) hasta dejar una sola.
//   2. Nunca se crea una factura "a medias". Antes, si al tipo le quedaban 12
//      unidades de cupo, el jugador nuevo nacía con 12% de agua y 7% de comida.
//      Ahora el cupo del tipo se ASEGURA primero (ensureStatTipo) y solo
//      después se crea la factura con el valor completo.
//   3. El delta de cada increase/decrease se calcula contra la cantidad REAL
//      leída del contrato, no contra el valor de Mongo. Si los dos se separan
//      (una TX falló antes), la cadena converge igual al valor pedido.
//   4. Si una TX falla, el valor que se devuelve al cliente es el de la cadena.
//      Nunca se responde "30" cuando en la cadena quedaron 12.
// -----------------------------------------------------------------------------

// Piso en la cadena: bajar una factura a 0 la DESACTIVA y libera su manualId
// (ver decreaseInvoiceQuantity en el contrato). Como la regla es "una sola
// factura y siempre la misma", jamás se baja de 1. El 0 real vive en Mongo.
const STAT_CHAIN_FLOOR = 1;

// Configuración de cada tabla (tipo) en el contrato.
//   perInvoiceLimit → techo de UNA factura. Para las vitales es 100 (la escala
//                     del juego); para oro/plata/exp, un techo alto.
//   headroom        → cupo global libre por debajo del cual se considera que
//                     la tabla se está quedando corta.
//   autoRaise       → si el backend puede subir `limit` por su cuenta cuando se
//                     queda sin cupo.
//
// autoRaise está en true para las SEIS tablas. El fallo de "recargo 30 de agua
// y al refrescar tengo 12" era una tabla sin cupo: increaseInvoiceQuantity
// revertía y el valor se perdía en silencio. Ese mismo fallo puede pasarle a
// oro, plata y exp, así que las seis se amplían solas.
//
// Nota sobre oro y plata: ampliar `limit` sube el techo de emisión de la
// moneda. Se hace porque perder el oro de un jugador es peor que tener un techo
// alto, pero cada ampliación queda registrada en el log con el prefijo
// `setLimit[oro]` / `setLimit[plata]` para que se pueda auditar. Si en algún
// momento querés congelar la emisión, poné autoRaise en false para esas dos:
// el backend seguirá avisando por log cuando la tabla se quede corta, sin
// tocar el contrato.
const STAT_TIPO_CONFIG = {
  vida:   { perInvoiceLimit: VITAL_MAX,     headroom: 1_000_000, autoRaise: true },
  agua:   { perInvoiceLimit: VITAL_MAX,     headroom: 1_000_000, autoRaise: true },
  comida: { perInvoiceLimit: VITAL_MAX,     headroom: 1_000_000, autoRaise: true },
  oro:    { perInvoiceLimit: 1_000_000_000, headroom: 1_000_000, autoRaise: true },
  plata:  { perInvoiceLimit: 1_000_000_000, headroom: 1_000_000, autoRaise: true },
  exp:    { perInvoiceLimit: 1_000_000_000, headroom: 1_000_000, autoRaise: true },
};

// Al ampliar una tabla se deja bastante más margen del que dispara la ampliación
// (headroom × este factor). Si se subiera justo hasta el headroom, el propio
// crecimiento normal volvería a cruzar el umbral enseguida y el backend estaría
// mandando un setLimit cada pocos minutos.
const TIPO_RAISE_FACTOR = 10;

// Cache de la config de tipos ya verificada en esta ejecución (evita un
// getTipoStats por stat en cada sync). TTL corto por si se toca desde fuera.
const _tipoCheckCache = new Map(); // stat → { at: ms, info: {...} }
const TIPO_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Se asegura de que la tabla `stat` exista en el contrato y tenga cupo para
 * operar: perInvoiceLimit suficiente para una factura llena y `limit` global
 * con headroom por delante. Si falta algo y el tipo es autoRaise, llama a
 * setLimit (el relayer es admin del contrato).
 *
 * Esta es la causa raíz de "agua 12% / comida 7%": el tipo se quedaba sin cupo
 * global, createInvoice truncaba la cantidad e increaseInvoiceQuantity revertía
 * con ExceedsTipoLimit, así que las recargas no llegaban nunca a la cadena.
 *
 * @returns {{exists:boolean, limit:number, perInvoiceLimit:number, totalQuantity:number, available:number}|null}
 */
async function ensureStatTipo(contract, stat, gasPrice, { force = false, minPerInvoice = 0 } = {}) {
  const cfg = STAT_TIPO_CONFIG[stat];
  if (!cfg) return null;

  if (!force) {
    const cached = _tipoCheckCache.get(stat);
    if (cached && (Date.now() - cached.at) < TIPO_CACHE_TTL_MS) return cached.info;
  }

  // Techo por factura que hace falta de verdad. Normalmente es el de la config,
  // pero si un jugador llegó a acumular más oro/plata/exp que ese techo, hay que
  // subirlo por encima o su factura no podría volver a crecer nunca.
  const perInvoiceObjetivo = Math.max(cfg.perInvoiceLimit, Math.ceil(minPerInvoice));

  let info;
  try {
    const ts = await contract.getTipoStats(stat);
    info = {
      totalQuantity:   Number(ts.totalQuantity   ?? ts[0] ?? 0),
      limit:           Number(ts.limit           ?? ts[1] ?? 0),
      perInvoiceLimit: Number(ts.perInvoiceLimit ?? ts[2] ?? 0),
      exists:          Boolean(ts.exists !== undefined ? ts.exists : ts[5]),
    };
  } catch (e) {
    console.warn(`⚠️  ensureStatTipo[${stat}]: getTipoStats falló:`, e.message);
    return null;
  }
  info.available = info.limit > info.totalQuantity ? info.limit - info.totalQuantity : 0;

  const needPerInvoice = info.perInvoiceLimit < perInvoiceObjetivo;
  const needHeadroom   = info.available       < cfg.headroom;

  if (info.exists && !needPerInvoice && !needHeadroom) {
    _tipoCheckCache.set(stat, { at: Date.now(), info });
    return info;
  }

  if (!cfg.autoRaise && info.exists) {
    // oro/plata: no se toca el techo de emisión por nuestra cuenta.
    console.warn(
      `⚠️  Tabla [${stat}] corta en el contrato ` +
      `(perInvoice=${info.perInvoiceLimit}, libre=${info.available}). ` +
      `No se sube automáticamente: ejecutá setLimit('${stat}', ...) desde el owner.`
    );
    _tipoCheckCache.set(stat, { at: Date.now(), info });
    return info;
  }

  const newPerInvoice = Math.max(perInvoiceObjetivo, info.perInvoiceLimit);
  const newLimit      = Math.max(info.limit, info.totalQuantity + cfg.headroom * TIPO_RAISE_FACTOR, newPerInvoice);

  try {
    const nonce = await provider.getTransactionCount(relayerWallet.address, 'pending');
    console.log(
      `🧾 setLimit[${stat}]: limit ${info.limit}→${newLimit}, ` +
      `perInvoice ${info.perInvoiceLimit}→${newPerInvoice}` +
      (info.exists ? '' : ' (tabla nueva)')
    );
    const tx = await contract.setLimit(stat, newLimit, newPerInvoice, { gasPrice, nonce });
    await tx.wait();
    info = {
      exists: true,
      limit: newLimit,
      perInvoiceLimit: newPerInvoice,
      totalQuantity: info.totalQuantity,
      available: newLimit - info.totalQuantity,
    };
    console.log(`✅ Tabla [${stat}] configurada: limit=${newLimit} perInvoice=${newPerInvoice}`);
  } catch (e) {
    console.error(`❌ setLimit[${stat}] falló (¿el relayer es admin?):`, e.message);
  }

  _tipoCheckCache.set(stat, { at: Date.now(), info });
  return info;
}

// Reintento ante caídas del nodo, compartido con el relay. El nodo de LitVM se
// cae y vuelve cada pocos minutos; sin esto, un sync o una actualización de
// stats que caiga en esa ventana pierde el valor del jugador.
const reintentarRPC = (fn, etiqueta) => RelayManager.conReintentoRPC(fn, etiqueta);

/** Lee la cantidad real de una factura. null si no existe o está inactiva. */
async function readInvoiceQty(contract, invId) {
  try {
    const inv = await reintentarRPC(() => contract.getInvoice(invId), `getInvoice(${invId})`);
    if (!inv || Number(inv.id) === 0 || !inv.active) return null;
    return Number(inv.cantidad);
  } catch (_) { return null; }
}

/**
 * Lleva LA factura `invId` de `stat` al valor `target`, con un único
 * increase o decrease. El delta se calcula contra la cantidad real en la
 * cadena, no contra Mongo, para que ambos converjan aunque se hubieran
 * separado antes.
 *
 * @returns {{ok:boolean, chainQty:number, error?:string}} chainQty = cantidad
 *          que quedó realmente en la factura (con el piso de 1 aplicado).
 */
async function applyStatOnChain(contract, stat, invId, target, gasPrice) {
  const desired = Math.max(STAT_CHAIN_FLOOR, Math.round(clampStat(stat, target)));

  let current = await readInvoiceQty(contract, invId);
  if (current === null) return { ok: false, chainQty: null, error: 'invoice_not_found_or_inactive' };
  if (current === desired) return { ok: true, chainQty: current };

  // Envuelto en reintento por caída del nodo: es la misma protección que tiene
  // el relay. Un revert del contrato NO se reintenta aquí (se trata abajo).
  const runTx = () => reintentarRPC(async () => {
    const nonce = await provider.getTransactionCount(relayerWallet.address, 'pending');
    if (desired > current) {
      const delta = desired - current;
      console.log(`⬆️  [${stat}] id=${invId} ${current}→${desired} (+${delta}, nonce=${nonce})`);
      const tx = await contract.increaseInvoiceQuantity(invId, delta, { gasPrice, nonce });
      await tx.wait();
    } else {
      const delta = current - desired;
      console.log(`⬇️  [${stat}] id=${invId} ${current}→${desired} (-${delta}, nonce=${nonce})`);
      const tx = await contract.decreaseInvoiceQuantity(invId, delta, { gasPrice, nonce });
      await tx.wait();
    }
  }, `applyStatOnChain[${stat}]`);

  try {
    await runTx();
    return { ok: true, chainQty: desired };
  } catch (err) {
    const msg = String(err.message || err);
    // ExceedsTipoLimit / InvoiceWouldExceedPerInvoiceLimit: la tabla se quedó
    // sin cupo. Esto era exactamente lo que hacía que "recargo a 30 y al
    // refrescar tengo 12": la TX revertía y nadie lo notaba. Se amplía el cupo
    // y se reintenta UNA vez.
    if (/ExceedsTipoLimit|PerInvoiceLimit/i.test(msg)) {
      console.warn(`⚠️  [${stat}] sin cupo en la tabla — ampliando y reintentando`);
      // `desired` va como techo mínimo por factura: si el jugador acumuló más
      // oro/plata/exp del que admitía una sola factura, la tabla se amplía lo
      // suficiente para que quepa en vez de quedarse atascada para siempre.
      await ensureStatTipo(contract, stat, gasPrice, { force: true, minPerInvoice: desired });
      try {
        current = await readInvoiceQty(contract, invId);
        if (current === null) return { ok: false, chainQty: null, error: 'invoice_not_found_or_inactive' };
        if (current === desired) return { ok: true, chainQty: current };
        await runTx();
        return { ok: true, chainQty: desired };
      } catch (err2) {
        const after = await readInvoiceQty(contract, invId);
        return { ok: false, chainQty: after, error: String(err2.message || err2) };
      }
    }
    const after = await readInvoiceQty(contract, invId);
    return { ok: false, chainQty: after, error: msg };
  }
}

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
  Listing,
  // Quién puede crear lotes limitados. Se pasa la versión CACHEADA porque el
  // mercado la consulta en cada listado y sin caché serían lecturas on-chain
  // constantes. Si no se pasara, el marketplace trata a todo el mundo como no
  // administrador (nadie podría crear lotes, que es el fallo seguro).
  isAdminAddress: isAdminAddressCached
});

// ── GF WALLET SDK — login social + wallet embebida ──────────────────────────
// Añade /api/wallet/* (config, OAuth de Google/Facebook/Apple y la bóveda de
// las medias claves). NO toca el login del juego: una wallet embebida entra por
// /api/auth/nonce + /api/auth/login exactamente igual que MetaMask, porque lo
// único que el backend verifica es una firma válida de una dirección.
//
// Si faltan las variables de entorno (GF_WALLET_VAULT_KEY, GF_WALLET_SUB_PEPPER
// y los client id de los proveedores), las rutas responden 503 y el juego sigue
// funcionando con MetaMask como hasta ahora. Ver gf-wallet-sdk/docs/BACKEND.md.
try {
  require('./gf-wallet-sdk/server/gf-wallet-routes')(app, {
    mongoose,
    apiLimiter,
    strictLimiter,
    csrfProtection,
    authMiddleware,
    JWT_SECRET
  });
} catch (e) {
  console.warn('⚠️  [gf-wallet] no se pudieron montar las rutas:', e.message);
}


// =============================================================================
// LIQUIDACIÓN ON-CHAIN DEL MERCADO P2P  (2026-08-03)
// -----------------------------------------------------------------------------
// PROBLEMA: en market.html se publicaba, se compraba y se cancelaba, pero todo
// se quedaba en el backend — los ítems nunca se movían de verdad en la
// blockchain, así que el mercado no manipulaba los NFT/facturas del contrato.
//
// SOLUCIÓN: tres operaciones que el mercado llama justo después de que su
// operación en base de datos sale bien:
//
//   escrow  → al PUBLICAR: quema en cadena las unidades del vendedor
//             (decreaseInvoiceQuantity / deleteInvoice). El ítem sale de su
//             cartera y queda "en depósito" del mercado.
//   deliver → al COMPRAR: acuña esas unidades al comprador (createInvoice o
//             increaseInvoiceQuantity).
//   refund  → al CANCELAR: devuelve al vendedor lo que quedaba en depósito.
//
// CONSERVACIÓN: por cada publicación se lleva un libro (MarketSettlement) y
// NUNCA se puede entregar/devolver más de lo que se quemó al publicar. Es
// decir, el mercado no puede crear ítems de la nada aunque el cliente mienta.
// Además cada operación es idempotente por (listingId, op, dirección, nonce).
// =============================================================================

const marketSettlementSchema = new mongoose.Schema({
  listingId: { type: String, required: true, index: true },
  op:        { type: String, enum: ['escrow', 'deliver', 'refund'], required: true },
  address:   { type: String, required: true, lowercase: true },
  itemId:    { type: String, required: true },
  qty:       { type: Number, required: true, min: 1 },
  txHash:    { type: String, default: '' },
  idem:      { type: String, required: true, unique: true }
}, { timestamps: true });
const MarketSettlement = mongoose.model('MarketSettlement', marketSettlementSchema);

// itemId del catálogo → `tipo` del contrato. Si un ítem no está aquí, no tiene
// representación on-chain y su liquidación se omite sin error.
//
// FIX (2026-08-05): esta tabla tenía su propia copia de los nombres y NO
// coincidía con la del juego — las maderas estaban como 'madera_pinos' cuando
// en ItemDefinitions son 'madera pinos' (con espacio) y faltaban las hachas y
// picos de piedra/cobre/hierro. Resultado: al publicar madera en el mercado, la
// quema on-chain no encontraba ninguna factura y el ítem se movía solo en la
// base de datos. Ahora se usa la ÚNICA tabla buena, ITEM_TIPO_MAP.
function marketOnchainTipo(itemId) {
  return itemTipoOnChain(itemId);
}

// Quema `quantity` unidades de `tipo` repartidas entre las facturas activas de
// la dirección. Devuelve cuántas se quemaron realmente.
async function burnItemOnChain(address, tipo, quantity) {
  if (!relayerWallet || quantity <= 0) return 0;
  const c = new ethers.Contract(CONTRACTS.ITEMS_CONTRACT.address, CONTRACTS.ITEMS_CONTRACT.abi, relayerWallet);
  const gasPrice = gatherGasPrice();

  let facturas = [];
  try {
    const snap = await c.getUserInventorySnapshot(address);
    for (const inv of snap) {
      if (inv.active && String(inv.tipo) === tipo && Number(inv.cantidad) > 0) {
        facturas.push({ id: Number(inv.id), cantidad: Number(inv.cantidad) });
      }
    }
  } catch (e) {
    console.warn('⚠️ market burn: no se pudo leer el inventario on-chain:', e.message);
    return 0;
  }

  // Se empieza por las facturas más pequeñas: así se cierran stacks enteros y
  // el inventario del contrato queda menos fragmentado.
  facturas.sort((a, b) => a.cantidad - b.cantidad);

  let restante = quantity;
  let quemadas = 0;
  for (const f of facturas) {
    if (restante <= 0) break;
    const aQuitar = Math.min(restante, f.cantidad);
    try {
      const nonce = await relayerNonceManager.getNextNonce();
      const tx = (aQuitar >= f.cantidad)
        ? await c.deleteInvoice(f.id, { gasPrice, nonce })
        : await c.decreaseInvoiceQuantity(f.id, aQuitar, { gasPrice, nonce });
      await tx.wait();
      restante -= aQuitar;
      quemadas += aQuitar;
    } catch (e) {
      console.error(`❌ market burn (factura ${f.id}):`, e.message);
      try { await relayerNonceManager.resetNonce(); } catch (_) {}
      break;
    }
  }
  return quemadas;
}

// POST /api/marketplace/onchain/settle
// body: { op: 'escrow'|'deliver'|'refund', listingId, itemId, qty }
app.post('/api/marketplace/onchain/settle',
  strictLimiter,
  authMiddleware,
  csrfProtection,
  [
    body('op').isIn(['escrow', 'deliver', 'refund']),
    body('listingId').isString().notEmpty(),
    body('itemId').isString().notEmpty(),
    body('qty').isInt({ min: 1, max: 10000 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const address = String(req.user.address || '').toLowerCase();
      const { op, listingId, itemId } = req.body;
      const qty = parseInt(req.body.qty, 10);

      const tipo = marketOnchainTipo(itemId);
      if (!tipo) {
        // Ítem sin representación on-chain: la operación de base de datos ya
        // está hecha y aquí no hay nada que mover.
        return res.json({ ok: true, onchain: false, reason: 'item_not_onchain' });
      }
      if (!relayerWallet) {
        return res.status(503).json({ error: 'relayer_unavailable' });
      }

      // ── Idempotencia ────────────────────────────────────────────────────
      const idem = `${op}:${listingId}:${address}:${itemId}:${qty}`;
      const yaHecho = await MarketSettlement.findOne({ idem }).lean();
      if (yaHecho) {
        return res.json({ ok: true, onchain: true, alreadySettled: true, txHash: yaHecho.txHash || '' });
      }

      // ── Libro de la publicación ─────────────────────────────────────────
      const movimientos = await MarketSettlement.find({ listingId }).lean();
      const suma = (o) => movimientos.filter(m => m.op === o).reduce((n, m) => n + m.qty, 0);
      const depositado = suma('escrow');
      const entregado  = suma('deliver') + suma('refund');
      const disponible = depositado - entregado;

      if (op === 'escrow') {
        // Solo el dueño de una publicación viva puede depositar, y solo por lo
        // que esa publicación declara.
        let listing = null;
        try { listing = await Listing.findById(listingId).lean(); } catch (_) {}
        if (!listing) return res.status(404).json({ error: 'listing_not_found' });
        if (String(listing.owner).toLowerCase() !== address) {
          return res.status(403).json({ error: 'not_listing_owner' });
        }
        if (String(listing.itemId) !== String(itemId)) {
          return res.status(400).json({ error: 'item_mismatch' });
        }
        if (depositado + qty > Number(listing.qty)) {
          return res.status(400).json({ error: 'escrow_exceeds_listing' });
        }

        const quemadas = await burnItemOnChain(address, tipo, qty);
        if (quemadas <= 0) {
          return res.status(409).json({ error: 'onchain_burn_failed' });
        }
        await MarketSettlement.create({ listingId, op, address, itemId, qty: quemadas, idem });
        return res.json({ ok: true, onchain: true, burned: quemadas });
      }

      // deliver / refund solo pueden repartir lo que ya se depositó.
      if (disponible <= 0) return res.status(409).json({ error: 'nothing_in_escrow' });
      if (qty > disponible) return res.status(400).json({ error: 'exceeds_escrow', available: disponible });

      if (op === 'refund') {
        // Devolver solo al vendedor original (quien depositó).
        const deposito = movimientos.find(m => m.op === 'escrow');
        if (!deposito || deposito.address !== address) {
          return res.status(403).json({ error: 'not_escrow_owner' });
        }
      }

      const minted = await mintGatherReward(address, tipo, qty);
      if (!minted) return res.status(409).json({ error: 'onchain_mint_failed' });

      await MarketSettlement.create({ listingId, op, address, itemId, qty, idem });
      return res.json({
        ok: true, onchain: true,
        invoiceId: minted.id, manualId: minted.manualId, newTotal: minted.cantidad
      });
    } catch (e) {
      console.error('POST /api/marketplace/onchain/settle:', e);
      return res.status(500).json({ error: 'internal_error' });
    }
  }
);

// Estado on-chain de una publicación (lo consulta market.html para saber si
// una liquidación quedó pendiente y reintentarla).
app.get('/api/marketplace/onchain/:listingId', apiLimiter, authMiddleware, async (req, res) => {
  try {
    const movimientos = await MarketSettlement.find({ listingId: req.params.listingId }).lean();
    const suma = (o) => movimientos.filter(m => m.op === o).reduce((n, m) => n + m.qty, 0);
    return res.json({
      ok: true,
      escrowed: suma('escrow'),
      delivered: suma('deliver'),
      refunded: suma('refund'),
      available: suma('escrow') - suma('deliver') - suma('refund')
    });
  } catch (e) {
    console.error('GET /api/marketplace/onchain/:listingId:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

console.log('✅ Liquidación on-chain del mercado: /api/marketplace/onchain/settle');

// manualId de LA factura de un stat. Usa la dirección COMPLETA: con los 8
// primeros caracteres que se usaban antes, dos jugadores cuyas direcciones
// empezaran igual generaban el mismo manualId, y como el manualId es único en
// todo el contrato, el segundo terminaba adoptando la factura del primero.
// Cabe de sobra en los 64 bytes que admite el contrato: 2 + 40 + 1 + 6 = 49.
function buildStatManualId(address, stat) {
  const addrPart = address.replace(/^0x/i, '').toLowerCase();
  return `s_${addrPart}_${stat}`;
}

function getStatsContract() {
  const cfg = CONTRACTS.ITEMS_CONTRACT;
  if (!cfg || !cfg.address || !relayerWallet) return null;
  try { return new ethers.Contract(cfg.address, cfg.abi, relayerWallet); }
  catch (e) { console.error('getStatsContract error:', e.message); return null; }
}

/**
 * Lee las facturas de stats del jugador y elige UNA canónica por tipo.
 *
 * Criterio de canónica (en orden):
 *   1. la que tiene el manualId que emite este backend (buildStatManualId),
 *   2. si ninguna lo tiene, la de id más bajo (la más antigua).
 * Todo lo demás del mismo tipo queda en `duplicates` para consolidarse.
 *
 * Antes esta función hacía `map[inv.tipo] = ...` dentro del bucle, así que con
 * dos facturas del mismo tipo ganaba la última del snapshot — y como el orden
 * del snapshot cambia (swap-remove), el "valor real" del stat saltaba de una
 * factura a otra entre recargas.
 *
 * @returns {Object|null} stat → { id, manualId, cantidad, duplicates: [...] }
 */
async function getOnChainStats(contract, address) {
  try {
    const snapshot = await contract.getUserInventorySnapshot(address);
    const porTipo = {};
    for (const inv of snapshot) {
      if (!inv.active) continue;
      const tipo = String(inv.tipo);
      if (!STAT_TYPES_LIST.includes(tipo)) continue;
      (porTipo[tipo] = porTipo[tipo] || []).push({
        id: Number(inv.id), manualId: String(inv.manualId), cantidad: Number(inv.cantidad)
      });
    }

    const map = {};
    for (const [tipo, lista] of Object.entries(porTipo)) {
      const esperado = buildStatManualId(address, tipo);
      lista.sort((a, b) => a.id - b.id);
      const idx = lista.findIndex(i => i.manualId === esperado);
      const canonical = idx >= 0 ? lista[idx] : lista[0];
      map[tipo] = { ...canonical, duplicates: lista.filter(i => i.id !== canonical.id) };
      if (map[tipo].duplicates.length) {
        console.warn(
          `⚠️  ${address} tiene ${lista.length} facturas de [${tipo}]. ` +
          `Canónica id=${canonical.id}; sobran ${map[tipo].duplicates.map(d => d.id).join(',')}`
        );
      }
    }
    return map;
  } catch (err) {
    console.error('getOnChainStats error:', err.message);
    return null;
  }
}

/**
 * Deja UNA sola factura del tipo. Las sobrantes:
 *   • oro/plata/exp (fungibles): se mueve su saldo a la canónica con
 *     transferQuantityBetweenInvoices, así no se pierde nada.
 *   • vida/agua/comida: el valor es un porcentaje, sumarlo no significa nada,
 *     así que la sobrante se quema con decreaseInvoiceQuantity.
 * En ambos casos la factura sobrante llega a 0 y el contrato la desactiva.
 *
 * @returns {number} cantidad final de la factura canónica.
 */
async function consolidateDuplicateStatInvoices(contract, stat, canonical, duplicates, gasPrice) {
  let total = canonical.cantidad;
  const fungible = !isVitalStat(stat);

  for (const dup of duplicates) {
    if (dup.cantidad <= 0) continue;
    try {
      const nonce = await provider.getTransactionCount(relayerWallet.address, 'pending');
      if (fungible) {
        console.log(`🔗 Consolidando [${stat}]: id=${dup.id} (${dup.cantidad}) → id=${canonical.id}`);
        const tx = await contract.transferQuantityBetweenInvoices(dup.id, canonical.id, dup.cantidad, { gasPrice, nonce });
        await tx.wait();
        total += dup.cantidad;
      } else {
        console.log(`🔥 Quemando factura duplicada de [${stat}]: id=${dup.id} (${dup.cantidad})`);
        const tx = await contract.decreaseInvoiceQuantity(dup.id, dup.cantidad, { gasPrice, nonce });
        await tx.wait();
      }
    } catch (e) {
      console.warn(`⚠️  No se pudo consolidar [${stat}] id=${dup.id}:`, e.message);
    }
  }
  return total;
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
  // Se acota SIEMPRE al devolver: así los documentos que ya quedaron corruptos
  // (vitales guardadas en 100000 por el bug del piso) se muestran bien de
  // inmediato, sin esperar a que un sync los reescriba.
  return {
    vida:   clampStat('vida',   doc.vida),
    agua:   clampStat('agua',   doc.agua),
    comida: clampStat('comida', doc.comida),
    oro: doc.oro, plata: doc.plata,
    exp: doc.exp ?? 0,
    invoiceIds: {
      vida:   doc.invoiceIds?.vida   ?? null,
      agua:   doc.invoiceIds?.agua   ?? null,
      comida: doc.invoiceIds?.comida ?? null,
      oro:    doc.invoiceIds?.oro    ?? null,
      plata:  doc.invoiceIds?.plata  ?? null,
      exp:    doc.invoiceIds?.exp    ?? null,
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
// COMPROBACIÓN DE PROPIEDAD — ANTI-IDOR
// -----------------------------------------------------------------------------
// Las rutas /api/<algo>/:playerName llevan el nombre del jugador en la URL. El
// authMiddleware confirma que QUIEN llama tiene sesión, pero no que ese nombre
// sea SUYO. Sin esta comprobación, cualquier usuario con sesión válida podía
// pasar el nombre de otro y leer o escribir sus datos.
//
// El patrón que había en algunas rutas era:
//     if (gp && gp.address && gp.address.toLowerCase() !== reqAddr) → 403
// que se SALTA la comprobación cuando el GamePlayer todavía no existe (gp es
// null): permitía escribir sobre cualquier nombre aún no registrado y, con el
// `upsert: true` de esas rutas, dejarlo ocupado antes que su dueño.
//
// Aquí la regla es al revés: solo se pasa si se puede DEMOSTRAR la propiedad.
// =============================================================================

/**
 * ¿La dirección `reqAddr` es la dueña de `playerName`?
 * @returns {Promise<boolean>}
 */
async function esDuenoDe(reqAddr, playerName) {
  if (!reqAddr || !playerName) return false;

  const addr   = String(reqAddr).toLowerCase();
  const target = String(playerName);

  // 1) El "nombre" es su propia dirección (jugadores que aún no eligieron nick).
  if (target.toLowerCase() === addr) return true;

  // 2) El nombre está registrado en GamePlayer: debe apuntar a su dirección.
  const gp = await GamePlayer.findOne({ playerName: target }).select('address').lean();
  if (gp && gp.address) return String(gp.address).toLowerCase() === addr;

  // 3) Aún sin GamePlayer: se compara con el nombre de su cuenta de acceso,
  //    que es lo que /api/auth/me le devolvió al cliente.
  const pa = await PlayerAuth.findOne({ address: addr }).select('playerName').lean();
  if (pa && pa.playerName) return String(pa.playerName).toLowerCase() === target.toLowerCase();

  // Nombre ajeno o inexistente: no se puede demostrar la propiedad.
  return false;
}

/**
 * Guarda de ruta: responde 403 y devuelve false si el que llama no es el dueño.
 * Uso:  if (!await requireOwner(req, res, playerName)) return;
 */
async function requireOwner(req, res, playerName) {
  const ok = await esDuenoDe(req.user && req.user.address, playerName);
  if (!ok) {
    console.warn(`🚫 IDOR bloqueado: ${(req.user && req.user.address) || 'sin-sesión'} intentó acceder a "${playerName}"`);
    res.status(403).json({ error: 'Forbidden' });
    return false;
  }
  return true;
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
    // FIX IDOR: no comprobaba dueño — filtraba las habilidades de cualquiera.
    if (!await requireOwner(req, res, playerName)) return;
    const doc = await PlayerSkills.findOne({ playerName }).lean();
    return res.json({ skills: doc ? doc.skills : {}, skillPoints: doc ? doc.skillPoints : 0 });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

app.post('/api/skills/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    // FIX: la comprobación anterior (`if (gp && gp.address && …)`) se saltaba
    // cuando el GamePlayer no existía todavía, y con `upsert:true` permitía
    // crear habilidades sobre nombres ajenos aún no registrados.
    if (!await requireOwner(req, res, playerName)) return;
    const { skills, skillPoints } = req.body;
    if (!skills || typeof skills !== 'object') return res.status(400).json({ error: 'Invalid' });

    // LAS HABILIDADES SOLO SUBEN. Este endpoint es un ESPEJO del panel, y el
    // panel puede mandar una foto vieja (se abre, el jugador sigue jugando y
    // pulsa "Save" cinco minutos después). Si se guardara tal cual, esa foto
    // borraría el progreso hecho mientras tanto. Se conserva el mayor de los
    // dos, igual que en /api/save.
    const previo  = await PlayerSkills.findOne({ playerName }).lean();
    const anterior = (previo && previo.skills) || {};

    const mayor = (a, b) => {
      const x = Number(a), y = Number(b);
      if (!Number.isFinite(x)) return Number.isFinite(y) ? y : 0;
      if (!Number.isFinite(y)) return x;
      return Math.max(x, y);
    };

    const fusion = { exp: {} };
    const claves = new Set([...Object.keys(anterior), ...Object.keys(skills)]);
    claves.delete('exp');
    claves.forEach(k => { fusion[k] = mayor(skills[k], anterior[k]); });

    const expNueva = (skills.exp && typeof skills.exp === 'object') ? skills.exp : {};
    const expVieja = (anterior.exp && typeof anterior.exp === 'object') ? anterior.exp : {};
    new Set([...Object.keys(expVieja), ...Object.keys(expNueva)]).forEach(k => {
      fusion.exp[k] = mayor(expNueva[k], expVieja[k]);
    });

    await PlayerSkills.findOneAndUpdate(
      { playerName },
      { skills: fusion, skillPoints: skillPoints || 0, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    return res.json({ success: true, skills: fusion });
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
    // FIX IDOR: no comprobaba dueño.
    if (!await requireOwner(req, res, playerName)) return;
    const doc = await PlayerPet.findOne({ playerName }).lean();
    return res.json({ pet: doc ? doc.pet : { type: 'perro', visible: true, equipped: true, level: 1 } });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

// POST /api/pet/:playerName
app.post('/api/pet/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    // FIX: misma laguna que en skills — se saltaba si no existía el GamePlayer.
    if (!await requireOwner(req, res, playerName)) return;
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
// SOULBOUND CHARACTER ROUTES  — /api/soulbound/:playerName
// =============================================================================
//
// Qué guarda: QUÉ personaje lleva equipado el jugador. Nada más. Los sprites
// viven en el cliente (Game/Sprites/Soulbound/<personaje>/…) y se descubren
// solos; aquí solo se recuerda la elección para que le siga al jugador cuando
// entre desde otro navegador u otro ordenador.
//
// Se valida el nombre contra [A-Za-z0-9_-]{1,40} porque ese valor vuelve al
// cliente y se usa para COMPONER UNA RUTA de sprites. Sin este filtro, un
// "../../algo" guardado aquí saldría del directorio Soulbound al construir la
// URL en el navegador. El cliente vuelve a validarlo por su cuenta, pero la
// comprobación tiene que estar también en el servidor: el cliente se puede
// saltar, esto no.
//
// Se usa colección propia (igual que las mascotas) en vez de añadir un campo a
// GamePlayer: así /api/save —que reescribe el documento entero del jugador— no
// puede pisar la elección de personaje por un guardado con datos viejos.
const soulboundSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true, index: true },
  character:  { type: String, default: 'personaje1' },
  updatedAt:  { type: Date,   default: Date.now }
}, { collection: 'player_soulbound' });
const PlayerSoulbound = mongoose.model('PlayerSoulbound', soulboundSchema);

// GET /api/soulbound/:playerName
app.get('/api/soulbound/:playerName', authMiddleware, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    if (!await requireOwner(req, res, playerName)) return;
    const doc = await PlayerSoulbound.findOne({ playerName }).lean();
    const character = (doc && NOMBRE_SOULBOUND_VALIDO.test(doc.character || ''))
      ? doc.character
      : 'personaje1';
    return res.json({ character });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

// POST /api/soulbound/:playerName   body: { character: 'personaje2' }
app.post('/api/soulbound/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    if (!await requireOwner(req, res, playerName)) return;
    const { character } = req.body;
    if (typeof character !== 'string' || !NOMBRE_SOULBOUND_VALIDO.test(character)) {
      return res.status(400).json({ error: 'Invalid character name' });
    }
    await PlayerSoulbound.findOneAndUpdate(
      { playerName },
      { character, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    return res.json({ success: true, character });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

console.log('✅ Soulbound routes loaded: /api/soulbound/:playerName');

// =============================================================================
// MAIL ROUTES  — /api/mail/:playerName
// =============================================================================
// Simple in-memory mail store keyed by playerName.
// Replace with DB calls (e.g. db.collection('mail')) as needed.
//
// FIX SEGURIDAD (IDOR + agotamiento de memoria):
//   Estas cinco rutas no comprobaban NADA salvo que hubiera sesión. Cualquier
//   usuario autenticado podía:
//     • leer el correo de otro           GET    /api/mail/<víctima>
//     • borrárselo entero                DELETE /api/mail/<víctima>/clear
//     • borrarle mensajes sueltos        DELETE /api/mail/<víctima>/<id>
//     • marcárselo como leído            POST   /api/mail/<víctima>/read-all
//     • ENVIARLE correo falsificando el remitente (`from` venía del cliente),
//       que es suplantación directa      POST   /api/mail/<víctima>
//   Además getPlayerMail() creaba una entrada nueva por CADA nombre que se
//   pidiera, sin caducidad: un bucle pidiendo nombres al azar llenaba la RAM
//   del servidor.
//
//   Ahora toda ruta exige ser el dueño (requireOwner), así que solo se crean
//   buzones de jugadores reales, y el remitente lo pone el SERVIDOR.
if (!global._mailStore) global._mailStore = {};

// Tope de mensajes guardados por jugador: el buzón es un array en memoria, sin
// límite crecía para siempre en cuentas muy activas.
const MAIL_MAX_POR_JUGADOR = 100;

function getPlayerMail(player) {
  if (!global._mailStore[player]) global._mailStore[player] = [];
  return global._mailStore[player];
}

// GET /api/mail/:playerName — list mails
app.get('/api/mail/:playerName', authMiddleware, async (req, res) => {
  if (!await requireOwner(req, res, req.params.playerName)) return;
  res.json({ mails: getPlayerMail(req.params.playerName) });
});

// POST /api/mail/:playerName/read-all — mark all read
app.post('/api/mail/:playerName/read-all', authMiddleware, csrfProtection, async (req, res) => {
  if (!await requireOwner(req, res, req.params.playerName)) return;
  getPlayerMail(req.params.playerName).forEach(m => { m.read = true; });
  res.json({ ok: true });
});

// DELETE /api/mail/:playerName/clear — delete all
app.delete('/api/mail/:playerName/clear', authMiddleware, csrfProtection, async (req, res) => {
  if (!await requireOwner(req, res, req.params.playerName)) return;
  global._mailStore[req.params.playerName] = [];
  res.json({ ok: true });
});

// DELETE /api/mail/:playerName/:mailId — delete one
app.delete('/api/mail/:playerName/:mailId', authMiddleware, csrfProtection, async (req, res) => {
  if (!await requireOwner(req, res, req.params.playerName)) return;
  const store = getPlayerMail(req.params.playerName);
  const idx = store.findIndex(m => String(m.id) === String(req.params.mailId));
  if (idx !== -1) store.splice(idx, 1);
  res.json({ ok: true });
});

// POST /api/mail/:playerName — send a mail (internal use or admin)
app.post('/api/mail/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  if (!await requireOwner(req, res, req.params.playerName)) return;

  const { subject, body } = req.body || {};
  // El remitente lo decide el SERVIDOR a partir de la sesión. Antes venía del
  // cuerpo de la petición, así que se podía firmar como cualquiera.
  const from = (req.user && req.user.address) || 'system';

  const mail = {
    id: Date.now().toString(),
    // Longitudes acotadas: sin esto un solo mensaje podía ocupar megas.
    subject: String(subject == null ? '' : subject).slice(0, 120),
    body:    String(body    == null ? '' : body).slice(0, 2000),
    from,
    date: new Date().toISOString(),
    read: false
  };

  const store = getPlayerMail(req.params.playerName);
  store.unshift(mail);
  if (store.length > MAIL_MAX_POR_JUGADOR) store.length = MAIL_MAX_POR_JUGADOR;

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
    // FIX IDOR: no comprobaba dueño — se podía leer el horno de cualquiera.
    if (!await requireOwner(req, res, playerName)) return;
    const doc = await FurnaceState.findOne({ playerName }).lean();
    if (!doc) return res.json({ oreItem: null, coalItem: null, timestamp: 0 });
    return res.json(doc);
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

// POST /api/furnace/:playerName
app.post('/api/furnace/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    // FIX IDOR: no comprobaba dueño — se podía sobrescribir (y sabotear) el
    // horno de cualquier otro jugador, incluido su resultado en curso.
    if (!await requireOwner(req, res, playerName)) return;
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
    // FIX: misma laguna que en skills/pet — se saltaba sin GamePlayer.
    if (!await requireOwner(req, res, playerName)) return;
    const doc = await PlayerNotifications.findOne({ playerName }).lean();
    return res.json({ notifications: doc ? doc.notifications : [] });
  } catch (err) { return res.status(500).json({ error: 'Internal server error' }); }
});

// POST /api/notifications/:playerName
app.post('/api/notifications/:playerName', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName = await resolvePlayerName(req.params.playerName);
    // FIX: misma laguna que en skills/pet — se saltaba sin GamePlayer.
    if (!await requireOwner(req, res, playerName)) return;
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

    // Sin .lean(): esta lectura también APLICA la regeneración fantasma (solo
    // Mongo, sin transacciones) para que el jugador vea el valor al día tanto
    // si acaba de entrar como si lleva la partida abierta.
    let doc = await PlayerStats.findOne({ playerName });
    if (!doc) return res.json({ stats: { ...STAT_DEFAULTS_MAP, invoiceIds: { vida: null, agua: null, comida: null, oro: null, plata: null, exp: null } } });
    await regenerarVitalesEnBD(doc);
    return res.json({ stats: buildStatsResponse(doc) });
  } catch (err) { console.error('GET /api/stats error:', err); return res.status(500).json({ error: 'Internal server error' }); }
});

// ── POST /api/stats/:playerName/sync ─────────────────────────────────────────
//
// Deja al jugador con EXACTAMENTE UNA factura por stat (vida, agua, comida,
// oro, plata, exp) y devuelve como verdad lo que hay en la cadena.
//
// Orden de trabajo por stat:
//   1. ensureStatTipo  → la tabla existe y tiene cupo (si no, no se crea nada
//                        a medias: eso era el "agua 12% / comida 7%").
//   2. factura canónica → una sola; las duplicadas se consolidan o se queman.
//   3. si no hay ninguna, se crea con el valor completo.
//   4. Mongo copia lo que quedó en la cadena.
app.post('/api/stats/:playerName/sync', authMiddleware, csrfProtection, async (req, res) => {
  let lockKey = null;
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
    const key = `sync_${address}`;
    if (_syncLocks.get(key)) {
      console.log(`⏳ Sync ya en curso para ${address}, esperando...`);
      await new Promise(r => setTimeout(r, 3000));
      const existing = await PlayerStats.findOne({ playerName });
      if (existing) return res.json({ stats: buildStatsResponse(existing), source: 'lock_wait' });
    }
    // A partir de aquí el lock es nuestro y el finally SIEMPRE lo suelta.
    // Antes se soltaba solo en el camino feliz: si el sync salía por
    // `!contract` o `!chainMap`, el lock quedaba puesto para siempre y todos
    // los syncs siguientes de ese jugador caían en la rama 'lock_wait'.
    lockKey = key;
    _syncLocks.set(lockKey, true);

    const contract = getStatsContract();
    let statsDoc = await PlayerStats.findOne({ playerName });
    if (!statsDoc) {
      statsDoc = new PlayerStats({ playerName, address });
      // Piso conservador: las vitales nacen llenas, oro/plata/exp en 0. El valor
      // definitivo lo pone la creación de la factura más abajo; así, si esa
      // creación falla, no se le muestran al jugador monedas que no existen.
      STAT_TYPES_LIST.forEach(s => { statsDoc[s] = STAT_DEFAULTS_MAP[s]; });
    }

    // Semilla de `exp`: la experiencia venía viviendo solo en
    // GamePlayer.nivel_exp. La primera vez que se sincroniza se arrastra ese
    // valor para que la factura nazca con la exp real y no en 0.
    if (!statsDoc.invoiceIds?.exp) {
      const gpExp = await GamePlayer.findOne({ playerName }).select('nivel_exp').lean();
      const prev  = Math.max(0, Math.round(Number(gpExp?.nivel_exp || 0)));
      if (prev > Number(statsDoc.exp || 0)) {
        statsDoc.exp = prev;
        console.log(`🌱 Semilla de exp para ${playerName}: ${prev} (desde nivel_exp)`);
      }
    }

    // Regeneración fantasma ANTES de reconciliar con la cadena: el sync es el
    // momento típico de "acabo de volver tras horas fuera", y así el rato
    // desconectado entra en el valor que se va a comparar (y a materializar)
    // contra la factura, en vez de perderse.
    applyGhostVitalRegen(statsDoc);

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
    const pendientes = [];   // stats que quedaron sin factura en este sync

    for (const stat of STAT_TYPES_LIST) {
      // ── 1. La tabla del tipo tiene que existir y tener cupo ───────────────
      const tipo = await ensureStatTipo(contract, stat, gasPrice);
      if (!tipo || !tipo.exists) {
        console.warn(`⚠️  Stats sync [${stat}]: tabla no configurada en el contrato — se conserva el valor de BD`);
        pendientes.push(stat);
        continue;
      }

      const existing = chainMap[stat];

      // ── 2. Ya hay factura: se deja UNA sola y manda la cadena ─────────────
      if (existing) {
        let chainQty = Number(existing.cantidad);

        if (existing.duplicates && existing.duplicates.length) {
          chainQty = await consolidateDuplicateStatInvoices(
            contract, stat, existing, existing.duplicates, gasPrice
          );
        }

        statsDoc.invoiceIds[stat] = existing.id;
        statsDoc.manualIds[stat]  = existing.manualId;

        // El piso de 1 existe solo para que la factura no se borre, así que un
        // 1 en la cadena es ambiguo: puede ser un 1 de verdad o un 0 apoyado en
        // el piso. Solo en ese caso se mira Mongo:
        //   • Mongo dice más de 1 → el 1 es piso, se restaura el valor de Mongo.
        //   • Mongo dice 0        → es el 0 real, se respeta (no se sube a 1).
        // Para cualquier otro valor la CADENA es la fuente de verdad.
        const dbQty = Number(statsDoc[stat] || 0);
        const tieneDeuda = Array.isArray(statsDoc.chainPending) && statsDoc.chainPending.includes(stat);

        if (tieneDeuda) {
          // Hay un consumo (o una recarga) ya cobrado en Mongo que todavía no se
          // ha escrito en la factura. Aquí manda SIEMPRE Mongo: si dejáramos
          // ganar a la cadena, bastaría con recargar la página nada más gastar
          // para que el sync devolviera el valor viejo y el gasto se esfumara.
          const r = await applyStatOnChain(contract, stat, existing.id, dbQty, gasPrice);
          if (r.ok) {
            statsDoc[stat] = clampStat(stat, dbQty);
            statsDoc.chainPending = statsDoc.chainPending.filter(s => s !== stat);
            statsDoc.markModified('chainPending');
            console.log(`⛓️  Deuda de [${stat}] liquidada en el sync: ${chainQty}→${dbQty}`);
          } else {
            // Sigue debiéndose: se conserva el valor de Mongo y la marca, y lo
            // reintenta el liquidador.
            statsDoc[stat] = clampStat(stat, dbQty);
            console.warn(`⚠️  [${stat}] sigue pendiente de liquidar:`, r.error);
          }
        } else if (chainQty === STAT_CHAIN_FLOOR && dbQty > STAT_CHAIN_FLOOR) {
          const r = await applyStatOnChain(contract, stat, existing.id, dbQty, gasPrice);
          statsDoc[stat] = clampStat(stat, r.ok ? dbQty : (r.chainQty ?? chainQty));
          if (!r.ok) console.warn(`⚠️  No se pudo restaurar [${stat}] a ${dbQty}:`, r.error);
        } else if (chainQty === STAT_CHAIN_FLOOR && dbQty === 0) {
          statsDoc[stat] = 0;
        } else if (isVitalStat(stat) && dbQty > chainQty) {
          // REGENERACIÓN FANTASMA PENDIENTE. En las vitales el modo fantasma
          // solo SUMA, así que "Mongo por encima de la cadena" solo puede venir
          // de minutos regenerados que todavía no se han materializado. Se
          // escriben ahora en la factura (una sola transacción, no una por
          // minuto). Si el gasto fuera al revés (cadena por encima), manda la
          // cadena, que es la rama de abajo.
          const r = await applyStatOnChain(contract, stat, existing.id, dbQty, gasPrice);
          statsDoc[stat] = clampStat(stat, r.ok ? dbQty : (r.chainQty ?? chainQty));
          if (r.ok) console.log(`🌙 [${stat}] regeneración fantasma materializada: ${chainQty}→${dbQty}`);
          else      console.warn(`⚠️  No se pudo materializar la regeneración de [${stat}]:`, r.error);
        } else {
          statsDoc[stat] = clampStat(stat, chainQty);
        }
        console.log(`✅ Stats sync [${stat}]: id=${existing.id}, qty=${statsDoc[stat]}`);
        continue;
      }

      // ── 3. No hay factura: se crea UNA, entera ───────────────────────────
      const manualId = buildStatManualId(address, stat);

      // El manualId puede existir aunque el snapshot no la haya traído
      // (p. ej. la factura quedó a nombre de otra dirección). Se comprueba
      // siempre antes de crear para no chocar con ManualIdAlreadyExists.
      try {
        const [invFound, already] = await contract.getInvoiceByManualIdSafe(manualId);
        if (already) {
          // Solo se adopta si es de ESTE jugador. Adoptar una factura ajena
          // le daría el control del saldo de otra persona.
          if (String(invFound.owner).toLowerCase() !== address) {
            console.error(`🚫 Stats sync [${stat}]: el manualId ${manualId} pertenece a ${invFound.owner} — no se toca`);
            pendientes.push(stat);
            continue;
          }
          statsDoc.invoiceIds[stat] = Number(invFound.id);
          statsDoc.manualIds[stat]  = String(invFound.manualId);
          statsDoc[stat]            = clampStat(stat, Number(invFound.cantidad));
          console.log(`♻️  Stats sync [${stat}]: manualId ya existía id=${invFound.id} qty=${invFound.cantidad}`);
          continue;
        }
      } catch (_) {}

      // Valor de nacimiento. Para exp se usa lo que ya tuviera el jugador
      // (semilla desde nivel_exp), no el 0 del mapa.
      let createVal = stat === 'exp'
        ? Math.max(0, Math.round(Number(statsDoc.exp || 0)))
        : (STAT_INITIAL_MAP[stat] || 0);
      if (createVal > tipo.perInvoiceLimit) createVal = tipo.perInvoiceLimit;

      // Nunca una factura parcial: si tras asegurar el cupo la tabla sigue sin
      // espacio para el valor completo, se deja para el próximo sync.
      if (createVal > tipo.available) {
        console.warn(`⏭️  Stats sync [${stat}]: cupo insuficiente (${tipo.available}/${createVal}) — NO se crea factura parcial`);
        pendientes.push(stat);
        continue;
      }

      try {
        const freshNonce = await provider.getTransactionCount(relayerWallet.address, 'pending');
        console.log(`🆕 Creando la factura de [${stat}] para ${address} = ${createVal} (nonce=${freshNonce})`);
        const tx = await contract.createInvoice(address, stat, createVal, manualId, { gasPrice, nonce: freshNonce });
        const receipt = await tx.wait();
        let newId = null;
        for (const log of receipt.logs) {
          try { const p = contract.interface.parseLog(log); if (p?.name === 'InvoiceCreated') { newId = Number(p.args.id); break; } } catch (_) {}
        }
        if (newId) {
          statsDoc.invoiceIds[stat] = newId;
          statsDoc.manualIds[stat]  = manualId;
          statsDoc[stat]            = clampStat(stat, createVal);
          _tipoCheckCache.delete(stat); // el cupo del tipo cambió
          console.log(`✅ Factura [${stat}] creada: id=${newId} qty=${createVal}`);
        } else {
          pendientes.push(stat);
        }
      } catch (txErr) {
        console.error(`❌ Error creando la factura de [${stat}]:`, txErr.message);
        pendientes.push(stat);
      }
    }

    // Stats que se quedaron SIN factura en este sync (RPC caído, tx lenta,
    // tabla sin cupo). No se inventa un valor: se conserva el que ya tenía el
    // jugador en BD y se reintenta la creación en el siguiente sync. Forzar
    // aquí un 100 fijo era lo que hacía que la barra dijera "lleno" mientras la
    // cadena tenía otra cosa, y al refrescar el valor se desplomaba.
    if (pendientes.length) {
      console.warn(`⏳ Sin factura todavía para ${playerName}: ${pendientes.join(', ')} — se reintenta en el próximo sync`);
    }
    for (const stat of STAT_TYPES_LIST) {
      statsDoc[stat] = clampStat(stat, statsDoc[stat]);
    }

    // Si ya no queda nada debiéndose, se apaga el reloj de la deuda.
    if (Array.isArray(statsDoc.chainPending) && statsDoc.chainPending.length === 0) {
      statsDoc.chainPendingSince = null;
    }

    statsDoc.markModified('invoiceIds');
    statsDoc.markModified('manualIds');
    statsDoc.lastSync = new Date();
    await statsDoc.save();
    return res.json({
      stats: buildStatsResponse(statsDoc),
      source: 'chain',
      pending: pendientes.length ? pendientes : undefined
    });

  } catch (err) {
    console.error('POST /api/stats/sync error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    if (lockKey) _syncLocks.delete(lockKey);
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

    // Se aplica primero la regeneración fantasma (solo Mongo). Así el reloj de
    // regeneración avanza aunque esta petición venga a BAJAR una vital, y los
    // stats que el cliente no toque quedan al día en la respuesta.
    applyGhostVitalRegen(doc);

    const contract   = getStatsContract();
    const gasPrice   = await getSafeGasPriceStats();
    const txErrors   = [];

    for (const stat of validKeys) {
      // clampStat acota las vitales a 0..100 (escala real del juego). Sin esto,
      // un cliente podía escribir 100000 y la barra mostraba "100000%".
      const newVal  = clampStat(stat, Math.round(Number(updates[stat])));
      const oldVal  = doc[stat] || 0;
      const invId   = doc.invoiceIds[stat];
      if (newVal === oldVal) continue;

      // VITALES: se guardan en Mongo al momento y su escritura en la factura se
      // agrupa (una transacción por barra cada minuto, ver el liquidador). Las
      // barras cambian docenas de veces por minuto mientras se juega; mandar
      // una transacción por cada cambio era lo que disparaba el gasto.
      // El dinero y la experiencia NO se aplazan: ahí sí interesa que la cadena
      // vaya al día en el acto.
      if (isVitalStat(stat)) {
        doc[stat] = newVal;
        marcarPendienteDeCadena(doc, stat);
        continue;
      }

      if (!contract || !invId) {
        // Sin factura todavía: se guarda en BD y el próximo /sync la crea.
        doc[stat] = newVal;
        console.log(`ℹ️  Update [${stat}] ${oldVal}→${newVal} (solo BD, aún sin factura)`);
        continue;
      }

      // Una sola factura y un solo movimiento: applyStatOnChain calcula el
      // delta contra la cantidad REAL de la factura, no contra `oldVal` de
      // Mongo. Si los dos se habían separado (una TX anterior revirtió sin que
      // nadie se enterara), la cadena converge igual al valor pedido en vez de
      // arrastrar el desfase — que es lo que hacía que una recarga a 30
      // apareciera como 12 al refrescar.
      const r = await applyStatOnChain(contract, stat, invId, newVal, gasPrice);

      if (r.ok) {
        // En la cadena hay como mínimo 1 por el piso anti-borrado; el valor
        // real (que puede ser 0) vive en Mongo.
        doc[stat] = newVal;
      } else {
        // Se responde lo que HAY en la cadena, no lo que el cliente pidió.
        console.error(`❌ TX error [${stat}]:`, r.error);
        txErrors.push({ stat, requested: newVal, error: r.error });
        if (r.chainQty !== null && r.chainQty !== undefined) {
          doc[stat] = clampStat(stat, r.chainQty);
        } else {
          doc[stat] = oldVal;
        }
      }
    }

    doc.markModified('invoiceIds');
    doc.markModified('manualIds');
    await doc.save();
    return res.json({ stats: buildStatsResponse(doc), errors: txErrors.length ? txErrors : undefined });

  } catch (err) { console.error('POST /api/stats/update error:', err); return res.status(500).json({ error: 'Internal server error' }); }
});

// =============================================================================
// TABLA DE COSTES DE LAS ACCIONES — AUTORIDAD DEL SERVIDOR       (2026-08-11)
// -----------------------------------------------------------------------------
// Lo que cuesta cada acción en vitales se decide AQUÍ y solo aquí. El cliente
// dice qué hace, nunca cuánto paga.
//
// Talar y minar cuestan medio punto de cada barra por golpe. Eso equivale al
// "una barra sí, otra no" que hace el cliente al alternar, pero sin necesidad
// de recordar de quién era el turno: el acumulador de fracciones de /consume
// (doc.vitalFractions) convierte dos golpes en 1 de agua + 1 de comida
// exactos. Menos estado que mantener y el mismo resultado.
//
// Sembrar y regar salen de la tabla de cultivos del propio servidor
// (cropController.cropTypes), que es la que ya manda en el crecimiento. Así no
// hay dos verdades sobre lo que cuesta una semilla.
// =============================================================================
const COSTE_POR_GOLPE = { agua: 0.5, comida: 0.5 };

/**
 * Coste en vitales de una acción.
 * @returns {object|null} mapa de coste, {} si es gratis, o null si la acción
 *                        no existe (petición inválida o manipulada).
 */
function costesDeAccion(reason, seedType, units) {
  if (reason === 'chop' || reason === 'mine') {
    return { agua: COSTE_POR_GOLPE.agua, comida: COSTE_POR_GOLPE.comida };
  }

  if (reason === 'plant' || reason === 'water') {
    const tabla = (cropController && cropController.cropTypes) || {};
    const cfg = tabla[seedType];
    // Semilla desconocida: se rechaza en vez de cobrar 0. Si se dejara pasar,
    // bastaría con mandar un seedType inventado para sembrar gratis.
    if (!cfg) return null;

    if (reason === 'water') {
      const c = Number(cfg.wateringCost) || 0;
      return c > 0 ? { agua: c } : {};
    }

    const salida = {};
    const agua   = (Number(cfg.waterCost) || 0) * units;
    const comida = (Number(cfg.foodCost)  || 0) * units;
    if (agua   > 0) salida.agua   = agua;
    if (comida > 0) salida.comida = comida;
    return salida;
  }

  // MORDISCO DE UN ANIMAL.
  // El coste lo pone el SERVIDOR, igual que el de talar o minar: el cliente
  // solo dice "me ha mordido algo", nunca cuánto duele. Si el daño llegara en
  // el cuerpo de la petición, bastaría con mandar 0 para ser invulnerable.
  if (reason === 'animal_bite') {
    return { vida: DANO_MORDISCO_ANIMAL };
  }

  return null;   // acción no reconocida
}

// ── POST /api/stats/:playerName/consume ─────────────────────────────────────
// GASTO DE VITALES: COBRO INSTANTÁNEO, TRANSACCIÓN AGRUPADA      (2026-08-05)
// -----------------------------------------------------------------------------
// Cuando una acción cuesta vida, agua o comida, el conteo del jugador se cobra
// AQUÍ y ANTES que nada más. El cliente espera esta respuesta y solo sigue con
// el resto (talar, minar, comprar, craftear…) si dice que sí.
//
// Lo que NO se espera es la blockchain. La barra de agua es UN número: no tiene
// sentido escribirlo en la cadena una vez por golpe de hacha. El cobro es
// inmediato en Mongo (que es la fuente autoritativa del saldo) y la escritura
// en la factura se marca como pendiente; el liquidador la agrupa y manda UNA
// transacción por barra cada minuto, por muchos golpes que hayan pasado.
//
// La deuda vive en la base de datos, no en el navegador: recargar la página o
// cerrar el juego no la borra.
//
// body: { costs: { vida?, agua?, comida? }, reason?: 'chop'|'mine'|... }
app.post('/api/stats/:playerName/consume', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const playerName  = await resolvePlayerName(req.params.playerName);
    const reqAddress  = (req.user.address || '').toLowerCase();
    const ownerGP     = await GamePlayer.findOne({ playerName }).lean();
    if (ownerGP && ownerGP.address && ownerGP.address.toLowerCase() !== reqAddress) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // ── EL COSTE LO DECIDE EL SERVIDOR ────────────────────────────────────
    // ANTES: el coste llegaba en `req.body.costs`. El servidor solo comprobaba
    // que el jugador tuviera saldo suficiente para lo que ÉL MISMO decía que
    // costaba la acción. Un cliente modificado mandaba `{ agua: 0 }` y talaba,
    // minaba, sembraba y regaba gratis para siempre. Era el agujero
    // anti-trampa más grande que quedaba, y encima toca dinero real porque las
    // vitales limitan cuánto se puede producir por hora.
    //
    // AHORA: el cliente solo dice QUÉ acción hace (`reason`) y, cuando aplica,
    // sobre qué semilla y cuántas unidades. El coste sale de la tabla de este
    // archivo — la misma que ya usa el controlador de cultivos — así que el
    // cliente no tiene ninguna voz en lo que paga. `costs` se ignora por
    // completo si viene.
    const reason   = String((req.body && req.body.reason) || 'action').slice(0, 40);
    const seedType = String((req.body && req.body.seedType) || '').slice(0, 40);
    const units    = Math.max(1, Math.min(100, Math.floor(Number(req.body && req.body.units) || 1)));

    const costesPedidos = costesDeAccion(reason, seedType, units);
    if (costesPedidos === null) {
      return res.status(400).json({ error: 'unknown_action', reason });
    }
    if (!Object.keys(costesPedidos).length) {
      // Acción real pero gratuita (p. ej. una semilla sin coste configurado).
      // Sin `stats` a propósito: el documento todavía no se ha leído y el
      // cliente ya contempla que la respuesta no lo traiga.
      return res.json({ ok: true, spent: {} });
    }

    const doc = await PlayerStats.findOne({ playerName });
    if (!doc) return res.status(404).json({ error: 'stats_not_found. Call /sync first' });

    // 1. Regeneración pendiente (modo fantasma) antes de cobrar.
    applyGhostVitalRegen(doc);

    // 1-bis. Convertir los costes decimales en enteros arrastrando el resto de
    // la vez anterior. Ejemplo con 0,2 de comida: las cuatro primeras siembras
    // cobran 0 y acumulan (0,2 → 0,4 → 0,6 → 0,8); la quinta llega a 1,0 y
    // cobra 1 de comida. En cinco siembras se paga exactamente 1, que es lo
    // que dice la tabla.
    if (!doc.vitalFractions) doc.vitalFractions = { vida: 0, agua: 0, comida: 0 };

    const costs         = {};   // lo que se cobra AHORA (entero)
    const restosNuevos  = {};   // lo que queda pendiente para la próxima
    for (const [stat, pedido] of Object.entries(costesPedidos)) {
      const acumulado = Number(doc.vitalFractions[stat] || 0) + pedido;
      const entero    = Math.floor(acumulado + 1e-9);   // margen anti-error de coma flotante
      restosNuevos[stat] = Number((acumulado - entero).toFixed(4));
      if (entero > 0) costs[stat] = Math.min(entero, VITAL_MAX);
    }

    // Si todo el coste se fue al acumulador (p. ej. la primera siembra), no hay
    // nada que cobrar: se guarda el resto y se responde OK. La acción es válida.
    if (!Object.keys(costs).length) {
      for (const [stat, resto] of Object.entries(restosNuevos)) doc.vitalFractions[stat] = resto;
      doc.markModified('vitalFractions');
      try { await doc.save(); } catch (_) {}
      // Misma forma de respuesta que el camino normal, para que el cliente no
      // tenga que distinguir los dos casos.
      return res.json({ ok: true, spent: {}, stats: buildStatsResponse(doc) });
    }

    /* 2. ¿Alcanza para TODO el coste? Es todo o nada: media tala no existe.

       EXCEPCIÓN: EL DAÑO. Un mordisco no es una acción que el jugador elija,
       es algo que le pasa, así que se cobra lo que haya: si te quedan 5 de vida
       y el zorro pega 6, te quedas en 0, no te salvas.

       EL BUG QUE ESTO ARREGLA — "mi vida llega al 5% y no baja de ahí aunque me
       sigan mordiendo": con la regla de todo o nada, en cuanto la vida bajaba
       del coste del mordisco el servidor devolvía 409 y NO descontaba nada. Los
       últimos puntos eran ininvulnerables y el personaje no podía morir jamás. */
    const esDano = (reason === 'animal_bite');
    if (esDano) {
      for (const stat of Object.keys(costs)) {
        costs[stat] = Math.min(costs[stat], clampStat(stat, doc[stat]));
      }
    }

    const faltan = [];
    for (const [stat, coste] of Object.entries(costs)) {
      if (clampStat(stat, doc[stat]) < coste) faltan.push(stat);
    }
    if (faltan.length) {
      // Se guarda igualmente lo regenerado (el reloj ya avanzó) y se responde
      // con los valores reales para que el cliente pinte las barras al día.
      try { await doc.save(); } catch (_) {}
      return res.status(409).json({
        error: 'insufficient_vitals',
        missing: faltan,
        stats: buildStatsResponse(doc)
      });
    }

    // 3. Cobro en Mongo (instantáneo) + apunte de la deuda con la cadena.
    for (const [stat, coste] of Object.entries(costs)) {
      doc[stat] = clampStat(stat, clampStat(stat, doc[stat]) - coste);
    }
    // El sobrante decimal se guarda SOLO aquí, cuando el cobro se ha hecho de
    // verdad. Si la petición se rechazó por falta de vitales (409) no se toca:
    // la acción no ocurrió, así que tampoco debe acumular deuda fraccionaria.
    for (const [stat, resto] of Object.entries(restosNuevos)) doc.vitalFractions[stat] = resto;
    doc.markModified('vitalFractions');

    marcarPendienteDeCadena(doc, Object.keys(costs));
    await doc.save();

    console.log(`🍖 Consumo [${reason}] de ${playerName}: ${JSON.stringify(costs)} → ` +
                `vida=${doc.vida} agua=${doc.agua} comida=${doc.comida} (pendiente de liquidar)`);

    return res.json({
      ok: true,
      spent: costs,
      stats: buildStatsResponse(doc),
      // Informativo: cuándo se escribirá en la cadena.
      settlesInMs: CHAIN_SETTLE_DELAY_MS
    });

  } catch (err) {
    console.error('POST /api/stats/consume error:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ── POST /api/currency/exchange — CAMBIO DE MONEDA (1000 plata = 1 oro) ──────
// La conversión la decide y ejecuta el SERVIDOR (nunca el cliente): valida el
// saldo, mueve las facturas on-chain de oro y plata, y solo entonces guarda.
// Mismo criterio anti-eliminación que /api/stats/update: en la cadena no se baja
// de 1, para que la factura no se borre y siga siendo movible.
const SILVER_PER_GOLD = 1000;

// ── REGALO SEMANAL DE MONEDA                                  (2026-08-05) ──
// Dos botones en el hub de moneda: "Get Gold" y "Get Silver". Cada uno se puede
// reclamar UNA VEZ CADA 7 DÍAS, por separado. Es una red de seguridad para que
// nadie se quede tirado sin dinero mientras la economía arranca.
//
// El contador vive en Mongo, no en el navegador: recargar la página, cambiar de
// dispositivo o tocar la hora del móvil no lo reinicia. Y la entrega usa el
// MISMO camino que el resto del dinero (applyStatOnChain sobre la factura), así
// que el oro regalado es tan real como el ganado jugando.
const WEEKLY_GIFTS = {
  gold:   { stat: 'oro',   amount: 2000, label: 'Gold'   },
  silver: { stat: 'plata', amount: 1000, label: 'Silver' }
};
const WEEKLY_GIFT_MS = 7 * 24 * 60 * 60 * 1000;

const weeklyGiftSchema = new mongoose.Schema({
  playerName: { type: String, required: true, index: true },
  address:    { type: String, lowercase: true, index: true },
  kind:       { type: String, enum: ['gold', 'silver'], required: true },
  claimedAt:  { type: Date, default: Date.now }
}, { collection: 'weekly_gifts' });
weeklyGiftSchema.index({ playerName: 1, kind: 1 }, { unique: true });

const WeeklyGift = mongoose.models.WeeklyGift || mongoose.model('WeeklyGift', weeklyGiftSchema);

// GET — cuánto falta para poder reclamar cada uno.
app.get('/api/currency/weekly', apiLimiter, authMiddleware, async (req, res) => {
  try {
    const address = (req.user.address || '').toLowerCase();
    const gp = await GamePlayer.findOne({ address }).lean();
    if (!gp) return res.status(404).json({ error: 'player_not_found' });

    const filas = await WeeklyGift.find({ playerName: gp.playerName }).lean();
    const porTipo = new Map(filas.map(f => [f.kind, f]));
    const ahora = Date.now();

    const salida = {};
    for (const [kind, cfg] of Object.entries(WEEKLY_GIFTS)) {
      const f = porTipo.get(kind);
      const listo = !f || (ahora - new Date(f.claimedAt).getTime()) >= WEEKLY_GIFT_MS;
      salida[kind] = {
        amount: cfg.amount,
        available: listo,
        msLeft: listo ? 0 : WEEKLY_GIFT_MS - (ahora - new Date(f.claimedAt).getTime())
      };
    }
    return res.json({ gifts: salida, periodMs: WEEKLY_GIFT_MS });
  } catch (err) {
    console.error('GET /api/currency/weekly error:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// POST — reclamar. body: { kind: 'gold' | 'silver' }
app.post('/api/currency/weekly/claim', strictLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const kind = String((req.body && req.body.kind) || '');
    const cfg = WEEKLY_GIFTS[kind];
    if (!cfg) return res.status(400).json({ error: 'invalid_kind' });

    const address = (req.user.address || '').toLowerCase();
    const gp = await GamePlayer.findOne({ address }).lean();
    if (!gp || !gp.playerName) return res.status(404).json({ error: 'player_not_found' });

    const doc = await PlayerStats.findOne({ playerName: gp.playerName });
    if (!doc) return res.status(404).json({ error: 'stats_not_found. Call /sync first' });

    const limite = new Date(Date.now() - WEEKLY_GIFT_MS);

    // RESERVA ATÓMICA. El upsert solo pasa si no hay fila o si la que hay ya
    // cumplió los 7 días: dos pulsaciones a la vez no pueden cobrar dos veces.
    let reserva;
    try {
      reserva = await WeeklyGift.findOneAndUpdate(
        { playerName: gp.playerName, kind, claimedAt: { $lte: limite } },
        { $set: { claimedAt: new Date(), address } },
        { new: true, upsert: true, setDefaultsOnInsert: true }
      ).exec();
    } catch (e) {
      // Índice único: ya existe una fila reciente → todavía no toca.
      if (e && e.code === 11000) {
        const f = await WeeklyGift.findOne({ playerName: gp.playerName, kind }).lean();
        const restante = f ? WEEKLY_GIFT_MS - (Date.now() - new Date(f.claimedAt).getTime()) : WEEKLY_GIFT_MS;
        return res.status(429).json({ error: 'already_claimed', msLeft: Math.max(0, restante) });
      }
      throw e;
    }
    if (!reserva) return res.status(429).json({ error: 'already_claimed', msLeft: WEEKLY_GIFT_MS });

    // Entrega por el camino de siempre: Mongo al momento y la factura después
    // (el liquidador agrupa la transacción, igual que con las vitales).
    applyGhostVitalRegen(doc);
    const nuevo = clampStat(cfg.stat, Number(doc[cfg.stat] || 0) + cfg.amount);
    doc[cfg.stat] = nuevo;
    marcarPendienteDeCadena(doc, cfg.stat);
    await doc.save();

    console.log(`🎁 Regalo semanal (${cfg.label}) para ${gp.playerName}: +${cfg.amount} → ${nuevo}`);
    return res.json({
      ok: true, kind, amount: cfg.amount,
      stats: buildStatsResponse(doc),
      msLeft: WEEKLY_GIFT_MS
    });
  } catch (err) {
    console.error('POST /api/currency/weekly/claim error:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

app.post('/api/currency/exchange', apiLimiter, authMiddleware, csrfProtection, async (req, res) => {
  try {
    const address = (req.user.address || '').toLowerCase();
    const { direction, amount } = req.body || {};
    const qty = Math.floor(Number(amount));

    if (!Number.isFinite(qty) || qty <= 0) return res.status(400).json({ error: 'invalid_amount' });
    if (direction !== 'silverToGold' && direction !== 'goldToSilver') {
      return res.status(400).json({ error: 'invalid_direction' });
    }

    const gp = await GamePlayer.findOne({ address }).lean();
    if (!gp || !gp.playerName) return res.status(404).json({ error: 'player_not_found' });

    const doc = await PlayerStats.findOne({ playerName: gp.playerName });
    if (!doc) return res.status(404).json({ error: 'stats_not_found. Call /sync first' });

    const oroActual   = Number(doc.oro   || 0);
    const plataActual = Number(doc.plata || 0);
    const silverCost  = qty * SILVER_PER_GOLD;

    let newOro, newPlata;
    if (direction === 'silverToGold') {
      if (plataActual < silverCost) {
        return res.status(400).json({ error: 'insufficient_silver', need: silverCost, have: plataActual });
      }
      newPlata = plataActual - silverCost;
      newOro   = oroActual + qty;
    } else {
      if (oroActual < qty) {
        return res.status(400).json({ error: 'insufficient_gold', need: qty, have: oroActual });
      }
      newOro   = oroActual - qty;
      newPlata = plataActual + silverCost;
    }

    const contract = getStatsContract();
    const gasPrice = await getSafeGasPriceStats();
    const aplicados = [];
    const errores   = [];

    // Aplica el nuevo valor de un stat a su ÚNICA factura on-chain.
    // Mismo camino que /api/stats/update: applyStatOnChain es el único sitio
    // que toca increase/decrease, así que las dos rutas no pueden divergir.
    const aplicar = async (stat, oldVal, newVal) => {
      const invId = doc.invoiceIds && doc.invoiceIds[stat];
      if (!contract || !invId) { doc[stat] = newVal; aplicados.push(stat); return; }

      const r = await applyStatOnChain(contract, stat, invId, newVal, gasPrice);
      if (r.ok) {
        doc[stat] = newVal;
        aplicados.push(stat);
      } else {
        console.error(`❌ exchange TX [${stat}]:`, r.error);
        if (r.chainQty !== null && r.chainQty !== undefined) doc[stat] = clampStat(stat, r.chainQty);
        errores.push({ stat, error: r.error });
      }
    };

    // Primero se QUITA y luego se DA: si el cobro falla, no se entrega nada.
    if (direction === 'silverToGold') {
      await aplicar('plata', plataActual, newPlata);
      if (errores.length) return res.status(502).json({ error: 'exchange_failed', errors: errores });
      await aplicar('oro', oroActual, newOro);
    } else {
      await aplicar('oro', oroActual, newOro);
      if (errores.length) return res.status(502).json({ error: 'exchange_failed', errors: errores });
      await aplicar('plata', plataActual, newPlata);
    }

    await doc.save();
    console.log(`💱 Cambio ${direction} x${qty} para ${gp.playerName}: oro=${doc.oro} plata=${doc.plata}`);
    return res.json({ ok: true, rate: SILVER_PER_GOLD, stats: buildStatsResponse(doc), errors: errores.length ? errores : undefined });

  } catch (err) {
    console.error('POST /api/currency/exchange error:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
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

// ============================================================================
// SISTEMA DE BATALLAS P2P DE MASCOTAS (matchmaking + turnos + clasificación)
// ============================================================================
//
// Todo el estado vive en el servidor: el cliente solo dibuja lo que se le
// manda y envía la acción del turno. Ni puntos ni temporada se guardan en el
// navegador.
//
//  Flujo:
//    1. socket.emit('battle:queue')            → entra a la cola
//    2. cuando hay 2 en cola → 'battle:matched' a ambos (datos del rival)
//    3. cada turno: socket.emit('battle:action', { action })
//       cuando LOS DOS han elegido, el servidor resuelve y emite 'battle:turn'
//    4. al llegar a 0 de vida → 'battle:end' + puntos guardados en Mongo
//
//  Acciones y resolución (piedra-papel-tijera con daño):
//    attack  (equilibrado)  gana a  charge   → daño normal
//    strong  (cargado)      gana a  attack   → daño alto, pero si el rival
//                                              defiende, se falla
//    defend  (defensa)      gana a  strong   → bloquea y contraataca flojo
//
// ---------------------------------------------------------------------------
// MODELOS
// ---------------------------------------------------------------------------

// Temporada de la clasificación: se reinicia cada 15 días.
const BATTLE_SEASON_DAYS = 15;

const battleSeasonSchema = new mongoose.Schema({
  seasonNumber: { type: Number, required: true, unique: true },
  startedAt: { type: Date, required: true },
  endsAt: { type: Date, required: true }
}, { timestamps: true });
const BattleSeason = mongoose.model('BattleSeason', battleSeasonSchema);

// Puntuación de un jugador DENTRO de una temporada.
// NIVEL DE LA MASCOTA a partir de su historial de batallas.
// Cada VICTORIA aporta el doble que una derrota (jugar también suma, para que
// el nivel avance aunque se pierda). 5 puntos = 1 nivel. Tope 50.
function computePetLevel(wins, battles) {
  const w = Math.max(0, Number(wins) || 0);
  const b = Math.max(0, Number(battles) || 0);
  const losses = Math.max(0, b - w);
  const puntos = w * 2 + losses;              // victorias valen doble
  return Math.max(1, Math.min(50, 1 + Math.floor(puntos / 5)));
}

const battleScoreSchema = new mongoose.Schema({
  seasonNumber: { type: Number, required: true, index: true },
  playerName: { type: String, required: true, index: true },
  address: { type: String, default: '', lowercase: true },
  petName: { type: String, default: '---' },
  points: { type: Number, default: 0, min: 0 },
  wins: { type: Number, default: 0, min: 0 },
  losses: { type: Number, default: 0, min: 0 },
  battles: { type: Number, default: 0, min: 0 },
  bestStreak: { type: Number, default: 0, min: 0 },
  streak: { type: Number, default: 0, min: 0 },
  lastBattleAt: { type: Date, default: null }
}, { timestamps: true });
battleScoreSchema.index({ seasonNumber: 1, playerName: 1 }, { unique: true });
battleScoreSchema.index({ seasonNumber: 1, points: -1, wins: -1 });
const BattleScore = mongoose.model('BattleScore', battleScoreSchema);

// Historial (para auditar resultados raros y detectar abusos)
const battleLogSchema = new mongoose.Schema({
  seasonNumber: { type: Number, required: true, index: true },
  matchId: { type: String, required: true, index: true },
  winner: { type: String, default: '' },
  loser: { type: String, default: '' },
  turns: { type: Number, default: 0 },
  reason: { type: String, default: 'ko' } // 'ko' | 'forfeit' | 'timeout'
}, { timestamps: true });
const BattleLog = mongoose.model('BattleLog', battleLogSchema);

// Batallas diarias contra bot: 5 por día y cada una más difícil que la
// anterior. El contador vive en el servidor (día en UTC) para que no se pueda
// reiniciar borrando datos del navegador.
const battleDailySchema = new mongoose.Schema({
  playerName: { type: String, required: true },
  day: { type: String, required: true },      // 'YYYY-MM-DD' (UTC)
  done: { type: Number, default: 0, min: 0 },
  wins: { type: Number, default: 0, min: 0 }
}, { timestamps: true });
battleDailySchema.index({ playerName: 1, day: 1 }, { unique: true });
const BattleDaily = mongoose.model('BattleDaily', battleDailySchema);

const BATTLE_DAILY_MAX = 5;
function battleTodayKey() {
  return new Date().toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------------
// TEMPORADA ACTIVA (con reinicio automático cada 15 días)
// ---------------------------------------------------------------------------
async function getCurrentBattleSeason() {
  const now = new Date();

  // La temporada vigente es la que aún no ha terminado
  let season = await BattleSeason.findOne({ endsAt: { $gt: now } }).sort({ seasonNumber: -1 });
  if (season) return season;

  // No hay ninguna viva: crear la siguiente (esto ES el "reinicio" de la
  // tabla — los BattleScore viejos quedan archivados con su seasonNumber).
  const last = await BattleSeason.findOne().sort({ seasonNumber: -1 });
  const seasonNumber = last ? last.seasonNumber + 1 : 1;
  const startedAt = now;
  const endsAt = new Date(now.getTime() + BATTLE_SEASON_DAYS * 24 * 60 * 60 * 1000);

  try {
    season = await BattleSeason.create({ seasonNumber, startedAt, endsAt });
    console.log(`🏆 Nueva temporada de batallas #${seasonNumber} (termina ${endsAt.toISOString()})`);
  } catch (e) {
    // Carrera entre dos peticiones simultáneas: releer la que ganó
    season = await BattleSeason.findOne({ seasonNumber });
    if (!season) throw e;
  }
  return season;
}

// Mínimo de batallas para aparecer en la tabla (pedido: "si el usuario hace 3
// o más batallas, todos los puntos los dará la tabla")
const BATTLE_MIN_FOR_RANKING = 3;

// ---------------------------------------------------------------------------
// ENDPOINT: CLASIFICACIÓN
// ---------------------------------------------------------------------------
app.get('/api/battle/leaderboard', apiLimiter, authMiddleware, async (req, res) => {
  try {
    const season = await getCurrentBattleSeason();

    // CONFIGURACIÓN EDITABLE DESDE admin.html (2026-08-04): tamaño de la tabla,
    // batallas mínimas y a quién se oculta. Si el administrador la desactiva,
    // la tabla se devuelve vacía y el cliente muestra el aviso.
    const lbCfg = await getLeaderboardConfig();
    if (lbCfg.enabled === false) {
      return res.json({
        success: true,
        disabled: true,
        message: 'The leaderboard is temporarily disabled',
        season: {
          number: season.seasonNumber,
          startedAt: season.startedAt,
          endsAt: season.endsAt,
          daysTotal: BATTLE_SEASON_DAYS,
          msRemaining: Math.max(0, season.endsAt.getTime() - Date.now())
        },
        seasonLabel: lbCfg.seasonLabel || '',
        minBattlesForRanking: lbCfg.minBattles,
        rows: [],
        me: null
      });
    }

    const minBatallas = Number.isFinite(Number(lbCfg.minBattles))
      ? Number(lbCfg.minBattles) : BATTLE_MIN_FOR_RANKING;
    const limit = Math.min(100, Math.max(3, parseInt(req.query.limit, 10) || lbCfg.topSize || 50));

    // JUGADORES EXCLUIDOS: baneados y suspendidos. Un tramposo baneado no debe
    // seguir ocupando el podio. Se pide de más para poder rellenar los huecos
    // que dejen los excluidos y que la tabla siga teniendo `limit` filas.
    const excluidas = await direccionesExcluidasDeClasificacion(lbCfg);
    const nombresFuera = await nombresExcluidosDeClasificacion(excluidas);

    const crudos = await BattleScore.find({
      seasonNumber: season.seasonNumber,
      battles: { $gte: minBatallas }
    })
      .sort({ points: -1, wins: -1, battles: 1 })
      .limit(limit + excluidas.size + 20)
      .select('playerName address petName points wins losses battles bestStreak -_id')
      .lean();

    // ── CLASIFICACIÓN DEL CANAL ──────────────────────────────────────────────
    // La tabla se limita a los jugadores que están AHORA MISMO en tu mismo
    // canal, igual que el chat y que los personajes que ves por el mapa: un
    // canal es una copia del mundo y su clasificación es la de esa copia.
    //
    // El canal NO se toma de la petición: se busca el socket del jugador que
    // pregunta y se lee de ahí. Si viniera en la URL, cualquiera podría pedir
    // la tabla de otro canal cambiando un número.
    //
    // Si el jugador no tiene socket vivo (pidió la tabla justo al recargar, o
    // se cayó la conexión) no se filtra nada y se devuelve la tabla global:
    // más vale enseñar de más que una tabla vacía sin explicación.
    let canalDelQuePregunta = null;
    let nombresDelCanal = null;
    try {
      const addrQ = req.user && req.user.address ? req.user.address.toLowerCase() : null;
      if (addrQ) {
        for (const [, s] of io.of('/').sockets) {
          if (s.authenticatedAddress && String(s.authenticatedAddress).toLowerCase() === addrQ) {
            canalDelQuePregunta = s.playerData && s.playerData.canal;
            break;
          }
        }
      }
      if (canalDelQuePregunta) nombresDelCanal = jugadoresDelCanal(canalDelQuePregunta);
    } catch (_) { /* sin filtro de canal */ }

    const filtrados = crudos.filter(r => {
      if (excluidas.has(String(r.address || '').toLowerCase())) return false;
      if (nombresFuera.has(r.playerName)) return false;
      // hideBots: el bot de entrenamiento no compite en la tabla.
      if (lbCfg.hideBots && /^bot[_-]?/i.test(String(r.playerName || ''))) return false;
      // Solo los de mi canal.
      if (nombresDelCanal && !nombresDelCanal.has(r.playerName)) return false;
      return true;
    }).slice(0, limit);

    const rows = filtrados.map((r, i) => ({ rank: i + 1, ...r }));

    // Fila del jugador que pregunta (aunque aún no llegue al mínimo).
    // El token solo trae la address; el playerName sale de PlayerAuth, igual
    // que en el resto de rutas autenticadas.
    let me = null;
    let myName = null;
    try {
      const addr = req.user && req.user.address ? req.user.address.toLowerCase() : null;
      if (addr) {
        const auth = await PlayerAuth.findOne({ address: addr }).select('playerName').lean();
        if (auth && auth.playerName) myName = auth.playerName;
      }
    } catch (e) { /* sin fila propia */ }

    if (myName) {
      const mine = await BattleScore.findOne({
        seasonNumber: season.seasonNumber,
        playerName: myName
      }).select('playerName address petName points wins losses battles bestStreak -_id').lean();

      if (mine) {
        const mejores = await BattleScore.countDocuments({
          seasonNumber: season.seasonNumber,
          battles: { $gte: minBatallas },
          points: { $gt: mine.points }
        });
        // Un jugador excluido (baneado/suspendido) tampoco ve su propio puesto.
        const estoyFuera = excluidas.has(String(mine.address || '').toLowerCase()) ||
                           nombresFuera.has(mine.playerName);
        me = {
          ...mine,
          rank: (!estoyFuera && mine.battles >= minBatallas) ? mejores + 1 : null,
          excluded: estoyFuera,
          missingBattles: Math.max(0, minBatallas - mine.battles)
        };
      } else {
        me = {
          playerName: myName, address: '', petName: '---',
          points: 0, wins: 0, losses: 0, battles: 0, bestStreak: 0,
          rank: null, excluded: false, missingBattles: minBatallas
        };
      }
    }

    res.json({
      success: true,
      season: {
        number: season.seasonNumber,
        startedAt: season.startedAt,
        endsAt: season.endsAt,
        daysTotal: BATTLE_SEASON_DAYS,
        msRemaining: Math.max(0, season.endsAt.getTime() - Date.now())
      },
      seasonLabel: lbCfg.seasonLabel || '',
      minBattlesForRanking: minBatallas,
      // Canal al que corresponde esta tabla (null = tabla global, sin socket vivo).
      canal: canalDelQuePregunta || null,
      rows,
      me
    });
  } catch (error) {
    console.error('❌ Error en /api/battle/leaderboard:', error);
    res.status(500).json({ error: 'internal_server_error' });
  }
});

// ---------------------------------------------------------------------------
// MATCHMAKING + COMBATE POR TURNOS (socket.io)
// ---------------------------------------------------------------------------
const battleQueue = [];              // sockets esperando rival
const battleMatches = new Map();     // matchId → estado del combate
const socketMatch = new Map();       // socket.id → matchId

const BATTLE_TURN_MS = 20000;        // tiempo máximo para elegir acción
const BATTLE_MAX_TURNS = 30;         // corte de seguridad

// =============================================================================
// PURGA DE LOS MAPAS EN MEMORIA                                 (2026-08-11)
// -----------------------------------------------------------------------------
// FUGA DE MEMORIA REPARADA AQUÍ.
//
// El servidor guarda varios Map con una entrada POR JUGADOR (anti-spam de
// siembra, enfriamiento de recolección, enfriamiento del verificador, caché de
// administradores, combates en curso). Todos hacían `.set()` y ninguno borraba
// nunca. En un proceso que no se reinicia eso crece sin techo: cada jugador que
// pasa por el servidor deja su entrada para siempre, aunque no vuelva jamás.
// Con decenas de miles de cuentas es RAM que no se recupera.
//
// Ninguno de esos datos tiene valor pasado un rato: son ventanas de minutos.
// Este barrido corre cada 10 minutos y borra lo que ya no puede influir en
// ninguna decisión. Es deliberadamente conservador — usa márgenes muy por
// encima de la ventana real de cada mecanismo — para que sea imposible que
// borre algo que todavía estuviera en uso.
// =============================================================================
const PURGA_INTERVALO_MS = 10 * 60 * 1000;   // cada 10 minutos
const PURGA_EDAD_MS      = 60 * 60 * 1000;   // se borra lo que lleve 1 h inactivo

/** Purga un Map cuyos valores son marcas de tiempo (número). */
function purgarMapaDeTiempos(mapa, ahora, edadMs) {
  let borrados = 0;
  for (const [clave, ts] of mapa) {
    if (typeof ts !== 'number' || ahora - ts > edadMs) { mapa.delete(clave); borrados++; }
  }
  return borrados;
}

function purgarMapasEnMemoria() {
  const ahora = Date.now();
  const stats = {};

  // ── Anti-spam de siembra ──────────────────────────────────────────────────
  // La ventana real son segundos y la sanción máxima 20 min. Se conserva
  // mientras el bloqueo siga vivo o haya habido actividad en la última hora.
  let n = 0;
  for (const [userId, estado] of plantSpamTracker) {
    if (!estado) { plantSpamTracker.delete(userId); n++; continue; }
    const bloqueoVivo = estado.lockedUntil && estado.lockedUntil > ahora;
    const reciente    = estado.lastPlantAt && (ahora - estado.lastPlantAt) <= PURGA_EDAD_MS;
    if (!bloqueoVivo && !reciente) { plantSpamTracker.delete(userId); n++; }
  }
  stats.plantSpamTracker = n;

  // ── Enfriamientos (valor = marca de tiempo) ───────────────────────────────
  stats._gatherLastByPlayer = purgarMapaDeTiempos(_gatherLastByPlayer, ahora, PURGA_EDAD_MS);
  stats._verifierCooldown   = purgarMapaDeTiempos(_verifierCooldown,   ahora, PURGA_EDAD_MS);
  // Se quedó fuera del barrido original y crece igual que los otros: una
  // entrada por jugador que espante un cuervo, para siempre.
  stats._cuervoUltimo       = purgarMapaDeTiempos(_cuervoUltimo,       ahora, PURGA_EDAD_MS);

  // ── Historial de chat de salas que ya no tiene nadie ──────────────────────
  // El historial es por sala y las salas llevan canal; una partida larga puede
  // dejar historiales de canales por los que ya no pasa nadie.
  n = 0;
  for (const [sala] of chatHistory) {
    const viva = rooms[sala] && Object.keys(rooms[sala]).length > 0;
    if (!viva) { chatHistory.delete(sala); n++; }
  }
  stats.chatHistory = n;

  // ── Caché de administradores ({ value, at }) ──────────────────────────────
  // Caduca a los ACCESS_CACHE_MS (30 s); pasado un minuto ya no sirve a nadie.
  n = 0;
  for (const [dir, entrada] of _adminAddrCache) {
    if (!entrada || typeof entrada.at !== 'number' || ahora - entrada.at > 60000) {
      _adminAddrCache.delete(dir); n++;
    }
  }
  stats._adminAddrCache = n;

  // ── Combates huérfanos ────────────────────────────────────────────────────
  // Un combate dura como mucho BATTLE_MAX_TURNS × BATTLE_TURN_MS (10 min). Si
  // los dos jugadores se caen a la vez, nadie llega a borrarlo y se queda
  // colgado con su temporizador. Se da un margen del triple antes de tocarlo.
  const topeCombate = BATTLE_MAX_TURNS * BATTLE_TURN_MS * 3;
  n = 0;
  for (const [id, match] of battleMatches) {
    // El id lleva dentro la marca de creación: 'm_<ms>_xxxx' | 'b_<ms>_xxxx'
    const nacido = Number(String(id).split('_')[1]);
    const viejo  = Number.isFinite(nacido) && (ahora - nacido) > topeCombate;
    if (match && match.ended === true) {
      if (match.turnTimer) { try { clearTimeout(match.turnTimer); } catch (e) {} }
      battleMatches.delete(id); n++;
    } else if (viejo) {
      if (match && match.turnTimer) { try { clearTimeout(match.turnTimer); } catch (e) {} }
      battleMatches.delete(id); n++;
    }
  }
  stats.battleMatches = n;

  // ── Punteros socket → combate que ya no existe ────────────────────────────
  n = 0;
  for (const [socketId, matchId] of socketMatch) {
    if (!battleMatches.has(matchId)) { socketMatch.delete(socketId); n++; }
  }
  stats.socketMatch = n;

  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  if (total > 0) {
    console.log('🧹 Purga de memoria:', JSON.stringify(stats),
                `| vivos: siembra=${plantSpamTracker.size} recolecta=${_gatherLastByPlayer.size} ` +
                `verificador=${_verifierCooldown.size} admin=${_adminAddrCache.size} ` +
                `combates=${battleMatches.size} sockets=${socketMatch.size}`);
  }
  return stats;
}

// `unref()` para que este temporizador no impida al proceso terminar.
const _purgaTimer = setInterval(purgarMapasEnMemoria, PURGA_INTERVALO_MS);
if (typeof _purgaTimer.unref === 'function') _purgaTimer.unref();

function battleStatsForLevel(nivel) {
  const lvl = Math.max(1, Number(nivel) || 1);
  return {
    maxHp: 80 + lvl * 12,
    attack: 10 + lvl * 2
  };
}

// =============================================================================
// EL NIVEL DEL PERSONAJE LO CALCULA EL SERVIDOR
// -----------------------------------------------------------------------------
// VULNERABILIDAD QUE ESTO CIERRA — rompía las batallas PvP por completo:
//
// `GamePlayer.nivel` llegaba del CLIENTE en el cuerpo de /api/save y se
// guardaba tal cual. Y ese mismo número alimenta battleStatsForLevel(), que
// decide la vida y el ataque en combate, y pesosPorNivel(), que decide con qué
// frecuencia salen cartas épicas. Un cliente modificado solo tenía que mandar
// `{"nivel": 150}` una vez para entrar a PvP con 1.880 de vida y 310 de ataque
// contra los 128/18 de un jugador legítimo de nivel 4. Imposible de perder.
//
// La experiencia (`nivel_exp`) SÍ es de fiar: vive en su propia factura del
// contrato y se sincroniza contra la cadena. Así que el nivel se DERIVA de ella
// aquí y el número que mande el cliente se ignora.
//
// La curva es la misma que usa el cliente para pintar la barra
// (GameScene._expTotalParaNivel): mínimo entre la curva vieja exponencial —que
// manda hasta el nivel 4, para no bajarle el nivel a nadie— y la nueva
// polinómica 100·n²+100·n, que es la que hace que la progresión siga siendo
// posible más allá del nivel 5. Si se cambia una, hay que cambiar la otra.
const MAX_LEVEL_PERSONAJE = 150;

function expTotalParaNivel(n) {
  const L = Math.max(1, Math.round(Number(n) || 1));
  const vieja = 200 * Math.pow(2, Math.min(L - 1, 40));
  const nueva = 100 * L * L + 100 * L;
  return Math.min(vieja, nueva);
}

/** Nivel que corresponde a `exp` puntos de experiencia acumulada. */
function nivelPorExperiencia(exp) {
  const e = Math.max(0, Math.round(Number(exp) || 0));
  let nivel = 0;
  while (nivel < MAX_LEVEL_PERSONAJE && e >= expTotalParaNivel(nivel + 1)) nivel++;
  return nivel;
}

function shortAddress(addr) {
  if (!addr || typeof addr !== 'string' || addr.length < 10) return '';
  return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
}

function battlePublicPlayer(p) {
  return {
    playerName: p.playerName,
    petName: p.petName,
    address: p.address,
    addressShort: shortAddress(p.address),
    level: p.level,
    hp: p.hp,
    maxHp: p.maxHp,
    isBot: !!p.isBot,
    /* QUÉ BICHO ES. Lo usa el cliente para dibujarlo (ver ESPECIES en
       BattleScene.js). Las mascotas de los jugadores son siempre perros; los
       bots, cada uno lo suyo. Sin esto, en pantalla salían dos perros
       idénticos y no se distinguía cuál era el tuyo. */
    species: p.species || 'perro',
    // Estados activos (veneno, escudo de espinas, aturdido…), para que la UI
    // los muestre siempre junto a la barra de vida.
    status: estadosPublicos(p)
  };
}

// ---------------------------------------------------------------------------
// BOT DE LAS BATALLAS DIARIAS
// ---------------------------------------------------------------------------
// ronda va de 1 a 5 y cada una es más dura que la anterior: sube de nivel,
// vida, ataque y también la "inteligencia" con la que elige su jugada.
/* ═══════════════════════════════════════════════════════════════════════
   LOS CINCO RIVALES DEL DÍA
   ───────────────────────────────────────────────────────────────────────
   Antes los cinco eran EL MISMO PERRO con otro nombre. El jugador lo dijo
   tal cual: "enemigos bots, haz que no solo sean los perros". Ahora cada
   ronda es un bicho distinto, y el bicho lo dibuja el cliente con los
   sprites de animales que el juego ya tiene en el mapa (ver ESPECIES en
   BattleScene.js) — no hace falta ni un archivo nuevo.

   El orden va de menos a más amenazante, que es lo que se espera de cinco
   rondas: conejo, jabalí, cuervo, zorro y cocodrilo de jefe.
   ═══════════════════════════════════════════════════════════════════════ */
const BATTLE_BOTS = [
  { species: 'conejo',    petName: 'Nibbles', playerName: 'Wild Rabbit' },
  { species: 'cerdo',     petName: 'Tusk',    playerName: 'Wild Boar' },
  { species: 'cuervo',    petName: 'Shade',   playerName: 'Old Crow' },
  { species: 'zorro',     petName: 'Rusty',   playerName: 'Red Fox' },
  { species: 'cocodrilo', petName: 'Gnash',   playerName: 'Swamp Croc' }
];
/* Rivales sueltos para el PvP contra bot fuera de las diarias, y por si algún
   día hay más de cinco rondas. */
const BATTLE_BOTS_EXTRA = [
  { species: 'vibora', petName: 'Fang',   playerName: 'Viper' },
  { species: 'topo',   petName: 'Digger', playerName: 'Mole' },
  { species: 'zorra',  petName: 'Ember',  playerName: 'Vixen' },
  { species: 'vaca',   petName: 'Bruno',  playerName: 'Angry Bull' }
];
// Se deja el nombre viejo por si algo externo lo mira.
const BATTLE_BOT_NAMES = BATTLE_BOTS.map(b => b.petName);

/* ═══════════════════════════════════════════════════════════════════════
   CUÁNTO SUBE EL RIVAL EN CADA RONDA
   ───────────────────────────────────────────────────────────────────────
   EL DESEQUILIBRIO QUE ESTO ARREGLA — "que las batallas sean justas":

   El bot subía TRES veces a la vez. En la ronda 5 tenía el nivel del jugador
   +4 (o sea, +48 de vida y +8 de ataque por la curva), y ENCIMA se le
   multiplicaba la vida por 1,48 y el ataque por 1,40. Total: contra un
   jugador de nivel 10 (200 hp / 30 atq), la ronda 5 salía con 355 hp y 53 de
   ataque. Un 78 % más de vida y un 77 % más de pegada. Eso no es una batalla
   difícil, es una batalla imposible: el jugador no llega a bajarle la vida
   antes de que el bot le pegue el doble de veces.

   Y hay más: el jugador entra con la vida QUE LE QUEDE a su mascota en el
   mapa (si un cocodrilo la mordió, entra al 40 %), mientras el bot entra
   siempre al 100 %.

   Ahora sube UNA sola vez, y poco: +6 % de vida y +5 % de ataque por ronda,
   sobre el nivel del jugador SIN sumarle rondas. En la ronda 5 el bot tiene
   un 24 % más de vida y un 20 % más de pegada — se nota que es más duro y se
   puede ganar. La otra palanca para que las rondas altas cuesten es la
   ASTUCIA: el bot juega mejor sus cartas, que es dificultad de verdad y no
   un muro de números.
   ═══════════════════════════════════════════════════════════════════════ */
const BOT_VIDA_POR_RONDA   = 0.06;
const BOT_ATAQUE_POR_RONDA = 0.05;

function crearBotDeRonda(ronda, nivelJugador, opciones) {
  const r = Math.max(1, Math.min(BATTLE_DAILY_MAX, Number(ronda) || 1));
  /* El nivel del bot es el DEL JUGADOR, sin sumarle la ronda: lo que sube por
     ronda es el porcentaje de abajo, y sumar las dos cosas era justo el
     problema. */
  const nivel = Math.max(1, Number(nivelJugador) || 1);
  const base = battleStatsForLevel(nivel);

  const maxHp  = Math.round(base.maxHp  * (1 + BOT_VIDA_POR_RONDA   * (r - 1)));
  const attack = Math.round(base.attack * (1 + BOT_ATAQUE_POR_RONDA * (r - 1)));

  const ficha = (opciones && opciones.ficha) || BATTLE_BOTS[r - 1] ||
                BATTLE_BOTS_EXTRA[(r - 1) % BATTLE_BOTS_EXTRA.length];

  return {
    socket: null,
    isBot: true,
    ronda: r,
    // 0.2 en la ronda 1 → 0.6 en la 5: probabilidad de leer la jugada del rival
    astucia: 0.2 + 0.1 * (r - 1),
    playerName: `${ficha.playerName} · Round ${r}`,
    petName: ficha.petName,
    species: ficha.species,
    address: '',
    level: nivel,
    maxHp,
    hp: maxHp,
    attack
  };
}

// ---------------------------------------------------------------------------
// CARTAS (estilo Axie: mano + energía por turno)
// ---------------------------------------------------------------------------
// Cada turno se reparte una mano y una reserva de energía. Se juegan las
// cartas que quepan en esa energía y AMBOS jugadores resuelven a la vez:
// el daño de cada uno se reduce con el escudo que el rival haya puesto ESE
// mismo turno, así que hay decisión real (atacar fuerte vs. cubrirse).
const BATTLE_ENERGY_PER_TURN = 3;
const BATTLE_HAND_SIZE = 5;          // antes 4: una carta más para decidir
const BATTLE_MAX_ENERGY_BANK = 2;    // energía sin gastar que se guarda al turno siguiente

// ── EFECTOS DE ESTADO ──────────────────────────────────────────────────────
// Duran varios turnos y se resuelven al inicio de cada uno. Son lo que da
// profundidad: ya no todo se decide en el intercambio de un solo turno.
//   poison  → daño al inicio del turno, ignora el escudo
//   stun    → el rival pierde 1 de energía el turno siguiente
//   weak    → el rival pega un 35% menos el turno siguiente
//   regen   → cura al inicio del turno
//   thorns  → devuelve parte del daño recibido ese turno
//   focus   → tu siguiente carta de ataque pega un 50% más
// ── ESTADOS Y SU DURACIÓN EN TURNOS ─────────────────────────────────────────
// `armor` y `expose` son nuevos (2026-08-12):
//   • armor  (3 turnos) — reduce a la MITAD el daño recibido. Es la "armadura
//     de varios turnos": a diferencia del escudo, que se gasta de un golpe y
//     hay que rehacerlo cada turno, ésta aguanta y premia invertir un turno en
//     defenderse.
//   • expose (2 turnos) — anula el efecto de armor y reduce a la mitad los
//     escudos que se levanten. Es la RESPUESTA al juego defensivo: antes, si
//     el rival se atrincheraba a base de escudo, no había forma de romperlo.
const BATTLE_STATUS_TURNS = {
  poison: 3, stun: 1, weak: 2, regen: 3, thorns: 2, focus: 1,
  armor: 3, expose: 2
};

// Qué estados son BUENOS para quien los lleva y cuáles son malos. Lo usan las
// cartas de limpieza (te quitas los malos) y de disipación (le quitas los
// buenos al rival).
const BATTLE_ESTADOS_BUENOS = ['regen', 'thorns', 'focus', 'armor'];
const BATTLE_ESTADOS_MALOS  = ['poison', 'stun', 'weak', 'expose'];

const BATTLE_CARDS = {
  // ── COMUNES (coste 1) ────────────────────────────────────────────────────
  zarpazo:    { id: 'zarpazo',   name: 'Claw',        emoji: '🐾', cost: 1, dmg: 1.00, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'common',
                desc: 'A fast swipe. Cheap, reliable damage every turn.' },
  guardia:    { id: 'guardia',   name: 'Guard',       emoji: '🛡️', cost: 1, dmg: 0.00, shield: 1.25, heal: 0.00, type: 'defense', rarity: 'common',
                desc: 'Raises a shield that soaks the rival’s hit this turn.' },
  colazo:     { id: 'colazo',    name: 'Tail Whip',   emoji: '🌀', cost: 1, dmg: 0.65, shield: 0.45, heal: 0.00, type: 'hybrid', rarity: 'common',
                desc: 'Cheap poke that also chips in a little shield.' },
  arania:     { id: 'arania',    name: 'Scratch',     emoji: '✳️', cost: 1, dmg: 0.80, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'common',
                applies: 'weak',
                desc: 'Light cut that leaves the rival weakened next turn.' },
  gruñido:    { id: 'gruñido',   name: 'Growl',       emoji: '😾', cost: 1, dmg: 0.00, shield: 0.60, heal: 0.00, type: 'defense', rarity: 'common',
                applies: 'weak',
                desc: 'A menacing growl: small shield and the rival hits softer.' },
  olfatear:   { id: 'olfatear',  name: 'Sniff Out',   emoji: '👃', cost: 1, dmg: 0.00, shield: 0.00, heal: 0.00, type: 'buff', rarity: 'common',
                self: 'focus',
                desc: 'Finds the weak spot: your next attack hits 50% harder.' },

  // ── RARAS (coste 2) ──────────────────────────────────────────────────────
  mordisco:   { id: 'mordisco',  name: 'Bite',        emoji: '🦷', cost: 2, dmg: 1.85, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'rare',
                desc: 'Sinks its fangs in for strong single-target damage.' },
  aullido:    { id: 'aullido',   name: 'Howl',        emoji: '🌙', cost: 2, dmg: 0.70, shield: 0.85, heal: 0.00, type: 'hybrid', rarity: 'rare',
                desc: 'Strikes and shields at once. Solid all-rounder.' },
  lamer:      { id: 'lamer',     name: 'Lick Wounds', emoji: '💚', cost: 2, dmg: 0.00, shield: 0.00, heal: 0.95, type: 'heal', rarity: 'rare',
                desc: 'Licks its wounds and recovers a chunk of HP.' },
  colmillo:   { id: 'colmillo',  name: 'Venom Fang',  emoji: '🟢', cost: 2, dmg: 0.90, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'rare',
                applies: 'poison',
                desc: 'Poisons the rival: damage every turn that ignores shields.' },
  sacudida:   { id: 'sacudida',  name: 'Head Slam',   emoji: '💫', cost: 2, dmg: 1.20, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'rare',
                applies: 'stun',
                desc: 'Dazes the rival: they get 1 less energy next turn.' },
  espinas:    { id: 'espinas',   name: 'Bristle',     emoji: '🦔', cost: 2, dmg: 0.00, shield: 1.10, heal: 0.00, type: 'defense', rarity: 'rare',
                self: 'thorns',
                desc: 'Shield plus thorns: returns part of the damage you take.' },
  siesta:     { id: 'siesta',    name: 'Cat Nap',     emoji: '😴', cost: 2, dmg: 0.00, shield: 0.40, heal: 0.35, type: 'heal', rarity: 'rare',
                self: 'regen',
                desc: 'Rests up: small shield and healing over the next turns.' },
  robavida:   { id: 'robavida',  name: 'Leech Bite',  emoji: '🩸', cost: 2, dmg: 1.15, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'rare',
                lifesteal: 0.5,
                desc: 'Heals you for half of the damage it deals.' },

  // ── ÉPICAS (coste 3) ─────────────────────────────────────────────────────
  embestida:  { id: 'embestida', name: 'Charge',      emoji: '💥', cost: 3, dmg: 2.90, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'epic',
                desc: 'A full-power body slam. Huge damage, all your energy.' },
  furia:      { id: 'furia',     name: 'Frenzy',      emoji: '🔥', cost: 3, dmg: 2.20, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'epic',
                applies: 'weak', self: 'focus',
                desc: 'Wild assault: weakens the rival and sharpens your next hit.' },
  muralla:    { id: 'muralla',   name: 'Bulwark',     emoji: '🧱', cost: 3, dmg: 0.00, shield: 2.60, heal: 0.30, type: 'defense', rarity: 'epic',
                self: 'thorns',
                desc: 'A wall of fur: huge shield, some healing and thorns.' },
  colmillos:  { id: 'colmillos', name: 'Savage Maul', emoji: '🦴', cost: 3, dmg: 1.90, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'epic',
                applies: 'poison', lifesteal: 0.35,
                desc: 'Poisons and drains: damage over time plus life steal.' },
  segundoaire:{ id: 'segundoaire', name: 'Second Wind', emoji: '🌬️', cost: 3, dmg: 0.00, shield: 0.70, heal: 1.60, type: 'heal', rarity: 'epic',
                self: 'regen',
                desc: 'Big heal, a shield and regeneration. The comeback card.' },
  aluvion:    { id: 'aluvion',   name: 'Barrage',     emoji: '⚡', cost: 3, dmg: 1.60, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'epic',
                applies: 'stun', energyNext: 1,
                desc: 'Stuns the rival and leaves you 1 extra energy next turn.' },

  // ── AMPLIACIÓN (2026-08-11) ──────────────────────────────────────────────
  // Ocho cartas nuevas para que la mano dé más juego. Se han construido SOLO
  // con mecánicas que el motor de batalla ya resuelve (dmg / shield / heal /
  // applies / self / lifesteal / energyNext), así que no hacen falta cambios ni
  // en el resolutor ni en el cliente: BattleScene pinta la carta con el emoji,
  // el nombre y la descripción que manda el servidor.
  //
  // Lo que aportan de verdad, más allá de "más cartas":
  //   • Veneno barato (Spit) — antes envenenar costaba 2 de energía sí o sí,
  //     así que abrir con veneno era imposible. Ahora hay una apertura real.
  //   • Defensas que preparan ataque (Sidestep, Roar) — defenderse dejaba de
  //     construir nada. Ahora aguantar un turno también avanza tu plan.
  //   • Rematadores (Executioner, Tempest) — dan una vía para cerrar partidas
  //     largas contra alguien que se atrinchera a base de escudos.
  // Los valores siguen la misma escala que las cartas de arriba: ~1 punto de
  // valor por energía en comunes, ~1.85 en raras y ~2.9 en épicas.

  // Comunes nuevas (coste 1)
  escupir:    { id: 'escupir',   name: 'Spit',        emoji: '💧', cost: 1, dmg: 0.55, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'common',
                applies: 'poison',
                desc: 'A cheap glob of venom. Weak hit, but the poison ticks.' },
  esquivar:   { id: 'esquivar',  name: 'Sidestep',    emoji: '💨', cost: 1, dmg: 0.00, shield: 0.75, heal: 0.00, type: 'defense', rarity: 'common',
                self: 'focus',
                desc: 'Slips aside: small shield and your next attack hits harder.' },

  // Raras nuevas (coste 2)
  zarpazo2:   { id: 'zarpazo2',  name: 'Double Slash',emoji: '⚔️', cost: 2, dmg: 1.45, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'rare',
                self: 'focus',
                desc: 'Two quick cuts that set up an even bigger next hit.' },
  rugido:     { id: 'rugido',    name: 'Roar',        emoji: '🗣️', cost: 2, dmg: 0.00, shield: 0.90, heal: 0.00, type: 'defense', rarity: 'rare',
                applies: 'stun',
                desc: 'A deafening roar: you brace up and the rival loses energy.' },
  lengua:     { id: 'lengua',    name: 'Lash',        emoji: '👅', cost: 2, dmg: 1.00, shield: 0.00, heal: 0.50, type: 'hybrid', rarity: 'rare',
                applies: 'weak',
                desc: 'Strikes, feeds and leaves the rival hitting softer.' },

  // Épicas nuevas (coste 3)
  tormenta:   { id: 'tormenta',  name: 'Tempest',     emoji: '🌪️', cost: 3, dmg: 2.40, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'epic',
                applies: 'weak', energyNext: 1,
                desc: 'A storm of blows that weakens the rival and keeps you going.' },
  verdugo:    { id: 'verdugo',   name: 'Executioner', emoji: '🪓', cost: 3, dmg: 2.50, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'epic',
                lifesteal: 0.50,
                desc: 'Brutal finisher that drains half the damage back as HP.' },
  renacer:    { id: 'renacer',   name: 'Rebirth',     emoji: '🌱', cost: 3, dmg: 0.00, shield: 1.20, heal: 1.40, type: 'heal', rarity: 'epic',
                self: 'regen', energyNext: 1,
                desc: 'Comes back swinging: shield, big heal, regen and extra energy.' },

  // ── ARMADURA Y ROTURA DE ESTADOS (2026-08-12) ────────────────────────────
  // Cierran los dos huecos que quedaban: no había defensa que durase más de un
  // turno, y no había forma de quitarse un veneno ni de romper a alguien
  // atrincherado. Ahora cada estrategia tiene su respuesta.
  caparazon:  { id: 'caparazon', name: 'Carapace',    emoji: '🐢', cost: 2, dmg: 0.00, shield: 0.60, heal: 0.00, type: 'defense', rarity: 'rare',
                self: 'armor',
                desc: 'Hardens its hide: halves the damage you take for 3 turns.' },
  sacudirse:  { id: 'sacudirse', name: 'Shake It Off',emoji: '🌀', cost: 1, dmg: 0.00, shield: 0.35, heal: 0.25, type: 'defense', rarity: 'common',
                cleanse: true,
                desc: 'Shrugs off poison, weakness and every bad effect on you.' },
  quebrar:    { id: 'quebrar',   name: 'Shatter',     emoji: '🔨', cost: 2, dmg: 1.05, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'rare',
                applies: 'expose',
                desc: 'Cracks the rival open: their armor and shields are halved.' },
  disipar:    { id: 'disipar',   name: 'Dispel',      emoji: '✨', cost: 2, dmg: 0.70, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'rare',
                dispel: true,
                desc: 'Strips every buff the rival has built up.' },
  bastion:    { id: 'bastion',   name: 'Bastion',     emoji: '🏯', cost: 3, dmg: 0.00, shield: 1.40, heal: 0.60, type: 'defense', rarity: 'epic',
                self: 'armor', cleanse: true,
                desc: 'Cleanses you, shields you and armors you for 3 turns.' },
  demoledor:  { id: 'demoledor', name: 'Wrecker',     emoji: '💣', cost: 3, dmg: 2.10, shield: 0.00, heal: 0.00, type: 'attack', rarity: 'epic',
                applies: 'expose', dispel: true,
                desc: 'Smashes through: strips the rival buffs and exposes them.' }
};
const BATTLE_CARD_IDS = Object.keys(BATTLE_CARDS);

// ── COMBOS ─────────────────────────────────────────────────────────────────
// Jugar ciertas combinaciones EN EL MISMO TURNO da una bonificación. Es lo que
// premia planear la mano en vez de tirar siempre la carta más cara.
const BATTLE_COMBOS = [
  { id: 'cazador',  name: 'Hunter',      emoji: '🎯', need: ['olfatear', 'mordisco'],  dmgMult: 1.35,
    desc: 'Sniff Out + Bite: the killing blow lands 35% harder.' },
  { id: 'fortaleza',name: 'Fortress',    emoji: '🏰', need: ['guardia', 'espinas'],    shieldMult: 1.40,
    desc: 'Guard + Bristle: shields stack 40% stronger.' },
  { id: 'ponzoña',  name: 'Plague',      emoji: '☠️', need: ['colmillo', 'colazo'],    poisonBoost: 2,
    desc: 'Venom Fang + Tail Whip: the poison lasts 2 extra turns.' },
  { id: 'vampiro',  name: 'Bloodthirst', emoji: '🧛', need: ['robavida', 'zarpazo'],   lifestealBonus: 0.35,
    desc: 'Leech Bite + Claw: steals a lot more life.' },
  { id: 'berserk',  name: 'Berserk',     emoji: '😤', need: ['gruñido', 'zarpazo', 'colazo'], dmgMult: 1.5,
    desc: 'Growl + Claw + Tail Whip: three cheap cards become a storm.' },

  // ── COMBOS NUEVOS (2026-08-11) ───────────────────────────────────────────
  // Cada uno premia una forma DISTINTA de jugar la mano, para que no haya una
  // única línea buena:
  { id: 'plaga',    name: 'Outbreak',    emoji: '🦠', need: ['escupir', 'colmillo'],   poisonBoost: 3,
    desc: 'Spit + Venom Fang: the poison digs in for 3 extra turns.' },
  { id: 'danza',    name: 'War Dance',   emoji: '🩰', need: ['esquivar', 'zarpazo2'],  dmgMult: 1.45,
    desc: 'Sidestep + Double Slash: dodge, then cut 45% deeper.' },
  { id: 'titan',    name: 'Titan',       emoji: '🗿', need: ['rugido', 'muralla'],     shieldMult: 1.55,
    desc: 'Roar + Bulwark: an unbreakable wall of fur.' },
  { id: 'sanguijuela', name: 'Bloodfeast', emoji: '🧟', need: ['verdugo', 'robavida'], lifestealBonus: 0.40,
    desc: 'Executioner + Leech Bite: nearly every point of damage comes back as HP.' },
  { id: 'ciclon',   name: 'Cyclone',     emoji: '🌀', need: ['tormenta', 'aluvion'],   dmgMult: 1.30,
    desc: 'Tempest + Barrage: the rival never gets a turn to breathe.' }
];

/** Combos completos dentro de las cartas jugadas este turno. */
function combosActivos(idsJugados) {
  const set = new Set(idsJugados);
  return BATTLE_COMBOS.filter(c => c.need.every(n => set.has(n)));
}

// Datos de la carta para el cliente. Si se pasa un jugador, se incluyen los
// valores REALES (daño/escudo/cura) calculados con su ataque, para mostrarlos
// en la carta como en Axie ("Deal 24", "Shield 15"…).
function cartaPublica(id, jugador) {
  const c = BATTLE_CARDS[id];
  if (!c) return null;
  const out = {
    id: c.id, name: c.name, emoji: c.emoji, cost: c.cost,
    type: c.type, rarity: c.rarity, desc: c.desc
  };
  // Efectos, para que el cliente los pinte como etiquetas en la carta.
  if (c.applies)    out.applies    = c.applies;
  if (c.self)       out.self       = c.self;
  if (c.lifesteal)  out.lifesteal  = c.lifesteal;
  if (c.energyNext) out.energyNext = c.energyNext;
  if (jugador && typeof jugador.attack === 'number') {
    out.dmg = c.dmg ? Math.round(jugador.attack * c.dmg) : 0;
    out.shield = c.shield ? Math.round(jugador.attack * c.shield) : 0;
    out.heal = c.heal ? Math.round(jugador.attack * c.heal) : 0;
  }
  return out;
}

// ── ESTADOS: aplicar, avanzar y consultar ──────────────────────────────────
function iniciarEstados(p) {
  if (!p.estados) p.estados = {};   // { poison: turnosRestantes, ... }
  if (typeof p.energiaExtra !== 'number') p.energiaExtra = 0;
  if (typeof p.energiaBanco  !== 'number') p.energiaBanco = 0;
}

function aplicarEstado(p, estado, turnosExtra = 0) {
  if (!estado || !BATTLE_STATUS_TURNS[estado]) return;
  iniciarEstados(p);
  const dur = BATTLE_STATUS_TURNS[estado] + turnosExtra;
  // Se refresca la duración (no se acumula sin límite).
  p.estados[estado] = Math.max(p.estados[estado] || 0, dur);
}

function tieneEstado(p, estado) {
  return !!(p.estados && p.estados[estado] > 0);
}

/**
 * Resuelve los estados al INICIO del turno: veneno y regeneración.
 * Devuelve el texto de lo que pasó, para el registro de la batalla.
 */
function tickEstados(p) {
  iniciarEstados(p);
  const notas = [];

  if (p.estados.poison > 0) {
    // El veneno ignora el escudo a propósito: es la vía para castigar a quien
    // se limita a cubrirse todos los turnos.
    const dano = Math.max(1, Math.round(p.maxHp * 0.05));
    p.hp = Math.max(0, p.hp - dano);
    notas.push(`🟢 ${p.petName} takes ${dano} poison`);
  }
  if (p.estados.regen > 0) {
    const cura = Math.max(1, Math.round(p.maxHp * 0.06));
    p.hp = Math.min(p.maxHp, p.hp + cura);
    notas.push(`💚 ${p.petName} regenerates ${cura}`);
  }

  // Se descuenta un turno a todos los estados activos.
  for (const k of Object.keys(p.estados)) {
    if (p.estados[k] > 0) p.estados[k]--;
    if (p.estados[k] <= 0) delete p.estados[k];
  }
  return notas;
}

/** Energía de la que dispone este turno (base + banco + extra − aturdimiento). */
function energiaDelTurno(p) {
  iniciarEstados(p);
  let e = BATTLE_ENERGY_PER_TURN + (p.energiaBanco || 0) + (p.energiaExtra || 0);
  if (tieneEstado(p, 'stun')) e -= 1;
  return Math.max(1, e);   // nunca se queda sin poder jugar nada
}

/** Lista de estados activos para el cliente. */
function estadosPublicos(p) {
  if (!p.estados) return [];
  return Object.entries(p.estados)
    .filter(([, t]) => t > 0)
    .map(([id, turnos]) => ({ id, turnos }));
}

/**
 * Reparte una mano PONDERADA POR EL NIVEL DE LA MASCOTA.
 *
 * Antes se sorteaba plano sobre BATTLE_CARD_IDS: una mascota de nivel 1 sacaba
 * épicas con la misma probabilidad que una de nivel 50, así que subir de nivel
 * no se notaba en la baraja y las mejores cartas salían igual de a menudo
 * desde el primer combate.
 *
 * Ahora cada rareza tiene un peso que se mueve con el nivel: las comunes van
 * perdiendo sitio y las raras y épicas lo van ganando. Los pesos son relativos,
 * así que siempre puede salir de todo — una mascota de nivel 1 puede tener
 * suerte y una de nivel 50 sigue viendo comunes. Lo que cambia es la
 * frecuencia, que es lo que hace que subir de nivel se note.
 *
 *   nivel 1   → común 70 %, rara 25 %, épica  5 %
 *   nivel 25  → común 45 %, rara 35 %, épica 20 %
 *   nivel 50+ → común 25 %, rara 40 %, épica 35 %
 */
function pesosPorNivel(nivel) {
  // 0 en el nivel 1, 1 a partir del 50.
  const t = Math.max(0, Math.min(1, ((Number(nivel) || 1) - 1) / 49));
  return {
    common: 70 - 45 * t,
    rare:   25 + 15 * t,
    epic:    5 + 30 * t
  };
}

function cartaAleatoriaPorNivel(nivel) {
  const pesos = pesosPorNivel(nivel);

  // Se sortea primero la RAREZA y después una carta de esa rareza. Así el
  // reparto no depende de cuántas cartas haya de cada tipo: añadir cartas
  // nuevas no desequilibra las probabilidades.
  const total = pesos.common + pesos.rare + pesos.epic;
  let r = Math.random() * total;
  let rareza = 'common';
  if ((r -= pesos.common) >= 0) rareza = ((r - pesos.rare) >= 0) ? 'epic' : 'rare';

  const candidatas = BATTLE_CARD_IDS.filter(id => BATTLE_CARDS[id].rarity === rareza);
  const lista = candidatas.length ? candidatas : BATTLE_CARD_IDS;
  return lista[Math.floor(Math.random() * lista.length)];
}

function repartirMano(nivel = 1) {
  const mano = [];
  // Siempre al menos una carta de 1 de energía, para que nunca haya una mano
  // imposible de jugar.
  mano.push(Math.random() < 0.5 ? 'zarpazo' : 'colazo');
  while (mano.length < BATTLE_HAND_SIZE) {
    mano.push(cartaAleatoriaPorNivel(nivel));
  }
  // Mezclar
  for (let i = mano.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [mano[i], mano[j]] = [mano[j], mano[i]];
  }
  return mano;
}

// Valida la jugada del cliente: índices reales de su mano y energía suficiente.
// El tope de energía ya NO es fijo: depende del banco, del aturdimiento y de
// las cartas que dan energía extra (energiaDelTurno).
function validarJugada(mano, indices, jugador) {
  const usados = new Set();
  const cartas = [];
  let energia = 0;
  const tope = jugador ? energiaDelTurno(jugador) : BATTLE_ENERGY_PER_TURN;

  (Array.isArray(indices) ? indices : []).forEach(i => {
    const idx = parseInt(i, 10);
    if (isNaN(idx) || idx < 0 || idx >= mano.length || usados.has(idx)) return;
    const carta = BATTLE_CARDS[mano[idx]];
    if (!carta) return;
    if (energia + carta.cost > tope) return; // no cabe
    usados.add(idx);
    energia += carta.cost;
    cartas.push(carta);
  });

  // La energía que no se gasta se guarda para el turno siguiente (con tope).
  // Así "pasar" tiene sentido táctico en vez de ser siempre malo.
  if (jugador) {
    jugador.energiaBanco = Math.min(BATTLE_MAX_ENERGY_BANK, tope - energia);
  }

  return { cartas, indices: [...usados], energia, tope };
}

// El bot juega: gasta toda la energía que pueda, priorizando curarse si está
// bajo de vida y atacando fuerte cuanto más difícil es la ronda.
// Ahora también valora los estados y busca combos.
function elegirCartasBot(bot, mano) {
  const vidaBaja = bot.hp / bot.maxHp < 0.35;
  const astucia  = bot.astucia || 0.2;

  const valor = (c) => {
    let v = vidaBaja
      ? c.heal * 3 + c.shield * 2 + c.dmg
      : c.dmg * (1 + astucia) + c.shield * 0.8 + c.heal;
    // Los estados valen más cuanto más listo es el bot (rondas altas).
    if (c.applies === 'poison') v += 0.9 * (1 + astucia);
    if (c.applies === 'stun')   v += 0.7 * (1 + astucia);
    if (c.applies === 'weak')   v += 0.5 * (1 + astucia);
    if (c.self === 'regen' && vidaBaja) v += 1.2;
    if (c.self === 'thorns')    v += 0.4;
    if (c.self === 'focus')     v += 0.5 * astucia;
    if (c.lifesteal)            v += c.lifesteal * (vidaBaja ? 1.6 : 0.8);
    if (c.energyNext)           v += 0.6;
    return v;
  };

  const orden = [...mano.keys()].sort((i, j) => valor(BATTLE_CARDS[mano[j]]) - valor(BATTLE_CARDS[mano[i]]));

  const tope = energiaDelTurno(bot);
  const elegidas = [];
  let energia = 0;
  orden.forEach(i => {
    const c = BATTLE_CARDS[mano[i]];
    if (energia + c.cost <= tope) {
      elegidas.push(i);
      energia += c.cost;
    }
  });
  bot.energiaBanco = Math.min(BATTLE_MAX_ENERGY_BANK, tope - energia);
  return elegidas;
}

// Resuelve el turno con las cartas de ambos lados, ya con estados y combos.
// Devuelve { dmgToA, dmgToB, curaA, curaB, escudoA, escudoB, texto, combos… }
function resolverCartas(a, b, cartasA, cartasB) {
  const azar = (v) => Math.max(0, Math.round(v * (0.9 + Math.random() * 0.2)));
  iniciarEstados(a); iniciarEstados(b);

  // Suma de una mano, aplicando sus propios modificadores.
  const sumar = (jugador, rival, cartas) => {
    const combos = combosActivos(cartas.map(c => c.id));
    const dmgMult    = combos.reduce((m, c) => m * (c.dmgMult    || 1), 1);
    const shieldMult = combos.reduce((m, c) => m * (c.shieldMult || 1), 1);
    const lifeBonus  = combos.reduce((s, c) => s + (c.lifestealBonus || 0), 0);
    const venenoExtra= combos.reduce((s, c) => s + (c.poisonBoost   || 0), 0);

    // 'focus' venía de un turno anterior: potencia el ataque de ESTE turno.
    const focusMult = tieneEstado(jugador, 'focus') ? 1.5 : 1;
    // 'weak' lo puso el rival: pega menos.
    const weakMult  = tieneEstado(jugador, 'weak') ? 0.65 : 1;

    let dmg = 0, shield = 0, heal = 0, lifesteal = 0, energyNext = 0;
    for (const c of cartas) {
      dmg    += azar(jugador.attack * c.dmg);
      shield += azar(jugador.attack * c.shield);
      heal   += azar(jugador.attack * c.heal);
      if (c.lifesteal)  lifesteal = Math.max(lifesteal, c.lifesteal + lifeBonus);
      if (c.energyNext) energyNext += c.energyNext;
      // Estados que la carta pone AL RIVAL o A UNO MISMO (para el turno que viene)
      if (c.applies) aplicarEstado(rival, c.applies, c.applies === 'poison' ? venenoExtra : 0);
      if (c.self)    aplicarEstado(jugador, c.self);

      // ── ROMPER ESTADOS ─────────────────────────────────────────────────
      // `cleanse` te quita TUS estados malos; `dispel` le quita al rival los
      // suyos buenos. Es lo que faltaba para poder responder a un veneno o a
      // alguien atrincherado. Se resuelven en el momento de jugar la carta.
      if (c.cleanse && jugador.estados) {
        BATTLE_ESTADOS_MALOS.forEach(e => { jugador.estados[e] = 0; });
      }
      if (c.dispel && rival.estados) {
        BATTLE_ESTADOS_BUENOS.forEach(e => { rival.estados[e] = 0; });
      }
    }

    dmg    = Math.round(dmg * dmgMult * focusMult * weakMult);

    // 'expose' del rival: los escudos que levanta valen la mitad.
    shield = Math.round(shield * shieldMult * (tieneEstado(jugador, 'expose') ? 0.5 : 1));

    return { dmg, shield, heal, lifesteal, energyNext, combos };
  };

  const A = sumar(a, b, cartasA);
  const B = sumar(b, a, cartasB);

  // ARMADURA: reduce a la mitad el daño que se recibe y dura varios turnos,
  // al contrario que el escudo, que se gasta en el turno. `expose` la anula:
  // ésa es la forma de romper a alguien que se atrinchera.
  const reduccionPorArmadura = (defensor) =>
    (tieneEstado(defensor, 'armor') && !tieneEstado(defensor, 'expose')) ? 0.5 : 1;

  // El escudo del rival absorbe daño de ESTE turno; la armadura recorta lo que
  // se cuela después.
  const dmgToB = Math.round(Math.max(0, A.dmg - B.shield) * reduccionPorArmadura(b));
  const dmgToA = Math.round(Math.max(0, B.dmg - A.shield) * reduccionPorArmadura(a));

  // Robo de vida sobre el daño REALMENTE hecho
  const roboA = A.lifesteal ? Math.round(dmgToB * A.lifesteal) : 0;
  const roboB = B.lifesteal ? Math.round(dmgToA * B.lifesteal) : 0;

  // Espinas: devuelve el 25% del daño recibido, saltándose el escudo del que pega
  const espinasA = tieneEstado(a, 'thorns') ? Math.round(dmgToA * 0.25) : 0;
  const espinasB = tieneEstado(b, 'thorns') ? Math.round(dmgToB * 0.25) : 0;

  // Energía guardada para el turno siguiente
  a.energiaExtra = A.energyNext;
  b.energiaExtra = B.energyNext;

  const nombres = (cartas) => cartas.length
    ? cartas.map(c => `${c.emoji} ${c.name}`).join(' + ')
    : 'nothing (no energy spent)';

  const textoCombos = (combos, quien) =>
    combos.length ? `  ${combos.map(c => `${c.emoji} ${quien} COMBO: ${c.name}!`).join(' ')}` : '';

  const texto =
    `${a.petName}: ${nombres(cartasA)} → ${dmgToB} dmg` +
    (A.heal ? ` (+${A.heal} HP)` : '') + (roboA ? ` (drains ${roboA})` : '') +
    textoCombos(A.combos, a.petName) +
    `  |  ${b.petName}: ${nombres(cartasB)} → ${dmgToA} dmg` +
    (B.heal ? ` (+${B.heal} HP)` : '') + (roboB ? ` (drains ${roboB})` : '') +
    textoCombos(B.combos, b.petName) +
    (espinasA ? `  🦔 ${b.petName} takes ${espinasA} from thorns` : '') +
    (espinasB ? `  🦔 ${a.petName} takes ${espinasB} from thorns` : '');

  return {
    // El daño de espinas se suma al del rival correspondiente
    dmgToA: dmgToA + espinasB,
    dmgToB: dmgToB + espinasA,
    curaA: A.heal + roboA,
    curaB: B.heal + roboB,
    escudoA: A.shield, escudoB: B.shield,
    combosA: A.combos.map(c => ({ id: c.id, name: c.name, emoji: c.emoji })),
    combosB: B.combos.map(c => ({ id: c.id, name: c.name, emoji: c.emoji })),
    texto
  };
}

function clearBattleTurnTimer(match) {
  if (match && match.turnTimer) {
    clearTimeout(match.turnTimer);
    match.turnTimer = null;
  }
}

async function saveBattleResult(match, winnerKey, reason) {
  try {
    const season = await getCurrentBattleSeason();
    const winner = winnerKey ? match[winnerKey] : null;
    const loser = winnerKey ? match[winnerKey === 'a' ? 'b' : 'a'] : null;

    const bump = async (p, gano) => {
      if (!p || !p.playerName || p.playerName === '---') return;
      if (p.isBot) return; // el bot no entra en la clasificación

      // Puntos: P2P → 3 por ganar, 1 por participar.
      //         Bot  → 1 por ganar, 0 por perder (tope de 5 batallas al día,
      //         así no se puede farmear la tabla contra la máquina).
      const puntos = match.esBot ? (gano ? 1 : 0) : (gano ? 3 : 1);

      const doc = await BattleScore.findOneAndUpdate(
        { seasonNumber: season.seasonNumber, playerName: p.playerName },
        {
          $set: { address: p.address || '', petName: p.petName || '---', lastBattleAt: new Date() },
          $inc: {
            points: puntos,
            wins: gano ? 1 : 0,
            losses: gano ? 0 : 1,
            battles: 1
          }
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );

      // Racha
      const nuevaRacha = gano ? (doc.streak || 0) + 1 : 0;
      await BattleScore.updateOne(
        { _id: doc._id },
        { $set: { streak: nuevaRacha, bestStreak: Math.max(doc.bestStreak || 0, nuevaRacha) } }
      );

      // NIVEL DE LA MASCOTA: sube con las batallas. Se guarda en GamePlayer para
      // que viaje en /api/load y en los paquetes de multijugador (así los demás
      // jugadores también ven el nivel junto al nombre del perro).
      try {
        const nivelPet = computePetLevel(doc.wins || 0, doc.battles || 0);
        await GamePlayer.updateOne({ playerName: p.playerName }, { $set: { petLevel: nivelPet } });
        // Avisar al jugador de su nuevo nivel de mascota. Sin esto el cliente
        // solo lo leía en /api/load, así que el nivel del perro se quedaba
        // congelado hasta recargar la página aunque ya hubieras ganado.
        try { p.socket && p.socket.emit('petLevelUpdate', { petLevel: nivelPet }); } catch (_) {}
      } catch (e) {
        console.warn('⚠️  No se pudo actualizar petLevel:', e.message);
      }
    };

    if (winner && loser) {
      await bump(winner, true);
      await bump(loser, false);
    }

    await BattleLog.create({
      seasonNumber: season.seasonNumber,
      matchId: match.id,
      winner: winner ? winner.playerName : '',
      loser: loser ? loser.playerName : '',
      turns: match.turn,
      reason: reason || 'ko'
    });
  } catch (e) {
    console.error('❌ Error guardando resultado de batalla:', e);
  }
}

async function endBattle(match, winnerKey, reason) {
  if (!match || match.ended) return;
  match.ended = true;
  clearBattleTurnTimer(match);

  await saveBattleResult(match, winnerKey, reason);

  // Contador de batallas diarias contra bot (solo si esta era una de ellas).
  // El contador vive ENTERO en el backend: se incrementa aquí y el valor
  // resultante se manda al cliente, que solo lo pinta.
  let dailyInfo = null;
  if (match.esBot && match.a && match.a.playerName && match.a.playerName !== '---') {
    try {
      const doc = await BattleDaily.findOneAndUpdate(
        { playerName: match.a.playerName, day: battleTodayKey() },
        { $inc: { done: 1, wins: winnerKey === 'a' ? 1 : 0 } },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
      const done = doc.done;
      dailyInfo = {
        done,
        max: BATTLE_DAILY_MAX,
        remaining: Math.max(0, BATTLE_DAILY_MAX - done),
        nextRound: Math.min(BATTLE_DAILY_MAX, done + 1),
        wins: doc.wins || 0
      };
      console.log(`🗓️  Batallas diarias de ${match.a.playerName}: ${done}/${BATTLE_DAILY_MAX}`);
    } catch (e) {
      console.error('❌ Error actualizando batallas diarias:', e);
    }
  }

  ['a', 'b'].forEach(key => {
    const p = match[key];
    if (!p || !p.socket) return;   // el bot no tiene socket
    const gano = winnerKey === key;
    p.socket.emit('battle:end', {
      matchId: match.id,
      result: winnerKey ? (gano ? 'win' : 'lose') : 'draw',
      reason: reason || 'ko',
      // Contra bot se da 1 punto por victoria (máximo 5 batallas al día);
      // en P2P, 3 por ganar y 1 por participar.
      pointsEarned: winnerKey ? (match.esBot ? (gano ? 1 : 0) : (gano ? 3 : 1)) : 0,
      mode: match.esBot ? 'bot' : 'pvp',
      round: match.esBot ? match.ronda : null,
      daily: dailyInfo,
      you: battlePublicPlayer(p),
      rival: battlePublicPlayer(match[key === 'a' ? 'b' : 'a'])
    });
    // Además del 'battle:end', se manda el contador por su propio evento: así
    // el hub del mundo lo repinta aunque el jugador ya hubiera salido de la
    // escena de batalla, sin tener que volver a preguntar.
    if (dailyInfo && key === 'a') {
      try { p.socket.emit('battle:daily', dailyInfo); } catch (_) {}
    }
    socketMatch.delete(p.socket.id);
  });

  battleMatches.delete(match.id);
}

function startBattleTurn(match) {
  clearBattleTurnTimer(match);
  match.actions = { a: null, b: null };
  match.turn += 1;

  // ── ESTADOS AL INICIO DEL TURNO ─────────────────────────────────────────
  // Veneno y regeneración se resuelven ANTES de repartir. Si alguien cae por
  // el veneno, la batalla termina aquí sin repartir mano.
  const notasEstado = [...tickEstados(match.a), ...tickEstados(match.b)];
  if (match.a.hp <= 0 || match.b.hp <= 0) {
    const ganador = match.a.hp <= 0 && match.b.hp <= 0 ? null : (match.a.hp <= 0 ? 'b' : 'a');
    ['a', 'b'].forEach(k => {
      const p = match[k];
      if (p && p.socket && notasEstado.length) {
        p.socket.emit('battle:status', { turn: match.turn, notes: notasEstado });
      }
    });
    endBattle(match, ganador, 'poison');
    return;
  }

  // Mano nueva para cada uno en cada turno, ponderada por el nivel de SU
  // mascota: cuanto más alta, más a menudo salen cartas raras y épicas.
  match.hands = {
    a: repartirMano(match.a && match.a.level),
    b: repartirMano(match.b && match.b.level)
  };

  ['a', 'b'].forEach(key => {
    const p = match[key];
    if (p && p.socket) {
      p.socket.emit('battle:turnStart', {
        matchId: match.id,
        turn: match.turn,
        msToChoose: BATTLE_TURN_MS,
        // Energía REAL de este turno: base + banco + extra − aturdimiento.
        energy: energiaDelTurno(p),
        energyBase: BATTLE_ENERGY_PER_TURN,
        energyBank: p.energiaBanco || 0,
        // Cada carta lleva ya sus valores reales para ESTE jugador (según su
        // ataque), así la UI muestra "Deal 24 / Shield 15" como en Axie.
        hand: match.hands[key].map(cid => cartaPublica(cid, p)),
        // Estados activos de los dos lados, para pintarlos como iconos.
        statusYou:   estadosPublicos(p),
        statusRival: estadosPublicos(match[key === 'a' ? 'b' : 'a']),
        statusNotes: notasEstado,
        combos: BATTLE_COMBOS.map(c => ({ id: c.id, name: c.name, emoji: c.emoji, need: c.need, desc: c.desc })),
        you: battlePublicPlayer(p),
        rival: battlePublicPlayer(match[key === 'a' ? 'b' : 'a'])
      });
    }
  });

  // El bot juega al momento (el jugador no ve sus cartas hasta resolver)
  if (match.b && match.b.isBot) {
    match.actions.b = elegirCartasBot(match.b, match.hands.b);
  }

  // Si alguien no juega a tiempo, pasa turno sin gastar energía
  match.turnTimer = setTimeout(() => {
    if (match.ended) return;
    if (!match.actions.a) match.actions.a = [];
    if (!match.actions.b) match.actions.b = [];
    resolveBattleTurn(match);
  }, BATTLE_TURN_MS + 1000);
}

async function resolveBattleTurn(match) {
  if (match.ended) return;
  clearBattleTurnTimer(match);

  // Se pasa el jugador para que el tope de energía sea el REAL de este turno
  // (con banco, energía extra y aturdimiento) y para guardar lo no gastado.
  const jugadaA = validarJugada(match.hands.a, match.actions.a || [], match.a);
  const jugadaB = validarJugada(match.hands.b, match.actions.b || [], match.b);

  const res = resolverCartas(match.a, match.b, jugadaA.cartas, jugadaB.cartas);
  const { dmgToA, dmgToB, texto } = res;

  match.a.hp = Math.max(0, Math.min(match.a.maxHp, match.a.hp - dmgToA + res.curaA));
  match.b.hp = Math.max(0, Math.min(match.b.maxHp, match.b.hp - dmgToB + res.curaB));

  ['a', 'b'].forEach(key => {
    const p = match[key];
    if (!p || !p.socket) return;
    const mia = key === 'a' ? jugadaA : jugadaB;
    const suya = key === 'a' ? jugadaB : jugadaA;
    const rivalP = match[key === 'a' ? 'b' : 'a'];
    p.socket.emit('battle:turn', {
      matchId: match.id,
      turn: match.turn,
      yourCards: mia.cartas.map(c => cartaPublica(c.id, p)),
      rivalCards: suya.cartas.map(c => cartaPublica(c.id, rivalP)),
      damageToYou: key === 'a' ? dmgToA : dmgToB,
      damageToRival: key === 'a' ? dmgToB : dmgToA,
      healYou: key === 'a' ? res.curaA : res.curaB,
      shieldYou: key === 'a' ? res.escudoA : res.escudoB,
      shieldRival: key === 'a' ? res.escudoB : res.escudoA,
      log: texto,
      // Combos y estados, para que la UI los pueda anunciar.
      combosYou:   key === 'a' ? res.combosA : res.combosB,
      combosRival: key === 'a' ? res.combosB : res.combosA,
      statusYou:   estadosPublicos(p),
      statusRival: estadosPublicos(rivalP),
      you: battlePublicPlayer(p),
      rival: battlePublicPlayer(match[key === 'a' ? 'b' : 'a'])
    });
  });

  const muertoA = match.a.hp <= 0;
  const muertoB = match.b.hp <= 0;

  if (muertoA || muertoB || match.turn >= BATTLE_MAX_TURNS) {
    let ganador = null;
    if (muertoA && !muertoB) ganador = 'b';
    else if (muertoB && !muertoA) ganador = 'a';
    else if (!muertoA && !muertoB) ganador = match.a.hp === match.b.hp ? null : (match.a.hp > match.b.hp ? 'a' : 'b');
    await endBattle(match, ganador, muertoA || muertoB ? 'ko' : 'timeout');
    return;
  }

  setTimeout(() => startBattleTurn(match), 1200);
}

/**
 * Nombre CANÓNICO del jugador de un socket. Es la clave con la que se cuentan
 * las batallas diarias, así que tiene que dar SIEMPRE el mismo valor para el
 * mismo jugador.
 *
 * El fallo que arregla: antes, si no se resolvía, se caía a
 * `socket.playerData?.username`, que es el nombre VISIBLE del personaje (el
 * campo Username), no el playerName. Según en qué estado estuviera el socket
 * —recién reconectado, antes o después de joinRoom— la misma persona contaba
 * sus batallas bajo dos claves distintas. Por eso el contador iba 5 → 4 y al
 * rato volvía a 5: la segunda lectura miraba un documento diferente, vacío.
 *
 * @returns {string|null} el playerName, o null si no se puede resolver.
 */
async function resolveBattlePlayerName(socket) {
  if (socket.authenticatedPlayer && socket.authenticatedPlayer !== '---') {
    return socket.authenticatedPlayer;
  }
  const addr = socket.authenticatedAddress ? socket.authenticatedAddress.toLowerCase() : null;
  if (!addr) return null;

  try {
    const auth = await PlayerAuth.findOne({ address: addr }).select('playerName').lean();
    if (auth && auth.playerName && auth.playerName !== '---') {
      socket.authenticatedPlayer = auth.playerName;   // se cachea en el socket
      return auth.playerName;
    }
  } catch (e) { /* se sigue con el fallback de abajo */ }

  try {
    const gp = await GamePlayer.findOne({ address: addr }).select('playerName').lean();
    if (gp && gp.playerName && gp.playerName !== '---') {
      socket.authenticatedPlayer = gp.playerName;
      return gp.playerName;
    }
  } catch (e) { /* nada */ }

  // Última opción estable: la propia dirección. NUNCA el Username visible, que
  // el jugador puede cambiar y que no identifica la cuenta.
  socket.authenticatedPlayer = addr;
  return addr;
}

// Datos del jugador humano a partir de su socket (nivel, nombre de mascota…)
async function construirJugadorDeSocket(socket) {
  let playerName = await resolveBattlePlayerName(socket);
  if (!playerName) playerName = '---';

  // petHealth NO estaba declarado y el select() tampoco lo traia: la asignacion
  // creaba un global suelto y el valor siempre acababa siendo el 100 por
  // defecto, con lo que la vida de la mascota nunca habria llegado a la batalla.
  let nivel = 1, petName = 'Pet', petHealth = 100;
  try {
    const gp = await GamePlayer.findOne({ playerName })
      .select('nivel nivel_exp petName petHealth').lean();
    if (gp) {
      // ANTI-TRAMPA: el nivel de combate se DERIVA de la experiencia, que está
      // respaldada por el contrato, en vez de leer `gp.nivel` — que hasta ahora
      // lo escribía el cliente y bastaba para entrar a PvP con estadísticas de
      // nivel 150. Ver nivelPorExperiencia().
      nivel = Math.max(1, nivelPorExperiencia(gp.nivel_exp));
      petName = gp.petName && gp.petName !== '---' ? gp.petName : 'Pet';
      petHealth = gp.petHealth == null ? 100 : gp.petHealth;
    }
  } catch (e) { /* valores por defecto */ }

  const stats = battleStatsForLevel(nivel);

  // LA MASCOTA ENTRA CON LA VIDA QUE LE QUEDE.
  // `maxHp` sigue siendo el del nivel (la barra mide lo mismo), pero la vida
  // con la que ARRANCA el combate es el porcentaje que tenga la mascota en el
  // mundo. Si la mordió un cocodrilo y va al 40%, entra al 40%. Si está muerta
  // (0) entra con 1: no se puede empezar un combate ya perdido de salida, pero
  // se nota muchísimo.
  const saludPet = Math.max(0, Math.min(100, Number(petHealth) || 0));
  const hpEntrada = Math.max(1, Math.round(stats.maxHp * saludPet / 100));

  return {
    socket,
    isBot: false,
    playerName,
    petName,
    address: socket.authenticatedAddress || '',
    level: nivel,
    petHealthPct: saludPet,
    maxHp: stats.maxHp,
    hp: hpEntrada,
    attack: stats.attack
  };
}

// Estado de las 5 batallas diarias de un jugador
async function estadoBatallasDiarias(playerName) {
  const day = battleTodayKey();
  const doc = await BattleDaily.findOne({ playerName, day }).lean();
  const done = doc ? doc.done : 0;
  return {
    done,
    max: BATTLE_DAILY_MAX,
    remaining: Math.max(0, BATTLE_DAILY_MAX - done),
    nextRound: Math.min(BATTLE_DAILY_MAX, done + 1),
    wins: doc ? doc.wins : 0
  };
}

async function tryBattleMatchmaking() {
  while (battleQueue.length >= 2) {
    const sa = battleQueue.shift();
    const sb = battleQueue.shift();
    if (!sa || !sa.connected) { if (sb && sb.connected) battleQueue.unshift(sb); continue; }
    if (!sb || !sb.connected) { battleQueue.unshift(sa); continue; }

    const [a, b] = await Promise.all([
      construirJugadorDeSocket(sa),
      construirJugadorDeSocket(sb)
    ]);

    // NUNCA emparejar a alguien consigo mismo. Pasa con dos pestañas abiertas
    // (o al reconectar dejando el socket viejo en la cola): la partida salía
    // "jugador vs jugador" pero el rival era uno mismo, con el nombre por
    // defecto de la mascota, y parecía una batalla contra un bot.
    if (a.playerName && a.playerName === b.playerName) {
      console.log(`↩️  Cola: ${a.playerName} estaba dos veces; se descarta el socket viejo`);
      // Se conserva el más reciente (sb) y se descarta el anterior.
      try { sa.emit('battle:error', { error: 'duplicate_session' }); } catch (_) {}
      battleQueue.unshift(sb);
      continue;
    }

    const match = {
      id: `m_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      a, b, turn: 0, ended: false, esBot: false,
      actions: { a: null, b: null },
      turnTimer: null
    };

    battleMatches.set(match.id, match);
    socketMatch.set(sa.id, match.id);
    socketMatch.set(sb.id, match.id);

    ['a', 'b'].forEach(key => {
      const p = match[key];
      p.socket.emit('battle:matched', {
        matchId: match.id,
        // Se marca explícitamente el modo: así el cliente puede rechazar una
        // partida que no sea la que pidió.
        mode: 'pvp',
        you: battlePublicPlayer(p),
        rival: battlePublicPlayer(match[key === 'a' ? 'b' : 'a'])
      });
    });

    console.log(`⚔️ Batalla ${match.id}: ${a.playerName} vs ${b.playerName}`);
    setTimeout(() => startBattleTurn(match), 2500);
  }
}

// ---------------------------------------------------------------------------
// BATALLA DIARIA CONTRA BOT (5 al día, cada una más difícil)
// ---------------------------------------------------------------------------
async function iniciarBatallaBot(socket) {
  const jugador = await construirJugadorDeSocket(socket);
  if (!jugador.playerName || jugador.playerName === '---') {
    return socket.emit('battle:error', { error: 'not_authenticated' });
  }

  const estado = await estadoBatallasDiarias(jugador.playerName);
  if (estado.remaining <= 0) {
    return socket.emit('battle:error', { error: 'daily_limit', daily: estado });
  }

  const ronda = estado.nextRound;
  const bot = crearBotDeRonda(ronda, jugador.level);

  /* ═══════════════════════════════════════════════════════════════════
     EL RIVAL LLEGA COMO LLEGUES TÚ
     ───────────────────────────────────────────────────────────────────
     LA INJUSTICIA QUE ESTO ARREGLA: la mascota entra al combate con la
     vida que le quede en el mapa —si la mordió un cocodrilo, al 40 %—
     mientras que el bot entraba SIEMPRE al 100 %. Sumado a que el bot ya
     pegaba y aguantaba más por la ronda, una batalla diaria con la
     mascota tocada estaba perdida antes de repartir cartas.

     Ahora el bot llega en la misma proporción, con un suelo del 75 %: es
     un animal salvaje, no está recién curado, pero tampoco medio muerto.
     Así seguir cuidando a la mascota SIGUE importando —a media vida el
     combate es mucho más corto y un mal turno te tumba— pero deja de ser
     una derrota automática.
     ═══════════════════════════════════════════════════════════════════ */
  const fraccionJugador = Math.max(0, Math.min(1,
    (Number(jugador.petHealthPct) || 100) / 100));
  const fraccionBot = Math.max(0.75, fraccionJugador);
  bot.hp = Math.max(1, Math.round(bot.maxHp * fraccionBot));

  const match = {
    id: `b_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    a: jugador, b: bot,
    turn: 0, ended: false,
    esBot: true, ronda,
    actions: { a: null, b: null },
    ultimaAccionJugador: null,
    turnTimer: null
  };

  battleMatches.set(match.id, match);
  socketMatch.set(socket.id, match.id);

  socket.emit('battle:matched', {
    matchId: match.id,
    mode: 'bot',
    round: ronda,
    daily: estado,
    you: battlePublicPlayer(jugador),
    rival: battlePublicPlayer(bot)
  });

  console.log(`🤖 Batalla diaria ${match.id}: ${jugador.playerName} vs ${bot.petName} (ronda ${ronda})`);
  setTimeout(() => startBattleTurn(match), 2000);
}

io.on('connection', (socket) => {
  socket.on('battle:dailyStatus', async () => {
    try {
      const jugador = await construirJugadorDeSocket(socket);
      if (!jugador.playerName || jugador.playerName === '---') {
        return socket.emit('battle:daily', { done: 0, max: BATTLE_DAILY_MAX, remaining: BATTLE_DAILY_MAX, nextRound: 1, wins: 0 });
      }
      socket.emit('battle:daily', await estadoBatallasDiarias(jugador.playerName));
    } catch (e) {
      console.error('❌ battle:dailyStatus', e);
    }
  });

  socket.on('battle:bot', async () => {
    try {
      if (!socket.authenticatedAddress) {
        return socket.emit('battle:error', { error: 'not_authenticated' });
      }
      if (socketMatch.has(socket.id)) {
        return socket.emit('battle:error', { error: 'already_in_battle' });
      }
      await iniciarBatallaBot(socket);
    } catch (e) {
      console.error('❌ battle:bot', e);
      socket.emit('battle:error', { error: 'bot_failed' });
    }
  });

  socket.on('battle:queue', async () => {
    try {
      // Solo jugadores autenticados (la tabla es por playerName)
      if (!socket.authenticatedAddress) {
        return socket.emit('battle:error', { error: 'not_authenticated' });
      }
      if (socketMatch.has(socket.id)) {
        return socket.emit('battle:error', { error: 'already_in_battle' });
      }
      if (battleQueue.some(s => s.id === socket.id)) return;

      battleQueue.push(socket);
      socket.emit('battle:queued', { position: battleQueue.length });
      await tryBattleMatchmaking();
    } catch (e) {
      console.error('❌ battle:queue', e);
      socket.emit('battle:error', { error: 'queue_failed' });
    }
  });

  socket.on('battle:leaveQueue', () => {
    const i = battleQueue.findIndex(s => s.id === socket.id);
    if (i >= 0) battleQueue.splice(i, 1);
    socket.emit('battle:leftQueue', {});
  });

  socket.on('battle:action', (data) => {
    try {
      const matchId = socketMatch.get(socket.id);
      if (!matchId) return;
      const match = battleMatches.get(matchId);
      if (!match || match.ended) return;

      const key = (match.a.socket && match.a.socket.id === socket.id) ? 'a' : 'b';
      if (match.actions[key]) return; // ya jugó en este turno

      // El cliente manda los ÍNDICES de las cartas de su mano; la validación
      // (que existan, que no repita y que quepan en la energía) se hace aquí,
      // nunca en el navegador.
      const indices = (data && Array.isArray(data.cards)) ? data.cards.slice(0, BATTLE_HAND_SIZE) : [];
      match.actions[key] = indices;

      // Avisar al rival de que ya eligió (sin decir qué)
      const rival = match[key === 'a' ? 'b' : 'a'];
      if (rival && rival.socket) rival.socket.emit('battle:rivalReady', { turn: match.turn });

      if (match.actions.a && match.actions.b) resolveBattleTurn(match);
    } catch (e) {
      console.error('❌ battle:action', e);
    }
  });

  socket.on('battle:forfeit', async () => {
    const matchId = socketMatch.get(socket.id);
    if (!matchId) return;
    const match = battleMatches.get(matchId);
    if (!match || match.ended) return;
    const key = (match.a.socket && match.a.socket.id === socket.id) ? 'a' : 'b';
    await endBattle(match, key === 'a' ? 'b' : 'a', 'forfeit');
  });

  socket.on('disconnect', async () => {
    const i = battleQueue.findIndex(s => s.id === socket.id);
    if (i >= 0) battleQueue.splice(i, 1);

    const matchId = socketMatch.get(socket.id);
    // El candado se suelta SIEMPRE. Antes se hacía `return` cuando el combate
    // ya no existía o ya había terminado, y la entrada de socketMatch se
    // quedaba puesta: a partir de ahí, cualquier intento de empezar otra
    // batalla respondía 'already_in_battle' y el jugador no podía entrar más.
    socketMatch.delete(socket.id);
    if (!matchId) return;
    const match = battleMatches.get(matchId);
    if (!match || match.ended) return;
    const key = (match.a.socket && match.a.socket.id === socket.id) ? 'a' : 'b';
    await endBattle(match, key === 'a' ? 'b' : 'a', 'forfeit');
  });

  // Salir de la escena de batalla sin haber terminado (volver al mundo, cerrar
  // el panel…). Sin esto el candado seguía puesto en el MISMO socket y el
  // jugador se quedaba con 'already_in_battle' hasta recargar la página.
  socket.on('battle:leave', async () => {
    const matchId = socketMatch.get(socket.id);
    socketMatch.delete(socket.id);
    const i = battleQueue.findIndex(s => s.id === socket.id);
    if (i >= 0) battleQueue.splice(i, 1);
    if (!matchId) return;
    const match = battleMatches.get(matchId);
    if (!match || match.ended) return;
    const key = (match.a.socket && match.a.socket.id === socket.id) ? 'a' : 'b';
    await endBattle(match, key === 'a' ? 'b' : 'a', 'forfeit');
  });
});

console.log('✅ Battle routes cargados: GET /api/battle/leaderboard + sockets battle:*');


// --- MANEJO DE ERRORES ---
// FIX: '/api/*' como string también se rompe en Express 5 / path-to-regexp 8+
// (mismo "Missing parameter name" que el de app.options). Probé el reemplazo
// obvio con una RegExp de ruta (app.use(/^\/api\//, ...)) y NO funcionó en
// ninguna de las dos versiones al probarlo — Express no lo matcheaba nunca,
// devolvía su 404 HTML por defecto en vez de pasar por el handler. La forma
// que sí probé y funciona igual en Express 4 y 5 es no usar un patrón de ruta
// en absoluto: un middleware normal que revisa req.path a mano.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'not_found' });
  }
  next();
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
  console.log(`⛓️  Liquidador de vitales: cada ${CHAIN_SETTLE_TICK_MS / 1000}s (espera ${CHAIN_SETTLE_DELAY_MS / 1000}s)`);
  console.log(`=================================`);

  // LIQUIDADOR DE VITALES (2026-08-05). Escribe en la cadena, agrupadas, las
  // barras que se cobraron en Mongo: UNA transacción por barra y jugador.
  //
  // La primera pasada es INMEDIATA y sin esperar el minuto: si el proceso se
  // reinició (o se cayó) con deudas apuntadas, se saldan al arrancar. Así, ni
  // recargar el navegador ni tirar el servidor sirven para escaparse de un
  // consumo ya cobrado.
  setTimeout(() => { rondaDeLiquidacion({ inmediato: true }).catch(() => {}); }, 8000);
  setInterval(() => { rondaDeLiquidacion().catch(() => {}); }, CHAIN_SETTLE_TICK_MS);
});

// --- GRACEFUL SHUTDOWN ---
/* ════════════════════════════════════════════════════════════════════════════
   QUE UN FALLO SUELTO NO TIRE EL SERVIDOR ENTERO
   ────────────────────────────────────────────────────────────────────────────
   FALLO QUE ESTO ARREGLA (y explica desconexiones "sin motivo"):

   No había ningún manejador de `unhandledRejection`. Desde Node 15 el
   comportamiento por defecto ante una promesa rechazada que nadie captura es
   MATAR EL PROCESO. Y este archivo está lleno de trabajo asíncrono de fondo
   —tareas periódicas, llamadas a la cadena, escrituras a Mongo— donde un fallo
   pasajero (la base de datos reconectando, el RPC devolviendo un 502) es normal
   y esperable. Cualquiera de ellos, en el sitio equivocado, tumbaba el servidor
   con todos los jugadores dentro: se les caía el chat, dejaban de verse entre
   ellos, y al volver el proceso el socket reconectaba pero fuera de la sala.

   El criterio es el estándar para un servidor de larga vida:

     · `unhandledRejection` → se APUNTA y se sigue. Un fallo de red asíncrono no
       deja el proceso en mal estado; tirarlo hace mucho más daño que el fallo.
     · `uncaughtException` → se apunta y se cierra ORDENADAMENTE. Ahí sí puede
       haber quedado estado a medias, así que lo correcto es salir y dejar que
       el supervisor levante un proceso limpio — pero cerrando antes el socket y
       Mongo, para que los clientes se enteren y reconecten.
   ═══════════════════════════════════════════════════════════════════════════ */
let _cerrando = false;

function cerrarOrdenadamente(motivo, codigo) {
  if (_cerrando) return;
  _cerrando = true;
  console.log(`🛑 Cerrando servidor (${motivo})...`);
  // Un tope: si algo se queda colgado, no se puede dejar el proceso zombi.
  const rendicion = setTimeout(() => process.exit(codigo), 8000);
  if (typeof rendicion.unref === 'function') rendicion.unref();
  try { if (typeof io !== 'undefined' && io) io.close(); } catch (e) {}
  server.close(async () => {
    try {
      await mongoose.connection.close(false);
      console.log('✅ Conexión MongoDB cerrada');
    } catch (e) {
      console.error('❌ Error cerrando MongoDB:', e && e.message);
      codigo = codigo || 1;
    }
    process.exit(codigo);
  });
}

process.on('unhandledRejection', (razon) => {
  console.error('⚠️  Promesa rechazada sin capturar — el servidor SIGUE en pie:',
                (razon && razon.stack) || razon);
});

process.on('uncaughtException', (err) => {
  console.error('💥 Excepción sin capturar:', (err && err.stack) || err);
  cerrarOrdenadamente('uncaughtException', 1);
});

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
