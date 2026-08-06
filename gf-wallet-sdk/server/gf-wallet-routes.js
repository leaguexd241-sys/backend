/**
 * GF Wallet SDK — rutas de backend
 * ============================================================================
 * Se monta desde server2.js:
 *
 *     require('./gf-wallet-sdk/server/gf-wallet-routes')(app, {
 *       mongoose, apiLimiter, strictLimiter, csrfProtection, JWT_SECRET
 *     });
 *
 * NO añade dependencias npm: usa lo que server2.js ya trae (express, mongoose,
 * jsonwebtoken, crypto) y el `fetch` nativo de Node 18+.
 *
 * ---------------------------------------------------------------------------
 * QUÉ GUARDA Y QUÉ NO
 * ---------------------------------------------------------------------------
 * Guarda, por cuenta social:
 *   · subHash        HMAC del "proveedor:id-de-usuario" con un pimiento del
 *                    servidor. NO se guarda el id crudo ni el correo: si se
 *                    filtra la base de datos, no se puede saber quién es quién
 *                    sin el pimiento.
 *   · address        la dirección pública de la wallet (no es secreta).
 *   · serverShareEnc LA MITAD DEL SERVIDOR de la clave, cifrada en reposo con
 *                    AES-256-GCM (clave en la variable de entorno
 *                    GF_WALLET_VAULT_KEY).
 *   · recoveryEnc    la clave entera cifrada con el CÓDIGO DE RECUPERACIÓN del
 *                    jugador. El servidor no tiene ese código: para él este
 *                    campo es ruido.
 *
 * NO guarda: la clave privada, ni la mitad del dispositivo, ni el código de
 * recuperación, ni nada que permita reconstruir la clave por sí solo.
 *
 * Aunque un atacante se lleve TODA la base de datos y el fichero .env, obtiene
 * la mitad del servidor — y con media clave XOR no se puede deducir nada de la
 * otra mitad. Necesitaría además el navegador de la víctima.
 * ---------------------------------------------------------------------------
 */
'use strict';

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');

module.exports = function mountGfWalletRoutes(app, deps) {
  const {
    mongoose,
    apiLimiter    = (req, res, next) => next(),
    strictLimiter = (req, res, next) => next(),
    csrfProtection = (req, res, next) => next(),
    // Middleware de sesión del juego. Solo lo usa /api/wallet/ticket, que exige
    // una sesión ya iniciada para volver a abrir la bóveda sin repetir el OAuth.
    authMiddleware = (req, res, next) => next(),
    JWT_SECRET
  } = deps || {};

  if (!mongoose) throw new Error('gf-wallet-routes: falta `mongoose` en las dependencias');

  // ==========================================================================
  // CONFIGURACIÓN POR ENTORNO
  // ==========================================================================
  const CFG = {
    google:   { clientId: process.env.GF_GOOGLE_CLIENT_ID   || '' },
    facebook: { appId:    process.env.GF_FACEBOOK_APP_ID    || '',
                appSecret: process.env.GF_FACEBOOK_APP_SECRET || '' },
    // APPLE: solo hacen falta el Services ID y la URL de retorno.
    //
    // El .p8 (con TEAM_ID y KEY_ID) sirve para firmar el `client_secret` que
    // Apple pide al CANJEAR un código por un token. Aquí no se canjea nada:
    // se pide `response_type=code id_token`, así que Apple manda el id_token
    // directamente en el form_post y se verifica su firma contra el JWKS
    // público de Apple. Nunca se llama al endpoint de tokens.
    //
    // Se dejan leídas por si algún día hace falta revocación de tokens
    // (server-to-server), pero NO son obligatorias para que el login funcione.
    apple:    { clientId: process.env.GF_APPLE_CLIENT_ID    || '',
                redirectUri: process.env.GF_APPLE_REDIRECT_URI || '',
                teamId:   process.env.GF_APPLE_TEAM_ID      || '',
                keyId:    process.env.GF_APPLE_KEY_ID       || '',
                privateKey: (process.env.GF_APPLE_PRIVATE_KEY || '').replace(/\\n/g, '\n') }
  };

  // Pimienta para el HMAC de los identificadores sociales.
  const SUB_PEPPER = process.env.GF_WALLET_SUB_PEPPER || '';
  // Clave de cifrado en reposo de la mitad del servidor (32 bytes en hex/base64).
  const VAULT_KEY_RAW = process.env.GF_WALLET_VAULT_KEY || '';

  const TICKET_TTL_SEC = 300;         // el permiso tras el OAuth dura 5 minutos
  const STATE_TTL_SEC  = 600;         // el state/nonce del OAuth, 10 minutos

  function claveBoveda() {
    if (!VAULT_KEY_RAW) return null;
    const b = /^[0-9a-fA-F]{64}$/.test(VAULT_KEY_RAW)
      ? Buffer.from(VAULT_KEY_RAW, 'hex')
      : Buffer.from(VAULT_KEY_RAW, 'base64');
    return b.length === 32 ? b : null;
  }

  const VAULT_KEY = claveBoveda();
  const SECRET    = JWT_SECRET || process.env.JWT_SECRET || '';

  // Un proveedor solo se anuncia como disponible si tiene TODO lo que su flujo
  // necesita de verdad. Ni de más (pedir variables que no se usan deja el botón
  // apagado sin motivo) ni de menos: a Apple le faltaba comprobar `redirectUri`,
  // que sí se usa para construir la URL de autorización — sin él, el botón
  // aparecía y Apple respondía `invalid_request`.
  const CONFIGURADO = {
    google:   !!CFG.google.clientId,
    facebook: !!(CFG.facebook.appId && CFG.facebook.appSecret),
    apple:    !!(CFG.apple.clientId && CFG.apple.redirectUri)
  };

  if (!VAULT_KEY)  console.warn('⚠️  [gf-wallet] Falta GF_WALLET_VAULT_KEY (32 bytes) — las rutas de la wallet quedan DESACTIVADAS');
  if (!SUB_PEPPER) console.warn('⚠️  [gf-wallet] Falta GF_WALLET_SUB_PEPPER — las rutas de la wallet quedan DESACTIVADAS');
  if (!SECRET)     console.warn('⚠️  [gf-wallet] Falta JWT_SECRET — las rutas de la wallet quedan DESACTIVADAS');

  const ACTIVO = !!(VAULT_KEY && SUB_PEPPER && SECRET);

  // ==========================================================================
  // MODELO
  // ==========================================================================
  const socialWalletSchema = new mongoose.Schema({
    // HMAC de "<proveedor>:<sub>". Único: una cuenta social = una wallet.
    subHash:  { type: String, required: true, unique: true, index: true },
    provider: { type: String, required: true, enum: ['google', 'facebook', 'apple'] },
    address:  { type: String, required: true, lowercase: true, index: true },

    // UNA MITAD DE SERVIDOR POR DISPOSITIVO             (arreglado 2026-08-05)
    // -------------------------------------------------------------------
    // Antes esto era UNA sola mitad para toda la cuenta, y era un fallo grave:
    // la clave se reparte con XOR contra la mitad del DISPOSITIVO, así que
    // cada dispositivo necesita su propia pareja. Al vincular un móvil se
    // sobrescribía la mitad del PC y el PC dejaba de abrir la bóveda
    // ("La clave reconstruida no coincide con la cuenta registrada").
    //
    // Ahora cada dispositivo tiene su entrada: vincular uno nuevo NO toca a
    // los demás. La clave privada sigue sin estar entera en ningún sitio.
    deviceShares: [{
      deviceId:   { type: String, required: true },
      enc: {
        iv:  { type: String, required: true },
        ct:  { type: String, required: true },
        tag: { type: String, required: true }
      },
      createdAt:  { type: Date, default: Date.now },
      lastUsedAt: { type: Date, default: Date.now }
    }],

    // Mitad única de las cuentas creadas ANTES del arreglo. Solo se lee para
    // migrarla a `deviceShares` la primera vez; nunca se vuelve a escribir.
    serverShareEnc: {
      iv:  { type: String },
      ct:  { type: String },
      tag: { type: String }
    },

    // Clave entera cifrada con el código de recuperación del jugador.
    recoveryEnc: {
      salt: String,
      iv:   String,
      ct:   String
    },

    // CLAVE PERSONAL (opcional). Es el CÓDIGO DE RECUPERACIÓN cifrado con una
    // llave derivada de la clave que eligió el jugador. El servidor no conoce
    // esa clave, así que para él este campo es ruido: no puede sacar el código
    // ni, por tanto, la clave privada. Solo sirve para que el jugador use algo
    // corto y memorizable en vez del código largo.
    passphraseEnc: {
      salt: String,
      iv:   String,
      ct:   String
    },

    keyFingerprint: { type: String, default: '' },
    rotations:      { type: Number, default: 0 },
    lastUnlockAt:   { type: Date, default: null },
    createdAt:      { type: Date, default: Date.now }
  }, { collection: 'social_wallets', timestamps: true });

  const SocialWallet = mongoose.models.SocialWallet ||
                       mongoose.model('SocialWallet', socialWalletSchema);

  // ==========================================================================
  // CRIPTO DEL SERVIDOR
  // ==========================================================================

  function hashSub(provider, sub) {
    return crypto.createHmac('sha256', SUB_PEPPER)
      .update(String(provider) + ':' + String(sub))
      .digest('hex');
  }

  function cifrarEnReposo(bufferPlano, aad) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, iv);
    if (aad) c.setAAD(Buffer.from(aad, 'utf8'));
    const ct = Buffer.concat([c.update(bufferPlano), c.final()]);
    return { iv: iv.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
  }

  function descifrarEnReposo(blob, aad) {
    const d = crypto.createDecipheriv('aes-256-gcm', VAULT_KEY, Buffer.from(blob.iv, 'base64'));
    if (aad) d.setAAD(Buffer.from(aad, 'utf8'));
    d.setAuthTag(Buffer.from(blob.tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(blob.ct, 'base64')), d.final()]);
  }

  function firmarTicket(payload, ttlSec) {
    return jwt.sign(payload, SECRET, { expiresIn: ttlSec, issuer: 'gf-wallet' });
  }

  function verificarTicket(token, tipoEsperado) {
    try {
      const p = jwt.verify(token, SECRET, { issuer: 'gf-wallet' });
      if (p.t !== tipoEsperado) return null;
      return p;
    } catch (e) { return null; }
  }

  // ==========================================================================
  // VERIFICACIÓN DE LOS PROVEEDORES
  // --------------------------------------------------------------------------
  // Regla de oro: el CLIENTE nunca decide quién es. Aquí se comprueba la firma
  // del token contra las claves públicas del proveedor, y además el `aud` (que
  // el token se emitió PARA nuestra app) y el `nonce` (que es la respuesta a
  // ESTE intento y no una capturada antes).
  // ==========================================================================

  const _jwksCache = new Map();   // url → { at, keys }
  const JWKS_TTL_MS = 60 * 60 * 1000;

  async function traerJwks(url) {
    const cached = _jwksCache.get(url);
    if (cached && (Date.now() - cached.at) < JWKS_TTL_MS) return cached.keys;
    const r = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error('No se pudieron leer las claves públicas de ' + url);
    const j = await r.json();
    _jwksCache.set(url, { at: Date.now(), keys: j.keys || [] });
    return j.keys || [];
  }

  /** Verifica un id_token OIDC (RS256) contra el JWKS del emisor. */
  async function verificarIdToken(idToken, { jwksUrl, issuers, audience, nonce }) {
    const partes = String(idToken || '').split('.');
    if (partes.length !== 3) throw new Error('id_token con formato inválido');

    let cabecera;
    try { cabecera = JSON.parse(Buffer.from(partes[0], 'base64url').toString('utf8')); }
    catch (e) { throw new Error('No se pudo leer la cabecera del id_token'); }
    if (cabecera.alg !== 'RS256') throw new Error('Algoritmo no permitido: ' + cabecera.alg);

    const keys = await traerJwks(jwksUrl);
    const jwk = keys.find(k => k.kid === cabecera.kid);
    if (!jwk) throw new Error('El id_token viene firmado con una clave desconocida');

    const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });

    const payload = jwt.verify(idToken, publicKey, {
      algorithms: ['RS256'],
      audience: audience,
      issuer: issuers
    });

    if (nonce && payload.nonce !== nonce) throw new Error('El nonce no coincide (posible reenvío)');
    if (!payload.sub) throw new Error('El id_token no trae identificador de usuario');
    return payload;
  }

  async function verificarGoogle(idToken, nonce) {
    const p = await verificarIdToken(idToken, {
      jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs',
      issuers: ['https://accounts.google.com', 'accounts.google.com'],
      audience: CFG.google.clientId,
      nonce
    });
    return { sub: p.sub, emailVerified: !!p.email_verified };
  }

  async function verificarApple(idToken, nonce) {
    const p = await verificarIdToken(idToken, {
      jwksUrl: 'https://appleid.apple.com/auth/keys',
      issuers: ['https://appleid.apple.com'],
      audience: CFG.apple.clientId,
      nonce
    });
    return { sub: p.sub, emailVerified: p.email_verified === true || p.email_verified === 'true' };
  }

  /**
   * Facebook no emite id_token OIDC en el flujo web, así que se valida el
   * access_token con debug_token, que además dice PARA QUÉ app se emitió. Sin
   * esa comprobación, cualquiera podría traer un token de otra aplicación
   * suya y entrar como el usuario que quisiera.
   */
  async function verificarFacebook(accessToken) {
    const appToken = `${CFG.facebook.appId}|${CFG.facebook.appSecret}`;
    const dbgUrl = 'https://graph.facebook.com/debug_token?input_token=' +
      encodeURIComponent(accessToken) + '&access_token=' + encodeURIComponent(appToken);

    const r = await fetch(dbgUrl, { headers: { Accept: 'application/json' } });
    const j = await r.json();
    const d = j && j.data;
    if (!d || !d.is_valid) throw new Error('El token de Facebook no es válido');
    if (String(d.app_id) !== String(CFG.facebook.appId)) {
      throw new Error('El token de Facebook pertenece a otra aplicación');
    }
    if (!d.user_id) throw new Error('El token de Facebook no identifica a ningún usuario');
    return { sub: d.user_id, emailVerified: false };
  }

  // ==========================================================================
  // RUTAS
  // ==========================================================================

  function siActivo(req, res, next) {
    if (!ACTIVO) {
      return res.status(503).json({
        error: 'wallet_not_configured',
        message: 'El inicio de sesión social no está configurado en este servidor.'
      });
    }
    next();
  }

  // ── Configuración pública (client ids). No expone ningún secreto. ────────
  app.get('/api/wallet/config', apiLimiter, (req, res) => {
    res.json({
      enabled: ACTIVO,
      providers: {
        google:   { enabled: ACTIVO && CONFIGURADO.google,   clientId: CFG.google.clientId },
        facebook: { enabled: ACTIVO && CONFIGURADO.facebook, appId: CFG.facebook.appId },
        apple:    { enabled: ACTIVO && CONFIGURADO.apple,    clientId: CFG.apple.clientId,
                    redirectUri: CFG.apple.redirectUri }
      }
    });
  });

  // ── 1. Empezar: el servidor emite state + nonce ─────────────────────────
  app.post('/api/wallet/oauth/start', strictLimiter, siActivo, csrfProtection, (req, res) => {
    const provider = String((req.body && req.body.provider) || '');
    if (!CONFIGURADO[provider]) return res.status(400).json({ error: 'provider_disabled' });

    const nonce = crypto.randomBytes(16).toString('hex');
    // El `state` ES un JWT firmado: lleva dentro el nonce y el proveedor, así
    // que no hace falta guardar nada en memoria ni en base de datos, y aun así
    // no se puede falsificar ni reutilizar pasados 10 minutos.
    const state = firmarTicket({ t: 'oauth-state', p: provider, n: nonce }, STATE_TTL_SEC);

    res.json({ state, nonce, provider });
  });

  // ── 2. Verificar la respuesta del proveedor ─────────────────────────────
  app.post('/api/wallet/oauth/verify', strictLimiter, siActivo, csrfProtection, async (req, res) => {
    try {
      const { provider, state, idToken, accessToken } = req.body || {};

      const st = verificarTicket(state, 'oauth-state');
      if (!st) return res.status(400).json({ error: 'invalid_state', message: 'La sesión de inicio caducó. Inténtalo otra vez.' });
      if (st.p !== provider) return res.status(400).json({ error: 'provider_mismatch' });
      if (!CONFIGURADO[provider]) return res.status(400).json({ error: 'provider_disabled' });

      let identidad;
      if (provider === 'google')        identidad = await verificarGoogle(idToken, st.n);
      else if (provider === 'apple')    identidad = await verificarApple(idToken, st.n);
      else if (provider === 'facebook') identidad = await verificarFacebook(accessToken);
      else return res.status(400).json({ error: 'bad_provider' });

      const subHash = hashSub(provider, identidad.sub);
      const existente = await SocialWallet.findOne({ subHash }).lean();

      // Permiso corto para operar con la bóveda de ESTA identidad.
      const ticket = firmarTicket({ t: 'vault', s: subHash, p: provider }, TICKET_TTL_SEC);

      console.log(`🔑 [gf-wallet] ${provider} verificado (${subHash.slice(0, 12)}…) — ` +
                  (existente ? 'cuenta existente' : 'cuenta nueva'));

      res.json({
        ticket,
        walletId: subHash,
        exists: !!existente,
        address: existente ? existente.address : null,
        expiresIn: TICKET_TTL_SEC
      });
    } catch (e) {
      console.error('❌ [gf-wallet] verify:', e.message);
      res.status(401).json({ error: 'oauth_verification_failed', message: e.message });
    }
  });

  // ── 2-bis. Retorno de Apple (form_post) ─────────────────────────────────
  // Apple obliga a devolver la respuesta con un POST de formulario, así que
  // llega aquí y esta página se la pasa al popup padre con postMessage.
  app.post('/api/wallet/oauth/apple/callback', (req, res) => {
    const { id_token, code, state, error } = req.body || {};
    const datos = JSON.stringify({
      __gfWallet: 'oauth-result',
      state: state || '',
      idToken: id_token || null,
      code: code || null,
      error: error || null
    });

    // El origen al que se manda el mensaje se toma de la configuración, NUNCA
    // de la petición: si se usara '*', cualquier página incrustada podría leer
    // el id_token.
    const destino = process.env.GF_WALLET_APP_ORIGIN || '';
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'");
    res.send(`<!doctype html><meta charset="utf-8"><title>…</title><body>
<script>
  (function () {
    var datos = ${datos};
    var destino = ${JSON.stringify(destino)};
    try { if (window.opener) window.opener.postMessage(datos, destino || window.location.origin); } catch (e) {}
    window.close();
  })();
</script>
Puedes cerrar esta ventana.</body>`);
  });

  // Tope de dispositivos vinculados por cuenta. Al pasarse se echa el que lleve
  // más tiempo sin usarse: así una cuenta no engorda sin límite y el jugador
  // que va cambiando de móvil no se queda bloqueado.
  const MAX_DISPOSITIVOS = 10;

  const idDispositivoValido = (v) => /^[0-9a-f]{32}$/.test(String(v || ''));

  // ── 3. Crear la bóveda (primera vez) ────────────────────────────────────
  app.post('/api/wallet/vault', strictLimiter, siActivo, csrfProtection, async (req, res) => {
    try {
      const { ticket, address, deviceId, serverShare, recovery, keyFingerprint } = req.body || {};
      const t = verificarTicket(ticket, 'vault');
      if (!t) return res.status(401).json({ error: 'invalid_ticket' });

      if (!/^0x[0-9a-fA-F]{40}$/.test(String(address || ''))) {
        return res.status(400).json({ error: 'invalid_address' });
      }
      if (!idDispositivoValido(deviceId)) return res.status(400).json({ error: 'invalid_device_id' });

      const shareBuf = Buffer.from(String(serverShare || ''), 'base64');
      if (shareBuf.length !== 32) return res.status(400).json({ error: 'invalid_share' });

      const yaExiste = await SocialWallet.findOne({ subHash: t.s }).lean();
      if (yaExiste) return res.status(409).json({ error: 'vault_already_exists', address: yaExiste.address });

      await SocialWallet.create({
        subHash: t.s,
        provider: t.p,
        address: String(address).toLowerCase(),
        deviceShares: [{
          deviceId: String(deviceId),
          enc: cifrarEnReposo(shareBuf, 'gf-wallet:' + t.s + ':' + deviceId),
          createdAt: new Date(),
          lastUsedAt: new Date()
        }],
        recoveryEnc: recovery && recovery.ct
          ? { salt: String(recovery.salt), iv: String(recovery.iv), ct: String(recovery.ct) }
          : undefined,
        keyFingerprint: String(keyFingerprint || ''),
        lastUnlockAt: new Date()
      });

      console.log('🆕 [gf-wallet] bóveda creada para ' + String(address).slice(0, 10) + '… (' + t.p + ')');
      res.json({ ok: true, address: String(address).toLowerCase() });
    } catch (e) {
      console.error('❌ [gf-wallet] crear bóveda:', e.message);
      res.status(500).json({ error: 'vault_create_failed' });
    }
  });

  // ── 4. Leer la mitad de ESTE dispositivo ────────────────────────────────
  // Ya no existe "la" mitad del servidor: hay una por dispositivo. Si el que
  // pregunta no está vinculado se responde `deviceLinked:false` y el cliente
  // pide el código de recuperación, en vez de devolver la mitad de OTRO
  // dispositivo — que era exactamente lo que rompía la reconstrucción de la
  // clave ("La clave reconstruida no coincide con la cuenta registrada").
  app.get('/api/wallet/vault', apiLimiter, siActivo, async (req, res) => {
    try {
      const t = verificarTicket(req.query.ticket, 'vault');
      if (!t) return res.status(401).json({ error: 'invalid_ticket' });

      const doc = await SocialWallet.findOne({ subHash: t.s });
      if (!doc) return res.status(404).json({ error: 'vault_not_found' });

      const deviceId = String(req.query.deviceId || '');
      const salida = { address: doc.address, deviceLinked: false };

      let entrada = null;
      if (idDispositivoValido(deviceId)) {
        entrada = (doc.deviceShares || []).find(d => d.deviceId === deviceId) || null;
      }

      if (entrada) {
        salida.serverShare = descifrarEnReposo(entrada.enc, 'gf-wallet:' + t.s + ':' + deviceId).toString('base64');
        salida.deviceLinked = true;
        entrada.lastUsedAt = new Date();
        doc.markModified('deviceShares');
      } else if (!deviceId && doc.serverShareEnc && doc.serverShareEnc.ct) {
        // MIGRACIÓN de las cuentas creadas antes del arreglo: todavía tienen la
        // mitad única y su navegador no conoce ningún deviceId. Se le entrega
        // esa mitad UNA vez; el cliente reconstruye la clave y acto seguido
        // llama a /link con un deviceId nuevo, que ya queda en deviceShares.
        salida.serverShare = descifrarEnReposo(doc.serverShareEnc, 'gf-wallet:' + t.s).toString('base64');
        salida.deviceLinked = true;
        salida.legacy = true;
      }

      // La copia de recuperación solo se manda si se pide explícitamente
      // (dispositivo nuevo). Sin el código del jugador es ruido, pero cuanto
      // menos viaje, mejor.
      if (String(req.query.recovery) === '1' && doc.recoveryEnc && doc.recoveryEnc.ct) {
        salida.recovery = { salt: doc.recoveryEnc.salt, iv: doc.recoveryEnc.iv, ct: doc.recoveryEnc.ct };
      }

      doc.lastUnlockAt = new Date();
      await doc.save();

      res.json(salida);
    } catch (e) {
      console.error('❌ [gf-wallet] leer bóveda:', e.message);
      res.status(500).json({ error: 'vault_read_failed' });
    }
  });

  // ── 5. Vincular ESTE dispositivo ────────────────────────────────────────
  // Añade (o reemplaza) la mitad de UN dispositivo sin tocar la de los demás.
  // Antes esto era /rotate y machacaba la única mitad que había: por eso
  // vincular el móvil dejaba el PC fuera de su propia cuenta.
  const vincularDispositivo = async (req, res) => {
    try {
      const { ticket, deviceId, serverShare } = req.body || {};
      const t = verificarTicket(ticket, 'vault');
      if (!t) return res.status(401).json({ error: 'invalid_ticket' });
      if (!idDispositivoValido(deviceId)) return res.status(400).json({ error: 'invalid_device_id' });

      const shareBuf = Buffer.from(String(serverShare || ''), 'base64');
      if (shareBuf.length !== 32) return res.status(400).json({ error: 'invalid_share' });

      const doc = await SocialWallet.findOne({ subHash: t.s });
      if (!doc) return res.status(404).json({ error: 'vault_not_found' });

      const enc = cifrarEnReposo(shareBuf, 'gf-wallet:' + t.s + ':' + deviceId);
      if (!Array.isArray(doc.deviceShares)) doc.deviceShares = [];

      const existente = doc.deviceShares.find(d => d.deviceId === String(deviceId));
      if (existente) {
        existente.enc = enc;
        existente.lastUsedAt = new Date();
      } else {
        doc.deviceShares.push({
          deviceId: String(deviceId), enc, createdAt: new Date(), lastUsedAt: new Date()
        });
      }

      // Si se pasa del tope, fuera el que lleve más tiempo sin usarse.
      if (doc.deviceShares.length > MAX_DISPOSITIVOS) {
        doc.deviceShares.sort((a, b) => new Date(a.lastUsedAt) - new Date(b.lastUsedAt));
        doc.deviceShares.splice(0, doc.deviceShares.length - MAX_DISPOSITIVOS);
      }

      // Migrada la cuenta vieja, la mitad única ya no pinta nada.
      if (doc.serverShareEnc && doc.serverShareEnc.ct) {
        doc.serverShareEnc = undefined;
        doc.markModified('serverShareEnc');
      }

      doc.rotations    = (doc.rotations || 0) + 1;
      doc.lastUnlockAt = new Date();
      doc.markModified('deviceShares');
      await doc.save();

      console.log('🔗 [gf-wallet] dispositivo vinculado a ' + doc.address.slice(0, 10) +
                  '… (' + doc.deviceShares.length + ' dispositivo(s))');
      res.json({ ok: true, devices: doc.deviceShares.length });
    } catch (e) {
      console.error('❌ [gf-wallet] vincular dispositivo:', e.message);
      res.status(500).json({ error: 'vault_link_failed' });
    }
  };

  app.post('/api/wallet/vault/link', strictLimiter, siActivo, csrfProtection, vincularDispositivo);
  // Alias del nombre viejo, por si algún navegador tiene cacheado el SDK anterior.
  app.post('/api/wallet/vault/rotate', strictLimiter, siActivo, csrfProtection, vincularDispositivo);

  // ── 5-bis. Clave personal (código ⇄ clave) ──────────────────────────────
  // El jugador cambia el código largo por una clave suya. Aquí solo se guarda
  // el SOBRE (el código cifrado con esa clave); el servidor nunca ve ninguna
  // de las dos cosas en claro y no puede abrirlo.
  app.get('/api/wallet/passphrase', apiLimiter, siActivo, async (req, res) => {
    try {
      const t = verificarTicket(req.query.ticket, 'vault');
      if (!t) return res.status(401).json({ error: 'invalid_ticket' });

      const doc = await SocialWallet.findOne({ subHash: t.s }).lean();
      if (!doc) return res.status(404).json({ error: 'vault_not_found' });

      const tiene = !!(doc.passphraseEnc && doc.passphraseEnc.ct);
      if (String(req.query.reveal) === '1' && tiene) {
        return res.json({
          exists: true,
          salt: doc.passphraseEnc.salt,
          iv:   doc.passphraseEnc.iv,
          ct:   doc.passphraseEnc.ct
        });
      }
      return res.json({ exists: tiene });
    } catch (e) {
      console.error('❌ [gf-wallet] leer clave personal:', e.message);
      res.status(500).json({ error: 'passphrase_read_failed' });
    }
  });

  app.post('/api/wallet/passphrase', strictLimiter, siActivo, csrfProtection, async (req, res) => {
    try {
      const { ticket, salt, iv, ct } = req.body || {};
      const t = verificarTicket(ticket, 'vault');
      if (!t) return res.status(401).json({ error: 'invalid_ticket' });
      if (!salt || !iv || !ct) return res.status(400).json({ error: 'invalid_envelope' });

      const doc = await SocialWallet.findOne({ subHash: t.s });
      if (!doc) return res.status(404).json({ error: 'vault_not_found' });

      doc.passphraseEnc = { salt: String(salt), iv: String(iv), ct: String(ct) };
      doc.markModified('passphraseEnc');
      await doc.save();

      console.log(`🔐 [gf-wallet] clave personal configurada para ${doc.address.slice(0, 10)}…`);
      res.json({ ok: true });
    } catch (e) {
      console.error('❌ [gf-wallet] guardar clave personal:', e.message);
      res.status(500).json({ error: 'passphrase_save_failed' });
    }
  });

  app.delete('/api/wallet/passphrase', strictLimiter, siActivo, csrfProtection, async (req, res) => {
    try {
      const t = verificarTicket((req.body && req.body.ticket) || req.query.ticket, 'vault');
      if (!t) return res.status(401).json({ error: 'invalid_ticket' });

      const doc = await SocialWallet.findOne({ subHash: t.s });
      if (!doc) return res.status(404).json({ error: 'vault_not_found' });

      doc.passphraseEnc = undefined;
      doc.markModified('passphraseEnc');
      await doc.save();
      res.json({ ok: true });
    } catch (e) {
      console.error('❌ [gf-wallet] borrar clave personal:', e.message);
      res.status(500).json({ error: 'passphrase_delete_failed' });
    }
  });

  // ── 5-ter. ¿Quién soy? — para OTRO ORIGEN (el juego)  (2026-08-05) ──────
  // El login vive en app.grasslandforest.com y el juego en
  // game.grasslandforest.com. IndexedDB es POR ORIGEN, así que la mitad del
  // dispositivo guardada al iniciar sesión NO existe en el juego y allí la
  // wallet nunca podía abrirse: el panel enseñaba el mensaje de MetaMask a
  // gente que había entrado con Google.
  //
  // Esto lo arregla: con la cookie de sesión (que sí es compartida por
  // COOKIE_DOMAIN=.grasslandforest.com), el juego pregunta "¿esta cuenta tiene
  // wallet embebida?" y recibe su identificador y su dirección. Con eso puede
  // pedir un ticket y usar todo lo que NO necesita la clave (saldo, actividad,
  // recibir). Para enviar o ver la clave privada se pide el código/clave, que
  // reconstruye la clave sin depender del dispositivo.
  app.get('/api/wallet/whoami', apiLimiter, siActivo, authMiddleware, async (req, res) => {
    try {
      const address = String((req.user && req.user.address) || '').toLowerCase();
      if (!address) return res.json({ embedded: false });

      const doc = await SocialWallet.findOne({ address }).lean();
      if (!doc) return res.json({ embedded: false });

      res.json({
        embedded: true,
        address: doc.address,
        walletId: doc.subHash,
        provider: doc.provider,
        hasPassphrase: !!(doc.passphraseEnc && doc.passphraseEnc.ct),
        devices: Array.isArray(doc.deviceShares) ? doc.deviceShares.length : 0
      });
    } catch (e) {
      console.error('❌ [gf-wallet] whoami:', e.message);
      res.status(500).json({ embedded: false, error: 'whoami_failed' });
    }
  });

  // ── 6. Ticket nuevo con la sesión del juego ya iniciada ─────────────────
  // Sirve para reabrir la wallet al recargar la página sin repetir el OAuth:
  // la cookie de sesión del juego demuestra que ya se verificó la identidad, y
  // el walletId pedido tiene que corresponder A ESA dirección.
  app.post('/api/wallet/ticket', apiLimiter, siActivo, authMiddleware, csrfProtection, async (req, res) => {
    try {
      const walletId = String((req.body && req.body.walletId) || '');
      if (!/^[0-9a-f]{64}$/.test(walletId)) return res.status(400).json({ error: 'invalid_wallet_id' });

      const doc = await SocialWallet.findOne({ subHash: walletId }).lean();
      if (!doc) return res.status(404).json({ error: 'vault_not_found' });

      // La sesión del juego se lee del middleware de server2.js si está montado;
      // si no hay sesión, no se entrega ticket.
      const sesion = req.user || null;
      if (!sesion || !sesion.address) {
        return res.status(401).json({ error: 'no_session', message: 'Inicia sesión otra vez con tu proveedor.' });
      }
      if (String(sesion.address).toLowerCase() !== String(doc.address).toLowerCase()) {
        return res.status(403).json({ error: 'session_mismatch' });
      }

      res.json({ ticket: firmarTicket({ t: 'vault', s: walletId, p: doc.provider }, TICKET_TTL_SEC) });
    } catch (e) {
      console.error('❌ [gf-wallet] ticket:', e.message);
      res.status(500).json({ error: 'ticket_failed' });
    }
  });

  console.log(`✅ [gf-wallet] rutas montadas — activo: ${ACTIVO}, proveedores: ` +
              Object.keys(CONFIGURADO).filter(k => CONFIGURADO[k]).join(', ') || '(ninguno)');

  return { SocialWallet, ACTIVO, CONFIGURADO };
};
