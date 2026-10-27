// =============================================================================
// MARKETPLACE ROUTES — mercado P2P de Grassland Forest
// =============================================================================
// Se monta desde server2.js así:
//
//   require('./marketplace-routes')(app, {
//     mongoose, authMiddleware, csrfProtection, apiLimiter, strictLimiter,
//     GamePlayer, PlayerStats, Listing
//   });
//
// Notas de diseño (léelas antes de tocar el dinero):
//
// 1) Este mercado es OFF-CHAIN: mueve cantidades en Mongo (GamePlayer.inventory
//    y PlayerStats.oro/plata), igual que el resto de sistemas "simples" del
//    juego (correo, misiones, furnace, badges...). NO llama al smart contract.
//
// 2) oro/plata en PlayerStats están pensados como espejo de facturas on-chain
//    (ver POST /api/stats/:playerName/sync, que compara contra
//    contract.getUserInventorySnapshot). Si tu cliente dispara ese sync después
//    de una compra/venta, en algunos casos el sync puede "restaurar" el valor
//    on-chain y pisar el cambio que hizo el mercado (ver comentario largo al
//    final de este archivo). Para que el mercado sea 100% resistente a esto,
//    habría que liquidar la compra llamando al contrato (increaseInvoiceQuantity
//    / su equivalente para restar) en vez de tocar sólo Mongo — no tengo el
//    ABI de ITEMS_CONTRACT en este entorno así que no puedo escribir esa parte
//    con seguridad. Es la mejora natural de la v2.
//
// 3) Los ítems que entrega el mercado (compra) se insertan con
//    IDX = <slot> y Manualid = <itemId> (sintéticos, no nulos), que es
//    exactamente el mismo fallback que ya usa tu cliente en loadPlayerData()
//    (`s.IDX ?? s.id`, `s.Manualid ?? s.objeto`). Así el filtro `validarItems`
//    de POST /api/save/:playerName los conserva sin tocar ese endpoint.
// =============================================================================

// (2026-10-22) "Si alguien vende o compra en la tienda P2P, la comisión del
// 1,5 % se va al tesoro." Era el 5 % y desaparecía; ahora es el 1,5 % y entra
// en el tesoro de server2.js ("EL TESORO Y SUS INCENTIVOS") en la MISMA
// transacción que la venta (ver ingresarAlTesoro).
// (2026-10-26) "La comisión es un 5 % en los dos mercados: el 1,5 % es de la
// economía circular y el 3,5 % del tesoro del juego."
const MARKET_FEE_BPS = 500; // 5% de comisión → 1,5 % tesoro circular + 3,5 % tesoro del juego

// ── Catálogo de ítems (nombre para mostrar, categoría, ícono, stack máximo) ─
// Debe mantenerse en sincronía con `this.ItemDefinitions` en GameScene.js.
// Los paths de ícono son relativos a la raíz del juego (ver ASSET BASE en
// market.html) — por eso empiezan con "/Game/...".
const ITEM_CATALOG = {
  Semillax:  { name: 'Semillas de Zanahoria', category: 'semillas', icon: '/Game/Objetos/Plantas/planta_zanahorias/item_saco.png', maxStack: 50 },
  Semillax1: { name: 'Semillas de Tomate',    category: 'semillas', icon: '/Game/Objetos/Plantas/planta_tomates/semillas_tomate.png', maxStack: 50 },
  Semillax4: { name: 'Strawberry Seed',      category: 'semillas', icon: '/Game/Objetos/Plantas/planta_fresa/item_semilla_fresa.png', maxStack: 50 },
  Semillax2: { name: 'Semillas de Trigo',     category: 'semillas', icon: '/Game/Objetos/Plantas/planta_trigo/item_semilla_trigo.png', maxStack: 50 },
  Semillax3: { name: 'Semillas de Calabaza',  category: 'semillas', icon: '/Game/Objetos/Plantas/planta_calabaza/item_semilla_calabaza.png', maxStack: 50 },

  Regaderax: { name: 'Regadera', category: 'herramientas', icon: '/Game/Source/recurso2.png', maxStack: 1 },
  Tijerasx:  { name: 'Tijeras',  category: 'herramientas', icon: '/Game/Source/tijeras.png', maxStack: 1 },

  hacha_de_madera: { name: 'Hacha de Madera', category: 'herramientas', icon: '/Game/Source/pico_y_hacha/hacha_de_madera.png', maxStack: 5 },
  hacha_de_piedra: { name: 'Hacha de Piedra', category: 'herramientas', icon: '/Game/Source/pico_y_hacha/hacha_de_piedra.png', maxStack: 5 },
  hacha_de_cobre:  { name: 'Hacha de Cobre',  category: 'herramientas', icon: '/Game/Source/pico_y_hacha/hacha_de_cobre.png', maxStack: 5 },
  hacha_de_hierro: { name: 'Hacha de Hierro', category: 'herramientas', icon: '/Game/Source/pico_y_hacha/hacha_de_hierro.png', maxStack: 5 },

  pico_de_madera: { name: 'Pico de Madera', category: 'herramientas', icon: '/Game/Source/pico_y_hacha/pico_de_madera.png', maxStack: 5 },
  pico_de_piedra: { name: 'Pico de Piedra', category: 'herramientas', icon: '/Game/Source/pico_y_hacha/pico_de_piedra.png', maxStack: 5 },
  pico_de_cobre:  { name: 'Pico de Cobre',  category: 'herramientas', icon: '/Game/Source/pico_y_hacha/pico_de_cobre.png', maxStack: 5 },
  pico_de_hierro: { name: 'Pico de Hierro', category: 'herramientas', icon: '/Game/Source/pico_y_hacha/pico_de_hierro.png', maxStack: 5 },

  balde_vacio:    { name: 'Balde Vacío',    category: 'herramientas', icon: '/Game/Source/item_pozo1.png', maxStack: 5 },
  balde_con_agua: { name: 'Balde con Agua', category: 'herramientas', icon: '/Game/Source/item_pozo2.png', maxStack: 5 },

  mineral_piedra: { name: 'Piedra', category: 'minerales', icon: '/Game/Source/piedra.png', maxStack: 20 },
  mineral_cobre:  { name: 'Lingote de Cobre',  category: 'minerales', icon: '/Game/Source/cobre.png', maxStack: 20 },
  mineral_hierro: { name: 'Lingote de Hierro', category: 'minerales', icon: '/Game/Source/hierro.png', maxStack: 20 },

  // Piedra en bruto y carbón: lo que sale de la mina desde que hay horno.
  // Sin estas entradas no se podrían publicar en el mercado (el catálogo de
  // aquí es el que decide qué se puede listar).
  mineral_piedra_cobre:  { name: 'Piedra de Cobre',  category: 'minerales', icon: '/Game/Source/piedra_cobre.png',  maxStack: 20 },
  mineral_piedra_hierro: { name: 'Piedra de Hierro', category: 'minerales', icon: '/Game/Source/piedra_hierro.png', maxStack: 20 },
  mineral_carbon:        { name: 'Piedra de Carbón', category: 'minerales', icon: '/Game/Source/piedra_carbon.png', maxStack: 20 },
  carbon:                { name: 'Carbón',           category: 'minerales', icon: '/Game/Objetos/carbon.png',       maxStack: 20 },

  palo:             { name: 'Palo',             category: 'madera', icon: '/Game/Source/palo.png', maxStack: 20 },
  tablon_de_madera: { name: 'Tablón de Madera', category: 'madera', icon: '/Game/Source/madera.png', maxStack: 20 },
  madera_pinos:     { name: 'Madera de Pino',   category: 'madera', icon: '/Game/Source/madera_oscura.png', maxStack: 50 },
  madera_con_hojas: { name: 'Madera con Hojas', category: 'madera', icon: '/Game/Source/madera de hoja.png', maxStack: 50 },
  madera_seca:      { name: 'Madera Seca',      category: 'madera', icon: '/Game/Source/madera seca.png', maxStack: 50 },

  zanahoria_buena: { name: 'Zanahoria Buena',    category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_zanahorias/item_zanahoria_buena.png', maxStack: 20 },
  zanahoria_corta: { name: 'Zanahoria (brote)',  category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_zanahorias/planta_crecimiento_zanahoria.png', maxStack: 20 },
  zanahoria_mala:  { name: 'Zanahoria Podrida',  category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_zanahorias/item_zanahoria_podrida.png', maxStack: 20 },

  tomate_buena: { name: 'Tomate Bueno',   category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_tomates/item_tomate_bueno.png', maxStack: 20 },
  tomate_corta: { name: 'Tomate (brote)', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_tomates/item_planta.png', maxStack: 20 },
  tomate_mala:  { name: 'Tomate Podrido', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_tomates/item_tomate_malo.png', maxStack: 20 },
  fresa_buena:  { name: 'Good Strawberry',   category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_fresa/item_fresa_buena.png', maxStack: 20 },
  fresa_corta:  { name: 'Unripe Strawberry', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_fresa/item_planta.png', maxStack: 20 },
  fresa_mala:   { name: 'Rotten Strawberry', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_fresa/item_fresa_podrida.png', maxStack: 20 },

  trigo_buena: { name: 'Trigo Bueno',   category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_trigo/item_trigo_bueno.png', maxStack: 20 },
  trigo_corta: { name: 'Trigo (brote)', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_trigo/item_planta_trigo.png', maxStack: 20 },
  trigo_mala:  { name: 'Trigo Podrido', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_trigo/item_trigo_podrido.png', maxStack: 20 },

  calabaza_buena: { name: 'Calabaza Buena',   category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_calabaza/item_calabaza_buena.png', maxStack: 20 },
  calabaza_corta: { name: 'Calabaza (brote)', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_calabaza/item_planta_calabaza.png', maxStack: 20 },
  calabaza_mala:  { name: 'Calabaza Podrida', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_calabaza/item_calabaza_podrida.png', maxStack: 20 },

  // Construcción (2026-10-03): la parcela que se coloca en la isla.
  parcela: { name: 'Parcela', category: 'construccion', icon: '/Game/Objetos/construccion/parcela.png', maxStack: 20 },
  pala_construccion: { name: 'Pala de construcción', category: 'construccion', icon: '/Game/Objetos/construccion/pala_construccion.png', maxStack: 1 },
  // El bote de basura y los cofres de la isla (2026-10-05).
  basura: { name: 'Bote de basura',   category: 'construccion', icon: '/Game/Objetos/cofres/basura.png', maxStack: 10 },
  cofre1: { name: 'Cofre de madera',  category: 'construccion', icon: '/Game/Objetos/cofres/cofre1.png', maxStack: 5 },
  cofre2: { name: 'Cofre reforzado',  category: 'construccion', icon: '/Game/Objetos/cofres/cofre2.png', maxStack: 5 },
  cofre3: { name: 'Cofre mágico',     category: 'construccion', icon: '/Game/Objetos/cofres/cofre3.png', maxStack: 5 },
  cofre4: { name: 'Cofre legendario', category: 'construccion', icon: '/Game/Objetos/cofres/cofre4.png', maxStack: 5 },

  // Equipo (2026-10-05). Los peces NO están: no se compran en ningún sitio,
  // solo se pescan (y se comen o se venden en la tienda).
  espada_madera:  { name: 'Wooden Sword', category: 'herramientas', icon: '/Game/Objetos/armas/espada_madera.png',   maxStack: 1 },
  espada_cobre:   { name: 'Copper Sword', category: 'herramientas', icon: '/Game/Objetos/armas/espada_cobre.png',    maxStack: 1 },
  espada_hierro:  { name: 'Iron Sword',   category: 'herramientas', icon: '/Game/Objetos/armas/espada_hierro.png',   maxStack: 1 },
  cana_pescar:    { name: 'Fishing Rod',  category: 'herramientas', icon: '/Game/Objetos/pesca/cana_pescar.png',     maxStack: 1 },
  espantapajaros: { name: 'Scarecrow',    category: 'herramientas', icon: '/Game/Objetos/granja/espantapajaros.png', maxStack: 10 },
  antorcha:       { name: 'Torch',        category: 'herramientas', icon: '/Game/Objetos/antorcha/antorcha.png',     maxStack: 20 },
  // (2026-10-21) El bote y las dos armas a distancia.
  bote:           { name: 'Boat',         category: 'herramientas', icon: '/Game/Objetos/bote/bote.png',             maxStack: 1 },
  arco:           { name: 'Bow',          category: 'herramientas', icon: '/Game/Objetos/armas/arco.png',            maxStack: 1 },
  baston_mago:    { name: 'Wizard Staff', category: 'herramientas', icon: '/Game/Objetos/armas/baston_mago.png',     maxStack: 1 }
};

const CATEGORIES = [
  { id: 'semillas',     label: 'Semillas' },
  { id: 'herramientas', label: 'Herramientas' },
  { id: 'minerales',    label: 'Minerales' },
  { id: 'madera',       label: 'Madera' },
  { id: 'cultivos',     label: 'Cultivos' },
  { id: 'construccion', label: 'Construcción' },
  { id: 'otros',        label: 'Otros' }
];

function catalogMeta(itemId) {
  return Object.prototype.hasOwnProperty.call(ITEM_CATALOG, itemId) ? ITEM_CATALOG[itemId]
    : { name: itemId, category: 'otros', icon: '', maxStack: 20 };
}

function round2(n) {
  return Math.round((Number(n) + Number.EPSILON) * 100) / 100;
}

function validMarketAmount(n) {
  return Number.isFinite(n) && n > 0 && Number.isSafeInteger(Math.round(n * 100));
}

function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Session propagation is local to this module: other game queries do not
// inherit a market transaction or any global Mongoose setting.
function createMarketAtomic(mongoose, auditar) {
  const { AsyncLocalStorage } = require('node:async_hooks');
  // (2026-10-27) Cada respuesta de error del mercado se cuenta a la auditoría de
  // server2.js (centro de control). Fuera de la transacción y sin poder romperla.
  const contar = (req, status, body) => {
    if (typeof auditar !== 'function' || !(status >= 400)) return;
    try { auditar(req, status, body); } catch (_) {}
  };
  const scope = new AsyncLocalStorage();
  const queryMethods = new Set(['find', 'findOne', 'findById', 'findOneAndUpdate',
    'findOneAndDelete', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'countDocuments']);
  async function transaction(work) {
    if (scope.getStore()) return work();
    const session = await mongoose.startSession();
    try {
      return await session.withTransaction(() => scope.run(session, work), {
        readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary'
      });
    } finally {
      // Cleanup cannot turn a committed payment into an apparent failure.
      try { await session.endSession(); } catch (error) { console.warn('⚠️ Marketplace session cleanup failed:', error.code || error.name); }
    }
  }
  function model(raw) {
    return new Proxy(raw, {
      get(target, key) {
        const value = Reflect.get(target, key, target);
        if (typeof value !== 'function') return value;
        return function (...args) {
          const session = scope.getStore();
          if (!session) return value.apply(target, args);
          if (key === 'create') {
            const multiple = Array.isArray(args[0]);
            return target.create(multiple ? args[0] : [args[0]], { ...args[1], session })
              .then(docs => multiple ? docs : docs[0]);
          }
          if (key === 'insertMany') return target.insertMany(args[0], { ...args[1], session });
          if (!queryMethods.has(key)) throw new Error('Unsupported transactional market operation: ' + String(key));
          return value.apply(target, args).session(session);
        };
      }
    });
  }
  function handler(work) {
    return async function (req, res, next) {
      let result;
      const aborted = new Error('marketplace_request_aborted');
      try {
        await transaction(async () => {
          // withTransaction may retry: never send an HTTP response from its
          // callback, and reconstruct its response on every attempt.
          result = { status: 200, body: undefined };
          const draft = { status(code) { result.status = code; return draft; },
            commitStatus(code) { result.status = code; result.commitOnError = true; return draft; },
            json(body) { result.body = body; return draft; } };
          await work(req, draft, next);
          if (result.status >= 400 && !result.commitOnError) throw aborted;
        });
      } catch (error) {
        if (error !== aborted) {
          console.error('❌ Marketplace transaction rolled back:', error.code || error.name || 'database_error');
          const cuerpo = { error: 'marketplace_transaction_unavailable',
            message: 'No se completó la operación. El mercado necesita una base de datos con transacciones disponibles.' };
          contar(req, 503, cuerpo);
          return res.status(503).json(cuerpo);
        }
      }
      contar(req, result.status, result.body);
      return res.status(result.status).json(result.body);
    };
  }
  return { transaction, model, handler };
}

module.exports = function registerMarketplaceRoutes(rawApp, ctx) {
  const atomic = createMarketAtomic(ctx.mongoose, ctx.auditarMercado);
  const app = { get: (...args) => rawApp.get(...args) };
  for (const method of ['post', 'patch', 'delete']) app[method] = (...args) => {
    const work = args.pop(); return rawApp[method](...args, atomic.handler(work));
  };
  const {
    mongoose,
    authMiddleware,
    csrfProtection,
    apiLimiter,
    strictLimiter,
    GamePlayer: RawGamePlayer,
    PlayerStats: RawPlayerStats,
    Listing: RawListing,
    // Comprobador de admin de server2.js (env ADMIN_ADDRESSES o isAdmin
    // on-chain). Si no llega, NADIE es admin: es preferible que el panel de
    // productos limitados no exista a que lo pueda usar cualquiera.
    isAdminAddress = async () => false,
    // (2026-10-22) El tesoro de server2.js. Sin él, la comisión se cobra igual
    // y no se apunta en ningún sitio (como antes).
    Tesoro: RawTesoro = null,
    TesoroMov: RawTesoroMov = null,
    TESORO_ID = 'principal',
    // (2026-10-26) El tesoro del juego y qué parte de la comisión es del circular.
    TesoroJuego: RawTesoroJuego = null,
    TESORO_JUEGO_ID = 'juego',
    TESORO_CIRCULAR_BPS = 150,
    // (2026-10-27) El nivel de cada objeto y el del jugador (server2.js): por
    // debajo no se compra ni se oferta. Sin ellos (servidor viejo), no se mira.
    nivelObjeto = null,
    nivelJugador = null,
    alertar = null
  } = ctx;
  const GamePlayer = atomic.model(RawGamePlayer), PlayerStats = atomic.model(RawPlayerStats), Listing = atomic.model(RawListing);
  const Tesoro = RawTesoro ? atomic.model(RawTesoro) : null;
  const TesoroMov = RawTesoroMov ? atomic.model(RawTesoroMov) : null;
  const TesoroJuego = RawTesoroJuego ? atomic.model(RawTesoroJuego) : null;

  /* La comisión de una venta al tesoro, EN BRONCE (1 plata = 1.000, 1 oro =
     1.000.000; el mercado cobra con dos decimales). Va dentro de la
     transacción del que llama: si la venta se deshace, esto también. */
  async function ingresarAlTesoro(currency, fee, sellerName, itemId, qty) {
    if (!Tesoro || !(fee > 0)) return;
    const bronce = Math.round(fee * (currency === 'plata' ? 1000 : 1000000));
    if (!(bronce > 0)) return;
    // (2026-10-26) Del 5 %, el 1,5 % al tesoro circular y lo demás (3,5 %) al del juego.
    // Sin tesoro del juego (servidor viejo), todo al circular, como antes.
    const circular = TesoroJuego ? Math.floor(bronce * TESORO_CIRCULAR_BPS / MARKET_FEE_BPS) : bronce;
    const juego = bronce - circular;
    const detalle = 'p2p ' + itemId + ' x' + qty;
    if (circular > 0) {
      await Tesoro.updateOne({ _id: TESORO_ID }, { $inc: { saldo: circular, 'ingresado.p2p': circular, 'ingresos.p2p': 1 } }, { upsert: true }).exec();
      if (TesoroMov) await TesoroMov.create({ t: new Date(), tipo: 'ingreso', origen: 'p2p', bronce: circular, playerName: sellerName || null, detalle });
    }
    if (juego > 0) {
      await TesoroJuego.updateOne({ _id: TESORO_JUEGO_ID }, { $inc: { saldo: juego, 'ingresado.p2p': juego, 'ingresos.p2p': 1 } }, { upsert: true }).exec();
      if (TesoroMov) await TesoroMov.create({ t: new Date(), tesoro: 'juego', tipo: 'ingreso', origen: 'p2p', bronce: juego, playerName: sellerName || null, detalle });
    }
  }

  const writeLimiter = strictLimiter || apiLimiter;

  /* "Si uno de nivel 12 compra algo de nivel 11 y se lo pasa a uno de nivel 2,
     ese no lo puede recoger" (2026-10-27): tampoco comprarlo aquí, o el mercado
     sería el atajo. null si puede; si no, el cuerpo del 403 (y el intento queda
     en el centro de control). */
  async function nivelInsuficiente(gp, itemId, tipo) {
    if (typeof nivelObjeto !== 'function' || typeof nivelJugador !== 'function' || !gp) return null;
    const requerido = Number(nivelObjeto(itemId)) || 0;
    if (requerido <= 1) return null;
    const nivel = Number(await nivelJugador(gp)) || 0;
    if (nivel >= requerido) return null;
    if (typeof alertar === 'function') { try { alertar(tipo, gp, { itemId, nivelRequerido: requerido, nivel }); } catch (_) {} }
    return { error: 'level_too_low', nivelRequerido: requerido, nivel,
             message: `You need level ${requerido} to get this item (you are level ${nivel}).` };
  }

  // ── Helpers internos ────────────────────────────────────────────────────

  async function getGamePlayerByAddress(address) {
    return GamePlayer.findOne({ address }).exec();
  }

  async function getOrCreateStats(playerName, address, gamePlayerFallback) {
    let stats = await PlayerStats.findOne({ playerName }).exec();
    if (!stats) {
      stats = await PlayerStats.create({
        playerName,
        address,
        oro: gamePlayerFallback ? (gamePlayerFallback.moneda ?? 0) : 0,
        plata: gamePlayerFallback ? (gamePlayerFallback.moneda_plata ?? 0) : 0
      });
    }
    return stats;
  }

  function currencyField(currency) {
    return currency === 'plata' ? 'plata' : 'oro';
  }

  // FIX "faltan objetos en el market": antes solo se serializaba gp.inventory
  // (los 40 espacios del bolso). Los objetos de la BARRA RÁPIDA (gp.chest, 7
  // espacios — regadera, hacha, tijeras, balde...) no aparecían. Ahora se
  // fusionan ambos, etiquetando cada uno con su `source` para que la venta
  // descuente del array correcto (ver POST /list).
  function serializeInventory(gp) {
    const rows = [];
    const pushFrom = (arr, source) => {
      (arr || []).forEach(e => {
        if (!e || !e.objeto || !(Number(e.cantidad) > 0)) return;
        const meta = catalogMeta(e.objeto);
        rows.push({
          slotId: e.id,
          source,                 // 'inventory' | 'chest'
          itemId: e.objeto,
          name: meta.name,
          category: meta.category,
          icon: meta.icon,
          maxStack: meta.maxStack,
          qty: Number(e.cantidad)
        });
      });
    };
    pushFrom(gp && gp.inventory, 'inventory');
    pushFrom(gp && gp.chest, 'chest');
    return rows;
  }

  // ── Historial de mercado (persistente, por jugador) ──────────────────────
  // Modelo propio. Cada compra genera DOS filas: una 'buy' para el comprador y
  // una 'sell' para el vendedor, cada una indexada por su playerName/address,
  // así el historial de un jugador NUNCA se mezcla con el de otro.
  const marketHistorySchema = new mongoose.Schema({
    playerName:       { type: String, required: true, index: true },
    address:          { type: String, index: true },
    // 'list'   = publiqué un ítem      (no mueve dinero)
    // 'cancel' = retiré mi publicación (no mueve dinero)
    // 'buy' / 'sell' = la compra de verdad
    //
    // Antes solo existían 'buy' y 'sell', así que publicar y cancelar no
    // dejaban ningún rastro. Si te habían comprado PARTE de una publicación y
    // luego cancelabas el resto, en el historial solo se veía la fila 'sell' y
    // parecía que se había vendido todo. Con estos dos eventos el historial
    // cuenta la historia completa y no hay forma de confundirse.
    type:             { type: String, enum: ['buy', 'sell', 'list', 'cancel'], required: true },
    itemId:           String,
    name:             String,
    category:         String,
    qty:              Number,
    pricePerUnit:     Number,
    total:            Number,   // bruto = qty * pricePerUnit
    fee:              Number,   // comisión aplicada (relevante en 'sell')
    sellerReceives:   Number,   // neto recibido por el vendedor (filas 'sell')
    currency:         String,
    counterparty:     String,   // address de la contraparte
    counterpartyName: String,   // playerName de la contraparte
    createdAt:        { type: Date, default: Date.now }
  }, { collection: 'market_history' });

  // Reutiliza el modelo si ya está registrado (evita OverwriteModelError si el
  // módulo se carga más de una vez).
  const MarketHistory = atomic.model(mongoose.models.MarketHistory
    || mongoose.model('MarketHistory', marketHistorySchema));

  function serializeHistory(h) {
    return {
      type: h.type,
      itemId: h.itemId,
      name: h.name,
      category: h.category,
      icon: catalogMeta(h.itemId).icon,
      qty: h.qty,
      pricePerUnit: h.pricePerUnit,
      total: h.total,
      fee: h.fee,
      sellerReceives: h.sellerReceives,
      currency: h.currency,
      counterpartyName: h.counterpartyName,
      createdAt: h.createdAt
    };
  }

  function serializeListing(doc, myAddress) {
    return {
      id: String(doc._id),
      owner: doc.owner,
      ownerName: doc.ownerName,
      mine: !!myAddress && doc.owner === myAddress,
      itemId: doc.itemId,
      name: doc.name,
      category: doc.category,
      icon: catalogMeta(doc.itemId).icon,
      qty: doc.qty,
      pricePerUnit: doc.pricePerUnit,
      currency: doc.currency,
      totalPrice: round2(doc.qty * doc.pricePerUnit),
      createdAt: doc.createdAt
    };
  }

  // Calcula cómo repartir `qty` unidades de `itemId` dentro del inventario del
  // jugador: primero rellena stacks existentes del mismo ítem, y usa slots
  // vacíos (0-39) para el resto. Devuelve null si no hay espacio suficiente.
  function computeInsertPlan(inventory, itemId, qty, maxStack) {
    if (!Array.isArray(inventory) || !Number.isSafeInteger(qty) || qty < 1 ||
        !Number.isSafeInteger(maxStack) || maxStack < 1) return null;
    const ops = [];
    let remaining = qty;
    const usedIds = new Set(inventory.filter(e => e && Number.isInteger(e.id)).map(e => e.id));

    for (const entry of inventory || []) {
      if (remaining <= 0) break;
      if (entry && Number.isInteger(entry.id) && entry.id >= 0 && entry.id < 40 &&
          entry.objeto === itemId && Number.isSafeInteger(Number(entry.cantidad)) &&
          Number(entry.cantidad) >= 0 && Number(entry.cantidad) < maxStack) {
        const space = maxStack - Number(entry.cantidad);
        const add = Math.min(space, remaining);
        if (add > 0) {
          ops.push({ type: 'inc', id: entry.id, amount: add });
          remaining -= add;
        }
      }
    }

    let candidate = 0;
    while (remaining > 0 && candidate < 40) {
      if (!usedIds.has(candidate)) {
        const add = Math.min(maxStack, remaining);
        ops.push({ type: 'new', id: candidate, amount: add });
        usedIds.add(candidate);
        remaining -= add;
      }
      candidate++;
    }

    if (remaining > 0) return null; // inventario lleno
    return ops;
  }

  async function applyInsertPlan(address, itemId, ops) {
    // Se marca que el MARKET ha tocado este inventario. /api/save lo consulta
    // para no sobrescribir la compra con la copia vieja que tiene la pestaña
    // del juego (ver el comentario de `marketWriteAt` en el esquema).
    // Va ANTES de insertar: si el guardado del juego llegara justo en medio,
    // es preferible que vea la marca de más y recargue, a que no la vea y
    // borre el ítem.
    const marked = await GamePlayer.updateOne({ address }, { $set: { marketWriteAt: new Date() } }).exec();
    if (marked.matchedCount !== 1) throw new Error('market_inventory_missing');

    for (const op of ops) {
      if (op.type === 'inc') {
        const updated = await GamePlayer.updateOne(
          { address, inventory: { $elemMatch: { id: op.id, objeto: itemId } } },
          { $inc: { 'inventory.$.cantidad': op.amount } }
        ).exec();
        if (updated.matchedCount !== 1) throw new Error('market_inventory_changed');
      } else {
        const updated = await GamePlayer.updateOne(
          { address, 'inventory.id': { $ne: op.id } },
          {
            $push: {
              inventory: {
                id: op.id,
                IDX: op.id,        // sintético, no-nulo (ver nota de cabecera)
                Manualid: itemId,  // sintético, no-nulo
                objeto: itemId,
                cantidad: op.amount,
                tipo: 'inventario'
              }
            }
          }
        ).exec();
        if (updated.matchedCount !== 1) throw new Error('market_inventory_changed');
      }
    }
  }

  // ── GET /api/marketplace/catalog ────────────────────────────────────────
  app.get('/api/marketplace/catalog', apiLimiter, authMiddleware, (req, res) => {
    res.json({ catalog: ITEM_CATALOG, categories: CATEGORIES, feeBps: MARKET_FEE_BPS });
  });

  // ── GET /api/marketplace/account ────────────────────────────────────────
  // Wallet, playerName, oro/plata e inventario vendible del usuario logeado.
  app.get('/api/marketplace/account', apiLimiter, authMiddleware, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const gp = await getGamePlayerByAddress(address);
      if (!gp) return res.status(404).json({ error: 'player_not_found' });

      const stats = await getOrCreateStats(gp.playerName, address, gp);

      return res.json({
        address,
        playerName: gp.playerName,
        oro: stats.oro,
        plata: stats.plata,
        inventory: serializeInventory(gp)
      });
    } catch (err) {
      console.error('❌ /api/marketplace/account:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── GET /api/marketplace/listings ───────────────────────────────────────
  app.get('/api/marketplace/listings', apiLimiter, authMiddleware, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const { category, search, currency, sort } = req.query;

      /* TODO LO QUE VIENE DE LA QUERY SE FUERZA A TEXTO ANTES DE ENTRAR AL
         FILTRO DE MONGO.
         Express monta objetos con la notación de corchetes: una petición como
             ?category[$ne]=todos
         llega aquí como `{ $ne: 'todos' }`, y Mongo lo interpreta como un
         OPERADOR, no como un valor. Es inyección NoSQL. Aquí el daño es
         pequeño —solo cambia qué anuncios se listan, y los anuncios son
         públicos— pero es el mismo descuido que en un endpoint de escritura
         sería serio, y arreglarlo cuesta un String().

         `currency` y `sort` ya estaban con lista blanca, y `search` ya pasaba
         por `escapeRegex`, que hace su propio String(). El único suelto era
         `category`.

         Al `search` se le pone además un tope de largo: sin él, una cadena de
         cien mil caracteres construye un regex enorme que se pasea por los 300
         anuncios en cada petición. */
      const filter = {};
      const categoriaTxt = (typeof category === 'string') ? category : '';
      const buscarTxt = (typeof search === 'string') ? search.slice(0, 80) : '';
      if (categoriaTxt && categoriaTxt !== 'todos') filter.category = categoriaTxt;
      if (currency && ['oro', 'plata'].includes(currency)) filter.currency = currency;
      if (buscarTxt) filter.name = new RegExp(escapeRegex(buscarTxt), 'i');

      let sortOpt = { createdAt: -1 };
      if (sort === 'price_asc') sortOpt = { pricePerUnit: 1 };
      if (sort === 'price_desc') sortOpt = { pricePerUnit: -1 };

      const listings = await Listing.find(filter).sort(sortOpt).limit(300).exec();
      return res.json({ listings: listings.map(l => serializeListing(l, address)) });
    } catch (err) {
      console.error('❌ GET /api/marketplace/listings:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── GET /api/marketplace/my-listings ────────────────────────────────────
  app.get('/api/marketplace/my-listings', apiLimiter, authMiddleware, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const listings = await Listing.find({ owner: address }).sort({ createdAt: -1 }).exec();
      return res.json({ listings: listings.map(l => serializeListing(l, address)) });
    } catch (err) {
      console.error('❌ GET /api/marketplace/my-listings:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── POST /api/marketplace/list ──────────────────────────────────────────
  // body: { slotId, itemId, qty, pricePerUnit, currency }
  app.post('/api/marketplace/list', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      let { slotId, itemId, qty, pricePerUnit, currency, source } = req.body || {};

      slotId = Number(slotId);
      qty = Math.floor(Number(qty));
      pricePerUnit = round2(Number(pricePerUnit));
      // FIX inventario completo: el objeto puede venir del bolso principal
      // ('inventory') o de la barra rápida ('chest'). Se descuenta del array
      // correcto; por defecto 'inventory' para compatibilidad.
      const srcField = source === 'chest' ? 'chest' : 'inventory';
      // El bolso tiene 40 espacios (0-39); la barra rápida 7 (0-6).
      const maxSlot = srcField === 'chest' ? 6 : 39;

      if (!Number.isInteger(slotId) || slotId < 0 || slotId > maxSlot) {
        return res.status(400).json({ error: 'invalid_slot' });
      }
      if (!itemId || typeof itemId !== 'string') {
        return res.status(400).json({ error: 'invalid_item' });
      }
      if (!Number.isSafeInteger(qty) || qty < 1) {
        return res.status(400).json({ error: 'invalid_qty' });
      }
      if (!validMarketAmount(pricePerUnit) || !validMarketAmount(round2(qty * pricePerUnit))) {
        return res.status(400).json({ error: 'invalid_price' });
      }
      if (!['oro', 'plata'].includes(currency)) {
        return res.status(400).json({ error: 'invalid_currency' });
      }

      const gp = await getGamePlayerByAddress(address);
      if (!gp) return res.status(404).json({ error: 'player_not_found' });

      // Descuento atómico sobre el array correcto (inventory o chest): sólo si
      // ese slot sigue teniendo ese ítem y cantidad suficiente
      const updated = await GamePlayer.findOneAndUpdate(
        {
          address,
          [srcField]: { $elemMatch: { id: slotId, objeto: itemId, cantidad: { $gte: qty } } }
        },
        { $inc: { [`${srcField}.$[slot].cantidad`]: -qty } },
        {
          new: true,
          arrayFilters: [{ 'slot.id': slotId, 'slot.objeto': itemId }]
        }
      ).exec();

      if (!updated) {
        return res.status(400).json({ error: 'insufficient_item_quantity', message: 'No tienes esa cantidad de ese objeto en ese espacio' });
      }

      // Limpieza best-effort de slots que quedaron en 0 (en el array usado)
      await GamePlayer.updateOne(
        { address },
        { $pull: { [srcField]: { cantidad: { $lte: 0 } } } }
      ).exec();

      const meta = catalogMeta(itemId);
      const listing = await Listing.create({
        owner: address,
        ownerName: gp.playerName,
        itemId,
        name: meta.name,
        category: meta.category,
        qty,
        pricePerUnit,
        currency,
        imageUrl: meta.icon
      });

      // Se anota la PUBLICACIÓN en el historial. No mueve dinero, pero es lo
      // que permite leer después "publiqué 10 → me compraron 3 → cancelé 7"
      // en vez de ver solo la venta parcial y pensar que se vendió todo.
      try {
        await MarketHistory.create({
          playerName: gp.playerName,
          address,
          type: 'list',
          itemId,
          name: meta.name,
          category: meta.category,
          qty,
          pricePerUnit,
          total: 0, fee: 0, sellerReceives: 0,
          currency,
          createdAt: new Date()
        });
      } catch (histErr) {
        console.warn('⚠️ No se pudo registrar la publicación en el historial:', histErr.message);
      }

      const fresh = await getGamePlayerByAddress(address);
      return res.json({
        success: true,
        listing: serializeListing(listing, address),
        inventory: serializeInventory(fresh)
      });
    } catch (err) {
      console.error('❌ POST /api/marketplace/list:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── POST /api/marketplace/cancel/:id ────────────────────────────────────
  app.post('/api/marketplace/cancel/:id', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'invalid_listing_id' });
      }

      const listing = await Listing.findById(id).exec();
      if (!listing) return res.status(404).json({ error: 'listing_not_found' });
      if (listing.owner !== address) return res.status(403).json({ error: 'not_your_listing' });

      const gp = await getGamePlayerByAddress(address);
      if (!gp) return res.status(404).json({ error: 'player_not_found' });

      const meta = catalogMeta(listing.itemId);
      const plan = computeInsertPlan(gp.inventory, listing.itemId, listing.qty, meta.maxStack);
      if (!plan) {
        return res.status(400).json({
          error: 'inventory_full',
          message: 'Tu inventario está lleno — libera espacio antes de cancelar esta publicación'
        });
      }

      await Listing.deleteOne({ _id: listing._id }).exec();
      await applyInsertPlan(address, listing.itemId, plan);

      // Deja constancia de que se RETIRÓ (no de que se vendió). Es lo que
      // faltaba: sin esta fila, cancelar no aparecía por ningún lado y una
      // venta parcial anterior era lo único visible en el historial.
      try {
        await MarketHistory.create({
          playerName: gp.playerName,
          address,
          type: 'cancel',
          itemId: listing.itemId,
          name: meta.name,
          category: meta.category,
          qty: listing.qty,
          pricePerUnit: listing.pricePerUnit,
          total: 0, fee: 0, sellerReceives: 0,
          currency: listing.currency,
          createdAt: new Date()
        });
      } catch (histErr) {
        console.warn('⚠️ No se pudo registrar la cancelación en el historial:', histErr.message);
      }

      const fresh = await getGamePlayerByAddress(address);
      return res.json({ success: true, inventory: serializeInventory(fresh) });
    } catch (err) {
      console.error('❌ POST /api/marketplace/cancel/:id:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── POST /api/marketplace/buy/:id ───────────────────────────────────────
  // body: { qty } (opcional — por defecto compra toda la publicación)
  app.post('/api/marketplace/buy/:id', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'invalid_listing_id' });
      }

      const listing = await Listing.findById(id).exec();
      if (!listing) return res.status(404).json({ error: 'listing_not_found', message: 'Esa publicación ya no está disponible' });
      if (listing.owner === address) {
        return res.status(400).json({ error: 'cannot_buy_own_listing', message: 'No puedes comprar tu propia publicación' });
      }

      let qty = req.body && req.body.qty ? Math.floor(Number(req.body.qty)) : listing.qty;
      if (!Number.isSafeInteger(qty) || qty < 1 || qty > listing.qty) {
        return res.status(400).json({ error: 'invalid_qty' });
      }

      const buyerGP = await getGamePlayerByAddress(address);
      if (!buyerGP) return res.status(404).json({ error: 'player_not_found' });
      const bajoNivel = await nivelInsuficiente(buyerGP, listing.itemId, 'p2p_nivel');
      if (bajoNivel) return res.status(403).json(bajoNivel);

      const meta = catalogMeta(listing.itemId);

      // 1) Verificar espacio en el inventario del comprador ANTES de cobrar nada
      const plan = computeInsertPlan(buyerGP.inventory, listing.itemId, qty, meta.maxStack);
      if (!plan) {
        return res.status(400).json({ error: 'inventory_full', message: 'Tu inventario está lleno' });
      }

      const totalPrice = round2(qty * listing.pricePerUnit);
      if (!validMarketAmount(totalPrice)) return res.status(400).json({ error: 'invalid_price' });
      const fee = round2(totalPrice * MARKET_FEE_BPS / 10000);
      const sellerReceives = round2(totalPrice - fee);
      const field = currencyField(listing.currency);

      const buyerStats = await getOrCreateStats(buyerGP.playerName, address, buyerGP);

      // 2) Cobrar al comprador de forma atómica (guard >= totalPrice evita saldo negativo)
      const debited = await PlayerStats.findOneAndUpdate(
        { playerName: buyerGP.playerName, [field]: { $gte: totalPrice } },
        { $inc: { [field]: -totalPrice } },
        { new: true }
      ).exec();

      if (!debited) {
        return res.status(402).json({
          error: 'insufficient_funds',
          message: `No tienes suficiente ${listing.currency === 'oro' ? 'oro' : 'plata'} para esta compra`
        });
      }

      // 3) Descontar la publicación de forma atómica (evita comprar más de lo que queda)
      const listingUpdated = await Listing.findOneAndUpdate(
        { _id: listing._id, qty: { $gte: qty } },
        { $inc: { qty: -qty } },
        { new: true }
      ).exec();

      if (!listingUpdated) {
        // Alguien más compró primero — devolver el dinero al comprador
        await PlayerStats.updateOne(
          { playerName: buyerGP.playerName },
          { $inc: { [field]: totalPrice } }
        ).exec();
        return res.status(409).json({
          error: 'listing_changed',
          message: 'Esa publicación cambió (alguien más compró primero). Intenta de nuevo.'
        });
      }

      if (listingUpdated.qty <= 0) {
        await Listing.deleteOne({ _id: listingUpdated._id }).exec();
      }

      // 4) Pagar al vendedor (95 % — el 5 % de comisión va a los dos tesoros)
      const sellerPaid = await PlayerStats.updateOne(
        { address: listing.owner },
        { $inc: { [field]: sellerReceives } }
      ).exec();
      if (sellerPaid.matchedCount !== 1) throw new Error('market_seller_stats_missing');
      await ingresarAlTesoro(listing.currency, fee, listing.ownerName, listing.itemId, qty);

      // 5) Entregar el ítem al comprador
      await applyInsertPlan(address, listing.itemId, plan);

      // 6) Registrar el HISTORIAL (persistente, por jugador). Dos filas: una
      //    para el comprador y otra para el vendedor. No es crítico para la
      //    transacción, así que si falla solo se avisa (best-effort).
      try {
        await MarketHistory.insertMany([
          {
            playerName: buyerGP.playerName,
            address,
            type: 'buy',
            itemId: listing.itemId,
            name: meta.name,
            category: meta.category,
            qty,
            pricePerUnit: listing.pricePerUnit,
            total: totalPrice,
            fee: 0,
            sellerReceives: null,
            currency: listing.currency,
            counterparty: listing.owner,
            counterpartyName: listing.ownerName,
            createdAt: new Date()
          },
          {
            playerName: listing.ownerName,
            address: listing.owner,
            type: 'sell',
            itemId: listing.itemId,
            name: meta.name,
            category: meta.category,
            qty,
            pricePerUnit: listing.pricePerUnit,
            total: totalPrice,
            fee,
            sellerReceives,
            currency: listing.currency,
            counterparty: address,
            counterpartyName: buyerGP.playerName,
            createdAt: new Date()
          }
        ]);
      } catch (histErr) {
        console.warn('⚠️ No se pudo registrar el historial de mercado:', histErr.message);
      }

      const freshStats = await PlayerStats.findOne({ playerName: buyerGP.playerName }).lean();
      const freshGP = await getGamePlayerByAddress(address);

      return res.json({
        success: true,
        paid: totalPrice,
        fee,
        currency: listing.currency,
        oro: freshStats.oro,
        plata: freshStats.plata,
        inventory: serializeInventory(freshGP)
      });
    } catch (err) {
      console.error('❌ POST /api/marketplace/buy/:id:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── GET /api/marketplace/history ────────────────────────────────────────
  // Historial de compras/ventas del jugador logeado. Sólo devuelve SUS filas
  // (por playerName o address), así nunca se mezcla con otros jugadores.
  app.get('/api/marketplace/history', apiLimiter, authMiddleware, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const gp = await getGamePlayerByAddress(address);
      const playerName = gp ? gp.playerName : null;

      const query = playerName
        ? { $or: [{ playerName }, { address }] }
        : { address };

      const rows = await MarketHistory.find(query)
        .sort({ createdAt: -1 })
        .limit(100)
        .lean();

      return res.json({ history: rows.map(serializeHistory) });
    } catch (err) {
      console.error('❌ GET /api/marketplace/history:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ==========================================================================
  // PERFIL PÚBLICO DE UN JUGADOR                                 (2026-08-05)
  // --------------------------------------------------------------------------
  // Al tocar el nombre o la cartera de quien publicó algo se abre su ficha.
  // Se enseña SOLO lo que es razonable que vea otro jugador: nombre, cartera,
  // nivel, skills, cuándo empezó y qué objetos tiene. Nunca su correo, ni sus
  // sesiones, ni nada de su bóveda.
  // ==========================================================================
  app.get('/api/marketplace/profile/:key', apiLimiter, authMiddleware, async (req, res) => {
    try {
      const key = String(req.params.key || '').trim();
      if (!key) return res.status(400).json({ error: 'invalid_key' });

      // La clave puede ser la dirección o el playerName (en este juego suelen
      // coincidir, pero un jugador con Username propio se busca por nombre).
      const esDireccion = /^0x[0-9a-fA-F]{40}$/.test(key);
      const gp = esDireccion
        ? await GamePlayer.findOne({ address: key.toLowerCase() }).lean()
        : await GamePlayer.findOne({ playerName: key }).lean();

      if (!gp) return res.status(404).json({ error: 'player_not_found' });

      // Inventario visible: se agrupan las unidades del mismo ítem para no
      // enseñar la disposición exacta de sus casillas.
      const porItem = new Map();
      const sumar = (arr) => {
        (arr || []).forEach(e => {
          if (!e || !e.objeto || !(Number(e.cantidad) > 0)) return;
          porItem.set(e.objeto, (porItem.get(e.objeto) || 0) + Number(e.cantidad));
        });
      };
      sumar(gp.inventory);
      sumar(gp.chest);

      const items = Array.from(porItem.entries()).map(([itemId, qty]) => {
        const meta = catalogMeta(itemId);
        return { itemId, name: meta.name, category: meta.category, icon: meta.icon, qty };
      }).sort((a, b) => b.qty - a.qty);

      const stats = await PlayerStats.findOne({ playerName: gp.playerName }).lean();

      return res.json({
        profile: {
          playerName: gp.playerName,
          username: gp.Username && gp.Username !== '---' ? gp.Username : null,
          address: gp.address || null,
          level: gp.nivel || 0,
          exp: gp.nivel_exp || 0,
          petName: gp.petName && gp.petName !== '---' ? gp.petName : null,
          petLevel: gp.petLevel || 1,
          missions: gp.misiones || 0,
          skills: {
            agricultura: gp.agricultura || 0,
            mineria: gp.mineria || 0,
            deforestacion: gp.deforestacion || 0,
            pesca: gp.pesca || 0,
            cocina: gp.cocina || 0,
            fuerza: gp.fuerza || 0
          },
          // Las vitales sí, pero el dinero NO: el saldo de otro jugador no es
          // asunto de nadie y enseñarlo invita a elegir víctima.
          vitals: stats ? { vida: stats.vida, agua: stats.agua, comida: stats.comida } : null,
          createdAt: gp.createdAt || null,
          itemCount: items.reduce((a, i) => a + i.qty, 0)
        },
        items
      });
    } catch (err) {
      console.error('❌ GET /api/marketplace/profile:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ==========================================================================
  // OFERTAS SOBRE UNA PUBLICACIÓN                                (2026-08-05)
  // --------------------------------------------------------------------------
  // Un comprador puede ofrecer MENOS (o más) de lo que pide el vendedor.
  //
  // REGLA DEL DINERO: al ofertar, el importe se RETIENE al comprador en el
  // acto. Si no se retuviera, el vendedor podría aceptar una oferta de alguien
  // que ya se gastó el dinero, y la venta fallaría al azar. El dinero vuelve
  // entero si la oferta se rechaza, se cancela o caduca.
  // ==========================================================================
  const OFFER_TTL_HORAS = 48;

  const marketOfferSchema = new mongoose.Schema({
    listingId:    { type: String, required: true, index: true },
    itemId:       String,
    name:         String,
    qty:          { type: Number, required: true, min: 1 },
    pricePerUnit: { type: Number, required: true, min: 0 },
    total:        { type: Number, required: true, min: 0 },
    currency:     { type: String, enum: ['oro', 'plata'], required: true },

    buyer:        { type: String, required: true, lowercase: true, index: true },
    buyerName:    String,
    seller:       { type: String, required: true, lowercase: true, index: true },
    sellerName:   String,

    status:       { type: String, enum: ['pending', 'accepted', 'rejected', 'cancelled', 'expired'], default: 'pending', index: true },
    message:      { type: String, default: '' },
    expiresAt:    { type: Date, required: true },
    createdAt:    { type: Date, default: Date.now },
    resolvedAt:   { type: Date, default: null }
  }, { collection: 'market_offers' });

  const MarketOffer = atomic.model(mongoose.models.MarketOffer
    || mongoose.model('MarketOffer', marketOfferSchema));

  function serializeOffer(o, listing) {
    const meta = catalogMeta(o.itemId);
    return {
      id: String(o._id),
      listingId: o.listingId,
      itemId: o.itemId,
      name: meta.name,
      icon: meta.icon,
      qty: o.qty,
      pricePerUnit: o.pricePerUnit,
      total: o.total,
      currency: o.currency,
      buyer: o.buyer,
      buyerName: o.buyerName,
      seller: o.seller,
      sellerName: o.sellerName,
      status: o.status,
      message: o.message,
      expiresAt: o.expiresAt,
      createdAt: o.createdAt,
      // Precio que pide el vendedor ahora mismo, para comparar de un vistazo.
      askPricePerUnit: listing ? listing.pricePerUnit : null,
      listingGone: !listing
    };
  }

  /** Devuelve el dinero retenido de una oferta. Idempotente por `status`. */
  async function devolverRetencion(offer, resolution = 'cancelled') {
    return atomic.transaction(async () => {
      // Claim and credit commit together. Stale copies from the expiry
      // worker or a second HTTP request cannot refund the same escrow twice.
      const claimed = await MarketOffer.findOneAndUpdate(
        { _id: offer._id, status: 'pending' },
        { $set: { status: resolution, resolvedAt: new Date() } }, { new: true }).exec();
      if (!claimed) return false;
      const field = currencyField(claimed.currency);
      const gp = await GamePlayer.findOne({ address: claimed.buyer }).lean();
      if (!gp) throw new Error('market_refund_player_missing');
      const refunded = await PlayerStats.updateOne(
        { playerName: gp.playerName }, { $inc: { [field]: claimed.total } }).exec();
      if (refunded.matchedCount !== 1) throw new Error('market_refund_stats_missing');
      return true;
    });
  }

  /** Caduca las ofertas pasadas de fecha y devuelve el dinero retenido. */
  async function caducarOfertas() {
    const vencidas = await MarketOffer.find({
      status: 'pending',
      expiresAt: { $lte: new Date() }
    }).limit(200);

    for (const o of vencidas) {
      try {
        await devolverRetencion(o, 'expired');
      } catch (e) {
        console.warn('⚠️ No se pudo caducar la oferta', String(o._id), e.message);
      }
    }
    return vencidas.length;
  }

  // Barrido periódico + uno al arrancar, para que el dinero retenido nunca se
  // quede atrapado si nadie vuelve a abrir el mercado.
  setTimeout(() => { caducarOfertas().catch(() => {}); }, 15000);
  setInterval(() => { caducarOfertas().catch(() => {}); }, 10 * 60 * 1000);

  // ── POST /api/marketplace/offer/:listingId — hacer una oferta ───────────
  app.post('/api/marketplace/offer/:listingId', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const { listingId } = req.params;

      if (!mongoose.Types.ObjectId.isValid(listingId)) {
        return res.status(400).json({ error: 'invalid_listing_id' });
      }

      const listing = await Listing.findById(listingId).exec();
      if (!listing) return res.status(404).json({ error: 'listing_not_found' });
      if (listing.owner === address) {
        return res.status(400).json({ error: 'cannot_offer_own_listing' });
      }

      const qty = Math.floor(Number(req.body && req.body.qty));
      const pricePerUnit = round2(Number(req.body && req.body.pricePerUnit));
      const message = String((req.body && req.body.message) || '').replace(/<[^>]*>/g, '').trim().slice(0, 140);

      if (!Number.isSafeInteger(qty) || qty < 1 || qty > listing.qty) {
        return res.status(400).json({ error: 'invalid_qty' });
      }
      if (!validMarketAmount(pricePerUnit) || !validMarketAmount(round2(qty * pricePerUnit))) {
        return res.status(400).json({ error: 'invalid_price' });
      }

      const gp = await getGamePlayerByAddress(address);
      if (!gp) return res.status(404).json({ error: 'player_not_found' });
      const bajoNivel = await nivelInsuficiente(gp, listing.itemId, 'p2p_nivel');
      if (bajoNivel) return res.status(403).json(bajoNivel);

      // Una oferta viva por publicación y comprador: si ya había una, se
      // cancela (y se devuelve su dinero) antes de crear la nueva.
      const previa = await MarketOffer.findOne({ listingId, buyer: address, status: 'pending' });
      if (previa) {
        await devolverRetencion(previa);
      }

      const total = round2(qty * pricePerUnit);
      const field = currencyField(listing.currency);
      await getOrCreateStats(gp.playerName, address, gp);

      // RETENCIÓN atómica: la condición $gte impide dejar el saldo en negativo
      // aunque lleguen dos ofertas a la vez.
      const retenido = await PlayerStats.findOneAndUpdate(
        { playerName: gp.playerName, [field]: { $gte: total } },
        { $inc: { [field]: -total } },
        { new: true }
      ).exec();

      if (!retenido) {
        return res.status(402).json({
          error: 'insufficient_funds',
          message: `No tienes suficiente ${listing.currency} para respaldar esta oferta`
        });
      }

      const oferta = await MarketOffer.create({
        listingId: String(listing._id),
        itemId: listing.itemId,
        name: listing.name,
        qty, pricePerUnit, total,
        currency: listing.currency,
        buyer: address,
        buyerName: gp.playerName,
        seller: listing.owner,
        sellerName: listing.ownerName,
        status: 'pending',
        message,
        expiresAt: new Date(Date.now() + OFFER_TTL_HORAS * 3600 * 1000)
      });

      return res.json({
        success: true,
        offer: serializeOffer(oferta, listing),
        oro: retenido.oro,
        plata: retenido.plata
      });
    } catch (err) {
      console.error('❌ POST /api/marketplace/offer:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── GET /api/marketplace/offers — recibidas y enviadas ──────────────────
  app.get('/api/marketplace/offers', apiLimiter, authMiddleware, async (req, res) => {
    try {
      await caducarOfertas();
      const address = (req.user.address || '').toLowerCase();

      const [recibidas, enviadas] = await Promise.all([
        MarketOffer.find({ seller: address }).sort({ status: 1, createdAt: -1 }).limit(100).lean(),
        MarketOffer.find({ buyer: address }).sort({ status: 1, createdAt: -1 }).limit(100).lean()
      ]);

      // Se acompaña cada oferta de su publicación para poder comparar precios
      // y avisar si la publicación ya no existe.
      const ids = [...new Set([...recibidas, ...enviadas].map(o => o.listingId))]
        .filter(id => mongoose.Types.ObjectId.isValid(id));
      const listings = ids.length ? await Listing.find({ _id: { $in: ids } }).lean() : [];
      const porId = new Map(listings.map(l => [String(l._id), l]));

      return res.json({
        received: recibidas.map(o => serializeOffer(o, porId.get(o.listingId))),
        sent:     enviadas.map(o => serializeOffer(o, porId.get(o.listingId))),
        pendingReceived: recibidas.filter(o => o.status === 'pending').length
      });
    } catch (err) {
      console.error('❌ GET /api/marketplace/offers:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── POST /api/marketplace/offer/:id/accept — el VENDEDOR acepta ─────────
  app.post('/api/marketplace/offer/:id/accept', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const { id } = req.params;
      if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'invalid_offer_id' });

      const offer = await MarketOffer.findById(id).exec();
      if (!offer) return res.status(404).json({ error: 'offer_not_found' });
      if (offer.seller !== address) return res.status(403).json({ error: 'not_your_offer' });
      if (offer.status !== 'pending') return res.status(409).json({ error: 'offer_not_pending' });
      if (offer.expiresAt <= new Date()) {
        await devolverRetencion(offer, 'expired');
        return res.commitStatus(409).json({ error: 'offer_expired' });
      }

      const listing = await Listing.findById(offer.listingId).exec();
      if (!listing) {
        await devolverRetencion(offer);
        return res.commitStatus(409).json({ error: 'listing_gone', message: 'Esa publicación ya no existe. Se devolvió el dinero al comprador.' });
      }

      const meta = catalogMeta(offer.itemId);
      const buyerGP = await GamePlayer.findOne({ address: offer.buyer }).lean();
      if (!buyerGP) return res.status(404).json({ error: 'buyer_not_found' });

      // El comprador tiene que tener sitio para el ítem ANTES de mover nada.
      const plan = computeInsertPlan(buyerGP.inventory, offer.itemId, offer.qty, meta.maxStack);
      if (!plan) {
        return res.status(409).json({
          error: 'buyer_inventory_full',
          message: 'El inventario del comprador está lleno. Pídele que haga espacio.'
        });
      }

      // Descontar de la publicación de forma atómica.
      const actualizada = await Listing.findOneAndUpdate(
        { _id: listing._id, qty: { $gte: offer.qty } },
        { $inc: { qty: -offer.qty } },
        { new: true }
      ).exec();

      if (!actualizada) {
        return res.status(409).json({
          error: 'not_enough_stock',
          message: 'Ya no te quedan tantas unidades publicadas para aceptar esta oferta.'
        });
      }
      if (actualizada.qty <= 0) await Listing.deleteOne({ _id: actualizada._id }).exec();

      // El dinero YA estaba retenido al comprador: aquí solo se le paga al
      // vendedor (menos comisión) y se entrega el ítem.
      const fee = round2(offer.total * MARKET_FEE_BPS / 10000);
      const sellerReceives = round2(offer.total - fee);
      const field = currencyField(offer.currency);

      const sellerPaid = await PlayerStats.updateOne(
        { address: offer.seller },
        { $inc: { [field]: sellerReceives } }
      ).exec();
      if (sellerPaid.matchedCount !== 1) throw new Error('market_seller_stats_missing');
      await ingresarAlTesoro(offer.currency, fee, offer.sellerName, offer.itemId, offer.qty);

      await applyInsertPlan(offer.buyer, offer.itemId, plan);

      offer.status = 'accepted';
      offer.resolvedAt = new Date();
      await offer.save();

      // Las demás ofertas de esa publicación que ya no quepan se caen solas en
      // el siguiente barrido; aquí no se tocan para no sorprender a nadie.

      try {
        await MarketHistory.insertMany([
          {
            playerName: offer.buyerName, address: offer.buyer, type: 'buy',
            itemId: offer.itemId, name: meta.name, category: meta.category,
            qty: offer.qty, pricePerUnit: offer.pricePerUnit, total: offer.total,
            fee: 0, sellerReceives: null, currency: offer.currency,
            counterparty: offer.seller, counterpartyName: offer.sellerName, createdAt: new Date()
          },
          {
            playerName: offer.sellerName, address: offer.seller, type: 'sell',
            itemId: offer.itemId, name: meta.name, category: meta.category,
            qty: offer.qty, pricePerUnit: offer.pricePerUnit, total: offer.total,
            fee, sellerReceives, currency: offer.currency,
            counterparty: offer.buyer, counterpartyName: offer.buyerName, createdAt: new Date()
          }
        ]);
      } catch (e) { console.warn('⚠️ historial de oferta aceptada:', e.message); }

      const stats = await PlayerStats.findOne({ address: offer.seller }).lean();
      return res.json({
        success: true, received: sellerReceives, fee,
        oro: stats ? stats.oro : null, plata: stats ? stats.plata : null
      });
    } catch (err) {
      console.error('❌ POST /api/marketplace/offer/accept:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── POST /api/marketplace/offer/:id/reject — el VENDEDOR rechaza ────────
  // ── POST /api/marketplace/offer/:id/cancel — el COMPRADOR retira ────────
  const resolverOferta = (quien) => async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const { id } = req.params;
      if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'invalid_offer_id' });

      const offer = await MarketOffer.findById(id).exec();
      if (!offer) return res.status(404).json({ error: 'offer_not_found' });

      const autorizado = quien === 'seller' ? offer.seller === address : offer.buyer === address;
      if (!autorizado) return res.status(403).json({ error: 'not_your_offer' });
      if (offer.status !== 'pending') return res.status(409).json({ error: 'offer_not_pending' });

      // Sea quien sea el que la cierra, el dinero retenido vuelve al comprador.
      const resolution = quien === 'seller' ? 'rejected' : 'cancelled';
      if (!(await devolverRetencion(offer, resolution))) return res.status(409).json({ error: 'offer_not_pending' });
      offer.status = resolution;

      const gp = await getGamePlayerByAddress(address);
      const stats = gp ? await PlayerStats.findOne({ playerName: gp.playerName }).lean() : null;
      return res.json({
        success: true, status: offer.status,
        oro: stats ? stats.oro : null, plata: stats ? stats.plata : null
      });
    } catch (err) {
      console.error('❌ resolver oferta:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  };

  app.post('/api/marketplace/offer/:id/reject', writeLimiter, authMiddleware, csrfProtection, resolverOferta('seller'));
  app.post('/api/marketplace/offer/:id/cancel', writeLimiter, authMiddleware, csrfProtection, resolverOferta('buyer'));

  // ==========================================================================
  // PRODUCTOS LIMITADOS (los pone el ADMIN)                      (2026-08-05)
  // --------------------------------------------------------------------------
  // Lotes que publica el administrador con su wallet: cantidad, precio y una
  // ventana de tiempo. No salen del inventario de nadie — los acuña el juego —
  // así que sirven tanto para objetos exclusivos como para los normales.
  //
  // Quién es admin lo decide server2.js (env ADMIN_ADDRESSES o isAdmin
  // on-chain). Si ese comprobador no llega en el contexto, nadie lo es.
  // ==========================================================================
  const limitedListingSchema = new mongoose.Schema({
    itemId:       { type: String, required: true },
    name:         String,
    qty:          { type: Number, required: true, min: 1 },   // stock inicial
    remaining:    { type: Number, required: true, min: 0 },   // lo que queda
    pricePerUnit: { type: Number, required: true, min: 0 },
    currency:     { type: String, enum: ['oro', 'plata'], default: 'oro' },
    perPlayerLimit: { type: Number, default: 0 },             // 0 = sin tope
    startsAt:     { type: Date, default: Date.now },
    endsAt:       { type: Date, required: true },
    note:         { type: String, default: '' },
    createdBy:    { type: String, lowercase: true },
    active:       { type: Boolean, default: true },
    createdAt:    { type: Date, default: Date.now }
  }, { collection: 'market_limited' });

  const LimitedListing = atomic.model(mongoose.models.LimitedListing
    || mongoose.model('LimitedListing', limitedListingSchema));

  // Cuántas unidades lleva compradas cada jugador de cada lote (para el tope).
  const limitedPurchaseSchema = new mongoose.Schema({
    limitedId: { type: String, required: true, index: true },
    address:   { type: String, required: true, lowercase: true, index: true },
    qty:       { type: Number, default: 0 }
  }, { collection: 'market_limited_purchases' });

  const LimitedPurchase = atomic.model(mongoose.models.LimitedPurchase
    || mongoose.model('LimitedPurchase', limitedPurchaseSchema));

  function serializeLimited(d, comprado) {
    const meta = catalogMeta(d.itemId);
    const ahora = Date.now();
    return {
      id: String(d._id),
      itemId: d.itemId,
      name: meta.name,
      icon: meta.icon,
      category: meta.category,
      qty: d.qty,
      remaining: d.remaining,
      pricePerUnit: d.pricePerUnit,
      currency: d.currency,
      perPlayerLimit: d.perPlayerLimit || 0,
      boughtByMe: comprado || 0,
      startsAt: d.startsAt,
      endsAt: d.endsAt,
      note: d.note,
      active: d.active,
      live: d.active && d.remaining > 0 &&
            new Date(d.startsAt).getTime() <= ahora && new Date(d.endsAt).getTime() > ahora,
      soldOut: d.remaining <= 0,
      ended: new Date(d.endsAt).getTime() <= ahora,
      msLeft: Math.max(0, new Date(d.endsAt).getTime() - ahora)
    };
  }

  async function soyAdmin(req) {
    try { return await isAdminAddress((req.user && req.user.address) || ''); }
    catch (e) { return false; }
  }

  // ── GET /api/marketplace/limited — lo que ve cualquier jugador ──────────
  app.get('/api/marketplace/limited', apiLimiter, authMiddleware, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const admin = await soyAdmin(req);

      // El admin ve TODO (incluidos los caducados y apagados) para poder
      // gestionarlos; el resto solo lo que está vivo o recién terminado.
      const filtro = admin ? {} : { active: true, endsAt: { $gt: new Date(Date.now() - 24 * 3600 * 1000) } };
      const docs = await LimitedListing.find(filtro).sort({ endsAt: 1 }).limit(60).lean();

      const compras = await LimitedPurchase.find({
        address, limitedId: { $in: docs.map(d => String(d._id)) }
      }).lean();
      const porLote = new Map(compras.map(c => [c.limitedId, c.qty]));

      return res.json({
        limited: docs.map(d => serializeLimited(d, porLote.get(String(d._id)))),
        isAdmin: admin
      });
    } catch (err) {
      console.error('❌ GET /api/marketplace/limited:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── POST /api/marketplace/limited — crear lote (SOLO ADMIN) ─────────────
  app.post('/api/marketplace/limited', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      if (!(await soyAdmin(req))) return res.status(403).json({ error: 'admin_only' });

      const b = req.body || {};
      const itemId = String(b.itemId || '').trim();
      if (!itemId) return res.status(400).json({ error: 'invalid_item' });

      const qty = Math.floor(Number(b.qty));
      const pricePerUnit = round2(Number(b.pricePerUnit));
      const currency = b.currency === 'plata' ? 'plata' : 'oro';
      const perPlayerLimit = Math.max(0, Math.floor(Number(b.perPlayerLimit) || 0));
      const horas = Math.max(1, Math.min(24 * 60, Math.floor(Number(b.hours) || 24)));
      const note = String(b.note || '').replace(/<[^>]*>/g, '').trim().slice(0, 160);

      if (!Number.isInteger(qty) || qty < 1 || qty > 1000000) return res.status(400).json({ error: 'invalid_qty' });
      if (!validMarketAmount(pricePerUnit) || !validMarketAmount(round2(qty * pricePerUnit))) return res.status(400).json({ error: 'invalid_price' });

      const meta = catalogMeta(itemId);
      const doc = await LimitedListing.create({
        itemId, name: meta.name,
        qty, remaining: qty,
        pricePerUnit, currency, perPlayerLimit,
        startsAt: new Date(),
        endsAt: new Date(Date.now() + horas * 3600 * 1000),
        note,
        createdBy: (req.user.address || '').toLowerCase(),
        active: true
      });

      console.log(`🎟️  Lote limitado creado: ${qty}× ${itemId} a ${pricePerUnit} ${currency} durante ${horas}h`);
      return res.json({ success: true, limited: serializeLimited(doc, 0) });
    } catch (err) {
      console.error('❌ POST /api/marketplace/limited:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── PATCH /api/marketplace/limited/:id — editar/apagar (SOLO ADMIN) ─────
  app.patch('/api/marketplace/limited/:id', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      if (!(await soyAdmin(req))) return res.status(403).json({ error: 'admin_only' });
      const { id } = req.params;
      if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'invalid_id' });

      const doc = await LimitedListing.findById(id).exec();
      if (!doc) return res.status(404).json({ error: 'not_found' });

      const b = req.body || {};
      if (b.active !== undefined) doc.active = !!b.active;
      if (b.pricePerUnit !== undefined) {
        const p = round2(Number(b.pricePerUnit));
        if (!validMarketAmount(p)) return res.status(400).json({ error: 'invalid_price' });
        doc.pricePerUnit = p;
      }
      if (b.addQty !== undefined) {
        const add = Math.floor(Number(b.addQty));
        if (Number.isInteger(add)) {
          doc.qty = Math.max(0, doc.qty + add);
          doc.remaining = Math.max(0, doc.remaining + add);
        }
      }
      if (b.hours !== undefined) {
        const h = Math.max(1, Math.min(24 * 60, Math.floor(Number(b.hours) || 1)));
        doc.endsAt = new Date(Date.now() + h * 3600 * 1000);
      }
      if (b.perPlayerLimit !== undefined) {
        doc.perPlayerLimit = Math.max(0, Math.floor(Number(b.perPlayerLimit) || 0));
      }
      await doc.save();
      return res.json({ success: true, limited: serializeLimited(doc, 0) });
    } catch (err) {
      console.error('❌ PATCH /api/marketplace/limited:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── DELETE /api/marketplace/limited/:id (SOLO ADMIN) ────────────────────
  app.delete('/api/marketplace/limited/:id', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      if (!(await soyAdmin(req))) return res.status(403).json({ error: 'admin_only' });
      const { id } = req.params;
      if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'invalid_id' });
      await LimitedListing.deleteOne({ _id: id }).exec();
      await LimitedPurchase.deleteMany({ limitedId: String(id) }).exec();
      return res.json({ success: true });
    } catch (err) {
      console.error('❌ DELETE /api/marketplace/limited:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // ── POST /api/marketplace/limited/:id/buy ───────────────────────────────
  app.post('/api/marketplace/limited/:id/buy', writeLimiter, authMiddleware, csrfProtection, async (req, res) => {
    try {
      const address = (req.user.address || '').toLowerCase();
      const { id } = req.params;
      if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'invalid_id' });

      const doc = await LimitedListing.findById(id).exec();
      if (!doc) return res.status(404).json({ error: 'not_found' });

      const ahora = Date.now();
      if (!doc.active)                          return res.status(409).json({ error: 'not_active' });
      if (new Date(doc.startsAt).getTime() > ahora) return res.status(409).json({ error: 'not_started' });
      if (new Date(doc.endsAt).getTime() <= ahora)  return res.status(409).json({ error: 'ended', message: 'Esta oferta limitada ya terminó' });

      const qty = Math.max(1, Math.floor(Number((req.body && req.body.qty) || 1)));
      if (!Number.isSafeInteger(qty)) return res.status(400).json({ error: 'invalid_qty' });
      if (qty > doc.remaining) return res.status(409).json({ error: 'not_enough_stock', remaining: doc.remaining });

      const gp = await getGamePlayerByAddress(address);
      if (!gp) return res.status(404).json({ error: 'player_not_found' });
      const bajoNivel = await nivelInsuficiente(gp, doc.itemId, 'p2p_nivel');
      if (bajoNivel) return res.status(403).json(bajoNivel);

      // Tope por jugador
      if (doc.perPlayerLimit > 0) {
        const previo = await LimitedPurchase.findOne({ limitedId: String(doc._id), address }).lean();
        const yaTiene = previo ? previo.qty : 0;
        if (yaTiene + qty > doc.perPlayerLimit) {
          return res.status(409).json({
            error: 'per_player_limit',
            message: `Solo puedes llevarte ${doc.perPlayerLimit} de este lote (ya tienes ${yaTiene})`
          });
        }
      }

      const meta = catalogMeta(doc.itemId);
      const plan = computeInsertPlan(gp.inventory, doc.itemId, qty, meta.maxStack);
      if (!plan) return res.status(400).json({ error: 'inventory_full', message: 'Tu inventario está lleno' });

      const total = round2(qty * doc.pricePerUnit);
      if (!validMarketAmount(total)) return res.status(400).json({ error: 'invalid_price' });
      const field = currencyField(doc.currency);
      await getOrCreateStats(gp.playerName, address, gp);

      // 1) Cobrar (atómico)
      const cobrado = await PlayerStats.findOneAndUpdate(
        { playerName: gp.playerName, [field]: { $gte: total } },
        { $inc: { [field]: -total } },
        { new: true }
      ).exec();
      if (!cobrado) return res.status(402).json({ error: 'insufficient_funds', message: `No tienes suficiente ${doc.currency}` });

      // 2) Descontar stock (atómico). Si otro se adelantó, se devuelve el dinero.
      const stockOk = await LimitedListing.findOneAndUpdate(
        { _id: doc._id, remaining: { $gte: qty } },
        { $inc: { remaining: -qty } },
        { new: true }
      ).exec();

      if (!stockOk) {
        await PlayerStats.updateOne({ playerName: gp.playerName }, { $inc: { [field]: total } }).exec();
        return res.status(409).json({ error: 'not_enough_stock', message: 'Se agotó mientras comprabas' });
      }

      // 3) Entregar y anotar
      await applyInsertPlan(address, doc.itemId, plan);
      await LimitedPurchase.updateOne(
        { limitedId: String(doc._id), address },
        { $inc: { qty } },
        { upsert: true }
      ).exec();

      try {
        await MarketHistory.create({
          playerName: gp.playerName, address, type: 'buy',
          itemId: doc.itemId, name: meta.name, category: meta.category,
          qty, pricePerUnit: doc.pricePerUnit, total,
          fee: 0, sellerReceives: null, currency: doc.currency,
          counterparty: null, counterpartyName: 'Grassland Forest',
          createdAt: new Date()
        });
      } catch (e) { console.warn('⚠️ historial de compra limitada:', e.message); }

      const freshGP = await getGamePlayerByAddress(address);
      return res.json({
        success: true, paid: total, currency: doc.currency,
        oro: cobrado.oro, plata: cobrado.plata,
        remaining: stockOk.remaining,
        inventory: serializeInventory(freshGP)
      });
    } catch (err) {
      console.error('❌ POST /api/marketplace/limited/buy:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  console.log('🛒 Marketplace routes montadas en /api/marketplace/* (perfiles, ofertas y lotes limitados incluidos)');
};
