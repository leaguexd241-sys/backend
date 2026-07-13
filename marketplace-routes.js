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

const MARKET_FEE_BPS = 500; // 5.00% de comisión/royalty

// ── Catálogo de ítems (nombre para mostrar, categoría, ícono, stack máximo) ─
// Debe mantenerse en sincronía con `this.ItemDefinitions` en GameScene.js.
// Los paths de ícono son relativos a la raíz del juego (ver ASSET BASE en
// market.html) — por eso empiezan con "/Game/...".
const ITEM_CATALOG = {
  Semillax:  { name: 'Semillas de Zanahoria', category: 'semillas', icon: '/Game/Objetos/Plantas/planta_zanahorias/item_saco.png', maxStack: 50 },
  Semillax1: { name: 'Semillas de Tomate',    category: 'semillas', icon: '/Game/Objetos/Plantas/planta_tomates/semillas_tomate.png', maxStack: 50 },
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
  mineral_cobre:  { name: 'Cobre',  category: 'minerales', icon: '/Game/Source/cobre.png', maxStack: 20 },
  mineral_hierro: { name: 'Hierro', category: 'minerales', icon: '/Game/Source/hierro.png', maxStack: 20 },

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

  trigo_buena: { name: 'Trigo Bueno',   category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_trigo/item_trigo_bueno.png', maxStack: 20 },
  trigo_corta: { name: 'Trigo (brote)', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_trigo/item_planta_trigo.png', maxStack: 20 },
  trigo_mala:  { name: 'Trigo Podrido', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_trigo/item_trigo_podrido.png', maxStack: 20 },

  calabaza_buena: { name: 'Calabaza Buena',   category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_calabaza/item_calabaza_buena.png', maxStack: 20 },
  calabaza_corta: { name: 'Calabaza (brote)', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_calabaza/item_planta_calabaza.png', maxStack: 20 },
  calabaza_mala:  { name: 'Calabaza Podrida', category: 'cultivos', icon: '/Game/Objetos/Plantas/planta_calabaza/item_calabaza_podrida.png', maxStack: 20 }
};

const CATEGORIES = [
  { id: 'semillas',     label: 'Semillas' },
  { id: 'herramientas', label: 'Herramientas' },
  { id: 'minerales',    label: 'Minerales' },
  { id: 'madera',       label: 'Madera' },
  { id: 'cultivos',     label: 'Cultivos' },
  { id: 'otros',        label: 'Otros' }
];

function catalogMeta(itemId) {
  return ITEM_CATALOG[itemId] || { name: itemId, category: 'otros', icon: '', maxStack: 20 };
}

function round2(n) {
  return Math.round((Number(n) + Number.EPSILON) * 100) / 100;
}

function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = function registerMarketplaceRoutes(app, ctx) {
  const {
    mongoose,
    authMiddleware,
    csrfProtection,
    apiLimiter,
    strictLimiter,
    GamePlayer,
    PlayerStats,
    Listing
  } = ctx;

  const writeLimiter = strictLimiter || apiLimiter;

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

  function serializeInventory(inventory) {
    return (inventory || [])
      .filter(e => e && e.objeto && Number(e.cantidad) > 0)
      .map(e => {
        const meta = catalogMeta(e.objeto);
        return {
          slotId: e.id,
          itemId: e.objeto,
          name: meta.name,
          category: meta.category,
          icon: meta.icon,
          maxStack: meta.maxStack,
          qty: Number(e.cantidad)
        };
      });
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
    const ops = [];
    let remaining = qty;
    const usedIds = new Set((inventory || []).map(e => e.id));

    for (const entry of inventory || []) {
      if (remaining <= 0) break;
      if (entry.objeto === itemId && Number(entry.cantidad) < maxStack) {
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
    for (const op of ops) {
      if (op.type === 'inc') {
        await GamePlayer.updateOne(
          { address, 'inventory.id': op.id },
          { $inc: { 'inventory.$.cantidad': op.amount } }
        ).exec();
      } else {
        await GamePlayer.updateOne(
          { address },
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
        inventory: serializeInventory(gp.inventory)
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

      const filter = {};
      if (category && category !== 'todos') filter.category = category;
      if (currency && ['oro', 'plata'].includes(currency)) filter.currency = currency;
      if (search) filter.name = new RegExp(escapeRegex(search), 'i');

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
      let { slotId, itemId, qty, pricePerUnit, currency } = req.body || {};

      slotId = Number(slotId);
      qty = Math.floor(Number(qty));
      pricePerUnit = round2(Number(pricePerUnit));

      if (!Number.isInteger(slotId) || slotId < 0 || slotId > 39) {
        return res.status(400).json({ error: 'invalid_slot' });
      }
      if (!itemId || typeof itemId !== 'string') {
        return res.status(400).json({ error: 'invalid_item' });
      }
      if (!Number.isInteger(qty) || qty < 1) {
        return res.status(400).json({ error: 'invalid_qty' });
      }
      if (!(pricePerUnit > 0)) {
        return res.status(400).json({ error: 'invalid_price' });
      }
      if (!['oro', 'plata'].includes(currency)) {
        return res.status(400).json({ error: 'invalid_currency' });
      }

      const gp = await getGamePlayerByAddress(address);
      if (!gp) return res.status(404).json({ error: 'player_not_found' });

      // Descuento atómico: sólo si ese slot sigue teniendo ese ítem y cantidad suficiente
      const updated = await GamePlayer.findOneAndUpdate(
        {
          address,
          inventory: { $elemMatch: { id: slotId, objeto: itemId, cantidad: { $gte: qty } } }
        },
        { $inc: { 'inventory.$[slot].cantidad': -qty } },
        {
          new: true,
          arrayFilters: [{ 'slot.id': slotId, 'slot.objeto': itemId }]
        }
      ).exec();

      if (!updated) {
        return res.status(400).json({ error: 'insufficient_item_quantity', message: 'No tienes esa cantidad de ese objeto en ese espacio' });
      }

      // Limpieza best-effort de slots que quedaron en 0
      await GamePlayer.updateOne(
        { address },
        { $pull: { inventory: { cantidad: { $lte: 0 } } } }
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

      const fresh = await getGamePlayerByAddress(address);
      return res.json({
        success: true,
        listing: serializeListing(listing, address),
        inventory: serializeInventory(fresh.inventory)
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

      const fresh = await getGamePlayerByAddress(address);
      return res.json({ success: true, inventory: serializeInventory(fresh.inventory) });
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
      if (!Number.isInteger(qty) || qty < 1 || qty > listing.qty) {
        return res.status(400).json({ error: 'invalid_qty' });
      }

      const buyerGP = await getGamePlayerByAddress(address);
      if (!buyerGP) return res.status(404).json({ error: 'player_not_found' });

      const meta = catalogMeta(listing.itemId);

      // 1) Verificar espacio en el inventario del comprador ANTES de cobrar nada
      const plan = computeInsertPlan(buyerGP.inventory, listing.itemId, qty, meta.maxStack);
      if (!plan) {
        return res.status(400).json({ error: 'inventory_full', message: 'Tu inventario está lleno' });
      }

      const totalPrice = round2(qty * listing.pricePerUnit);
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

      // 4) Pagar al vendedor (95% — 5% queda como comisión del mercado)
      await PlayerStats.updateOne(
        { address: listing.owner },
        { $inc: { [field]: sellerReceives } }
      ).exec();

      // 5) Entregar el ítem al comprador
      await applyInsertPlan(address, listing.itemId, plan);

      const freshStats = await PlayerStats.findOne({ playerName: buyerGP.playerName }).lean();
      const freshGP = await getGamePlayerByAddress(address);

      return res.json({
        success: true,
        paid: totalPrice,
        fee,
        currency: listing.currency,
        oro: freshStats.oro,
        plata: freshStats.plata,
        inventory: serializeInventory(freshGP.inventory)
      });
    } catch (err) {
      console.error('❌ POST /api/marketplace/buy/:id:', err);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  });

  console.log('🛒 Marketplace routes montadas en /api/marketplace/*');
};
