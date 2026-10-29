#!/usr/bin/env node
/**
 * =============================================================================
 * MIGRAR EL CONTRATO DE FACTURAS (v2 -> v3)                       (2026-10-04)
 * =============================================================================
 *
 * Copia TODAS las facturas ACTIVAS del contrato viejo al nuevo, con su mismo id,
 * su manualId, su dueno, su tabla (tipo), su cantidad y su fecha. Antes copia
 * los limites de cada tabla (setLimit) y, si se le dice, da de alta al relayer
 * como admin. Al final compara los dos contratos tabla por tabla.
 *
 * QUE HACE FALTA
 * ---------------------------------------------------------------------------
 *   - El contrato NUEVO ya desplegado (contrato.txt, v3) cuyo OWNER sea la
 *     cartera que firma: migrateInvoicesBatch y sealMigration son onlyOwner.
 *   - La clave privada de esa cartera en la variable de entorno
 *     OWNER_PRIVATE_KEY (nunca en un archivo ni en la linea de comandos).
 *   - Node 18+ y ethers 6:  npm install ethers@6   (en esta misma carpeta)
 *
 * USO
 * ---------------------------------------------------------------------------
 *   1) Ensayo en seco (no envia NADA, solo lee y cuenta):
 *        node migrar-contrato-v3.js --origen 0xVIEJO --destino 0xNUEVO --seco
 *
 *   2) Migracion de verdad (con el juego en mantenimiento, ver abajo):
 *        set OWNER_PRIVATE_KEY=0x...          (PowerShell: $env:OWNER_PRIVATE_KEY="0x...")
 *        node migrar-contrato-v3.js --origen 0xVIEJO --destino 0xNUEVO --relayer 0xRELAYER
 *
 *   3) Cuando la verificacion salga bien, cerrar el candado (IRREVERSIBLE):
 *        node migrar-contrato-v3.js --origen 0xVIEJO --destino 0xNUEVO --sellar
 *
 *   Opciones:
 *     --rpc URL          nodo (por defecto el del juego, chain 4441)
 *     --relayer 0x..     direccion del relayer del servidor: se hace admin
 *     --tipos a,b,c      tablas extra a copiar aunque no tengan facturas activas
 *     --lote N           facturas por transaccion (por defecto se ajusta solo)
 *     --seco             no envia transacciones
 *     --sellar           sella la migracion al terminar si todo cuadra
 *
 * SE PUEDE REPETIR SIN MIEDO
 * ---------------------------------------------------------------------------
 * migrateInvoicesBatch es idempotente: se salta los ids que ya existen en el
 * destino y los manualId ya tomados. Si se corta a mitad (luz, red, gas), se
 * vuelve a lanzar el mismo comando y sigue por donde iba. Antes de cada lote se
 * pregunta al destino que ids tiene ya, asi que no se gasta gas en repetidos.
 *
 * LO QUE NO SE PUEDE MIGRAR (y por que no importa)
 * ---------------------------------------------------------------------------
 *   - Las facturas INACTIVAS (gastadas, borradas): no son de nadie.
 *   - `totalBurned` de cada tabla (el historial de quemas): arranca en 0.
 *   - La lista de admins del viejo: el contrato no la expone. Se pasa el
 *     relayer con --relayer; otros admins, con addAdmin a mano.
 *   - Las casillas del inventario (v3): el viejo no las tenia. El servidor
 *     las escribe solo la proxima vez que cada jugador guarde.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const RPC_POR_DEFECTO = 'https://liteforge.rpc.caldera.xyz/http';
const MAX_LECTURA = 200;                  // MAX_BATCH_SIZE del contrato
const LOTE_MAXIMO = 120;                  // facturas por transaccion, como mucho

const ABI = [
  'function owner() view returns (address)',
  'function isAdmin(address) view returns (bool)',
  'function addAdmin(address)',
  'function setLimit(string,uint256,uint256)',
  'function deprecateTipo(string)',
  'function getTipoStats(string) view returns (uint256 totalQuantity, uint256 limit, uint256 perInvoiceLimit, uint256 invoiceCount, uint256 totalBurned, bool exists)',
  'function totalInvoicesEver() view returns (uint256)',
  'function getInvoicesSafe(uint256[] ids) view returns (tuple(uint256 id, string manualId, address owner, string tipo, uint256 cantidad, bool active, uint256 createdAt)[] result)',
  'function migrateInvoicesBatch(tuple(uint256 id, string manualId, address owner, string tipo, uint256 cantidad, bool active, uint256 createdAt)[] batch)',
  'function migrationSealed() view returns (bool)',
  'function sealMigration()',
  'function CONTRACT_VERSION() view returns (uint256)'
];

function cargarEthers() {
  const candidatos = [
    'ethers',
    path.join(__dirname, 'node_modules', 'ethers'),
    process.env.GF_ETHERS_PATH || ''
  ].filter(Boolean);
  for (const c of candidatos) {
    try { return require(c); } catch (_) { /* siguiente */ }
  }
  throw new Error('No encuentro ethers. Instalalo en esta carpeta con:  npm install ethers@6');
}

function plano(f) {
  return {
    id: BigInt(f.id), manualId: String(f.manualId), owner: String(f.owner),
    tipo: String(f.tipo), cantidad: BigInt(f.cantidad), active: Boolean(f.active),
    createdAt: BigInt(f.createdAt)
  };
}

/**
 * La migracion, como funcion: la usa la linea de comandos y la prueba.
 *
 * @param {object} o
 * @param {object} o.origen     contrato viejo (solo lectura)
 * @param {object} o.destino    contrato nuevo, conectado a la cartera OWNER
 * @param {object} o.provider   para el limite de gas del bloque
 * @param {boolean} [o.seco]    no envia transacciones
 * @param {string} [o.relayer]  direccion a hacer admin en el destino
 * @param {string[]} [o.tiposExtra]
 * @param {number} [o.lote]     facturas por transaccion (fijo)
 * @param {boolean} [o.sellar]
 * @param {function} [o.log]
 */
async function migrar(o) {
  const log = o.log || console.log;
  const { origen, destino } = o;
  const informe = { activas: 0, migradas: 0, yaEstaban: 0, tablas: {}, transacciones: 0, sellado: false, cuadra: false };

  async function enviar(nombre, fn) {
    if (o.seco) { log('   [seco] ' + nombre); return null; }
    const tx = await fn();
    const rc = await tx.wait();
    informe.transacciones++;
    log('   ✓ ' + nombre + '  (gas ' + rc.gasUsed + ', tx ' + tx.hash + ')');
    return rc;
  }

  // ── 0. Comprobaciones del destino ────────────────────────────────────────
  const version = Number(await destino.CONTRACT_VERSION().catch(() => 0));
  if (version < 3) throw new Error('el DESTINO no es el contrato v3 (CONTRACT_VERSION = ' + version + ')');
  if (await destino.migrationSealed()) throw new Error('la migracion del destino YA ESTA SELLADA: no admite mas facturas');
  if (!o.seco) {
    const quien = await destino.runner.getAddress();
    const dueno = await destino.owner();
    if (quien.toLowerCase() !== dueno.toLowerCase()) {
      throw new Error('la cartera que firma (' + quien + ') no es el owner del destino (' + dueno + ')');
    }
  }

  // ── 1. Leer todas las facturas activas del origen ────────────────────────
  const total = Number(await origen.totalInvoicesEver());
  log('1) El contrato viejo emitio ' + total + ' facturas en total. Leyendo las activas…');
  const activas = [];
  for (let desde = 1; desde <= total; desde += MAX_LECTURA) {
    const ids = [];
    for (let i = desde; i < desde + MAX_LECTURA && i <= total; i++) ids.push(i);
    const lote = await origen.getInvoicesSafe(ids);
    for (const f of lote) {
      if (f.active && Number(f.id) !== 0) activas.push(plano(f));
    }
  }
  informe.activas = activas.length;
  log('   ' + activas.length + ' activas.');

  // ── 2. Las tablas (tipos) y sus limites ──────────────────────────────────
  const tipos = new Set(activas.map(f => f.tipo));
  (o.tiposExtra || []).forEach(t => t && tipos.add(t));
  log('2) Copiando los limites de ' + tipos.size + ' tablas…');
  const deprecadas = [];
  for (const tipo of [...tipos].sort()) {
    const v = await origen.getTipoStats(tipo);
    const n = await destino.getTipoStats(tipo);
    let limit = BigInt(v.limit), per = BigInt(v.perInvoiceLimit);
    // Una tabla deprecada en el viejo con facturas vivas: hay que crearla
    // para poder importarlas y deprecarla despues, como estaba.
    if (!v.exists) {
      const suma = activas.filter(f => f.tipo === tipo).reduce((s, f) => s + f.cantidad, 0n);
      if (limit === 0n) limit = suma > 0n ? suma : 1n;
      if (per === 0n) per = activas.filter(f => f.tipo === tipo).reduce((m, f) => (f.cantidad > m ? f.cantidad : m), 1n);
      if (suma > 0n || activas.some(f => f.tipo === tipo)) deprecadas.push(tipo);
      else continue;     // deprecada y sin facturas: no hace falta
    }
    informe.tablas[tipo] = { limite: String(limit), porFactura: String(per) };
    if (n.exists && BigInt(n.limit) === limit && BigInt(n.perInvoiceLimit) === per) continue;
    await enviar('setLimit("' + tipo + '", ' + limit + ', ' + per + ')', () => destino.setLimit(tipo, limit, per));
  }

  // ── 3. El relayer, admin del nuevo ───────────────────────────────────────
  if (o.relayer) {
    if (await destino.isAdmin(o.relayer)) log('3) El relayer ya es admin del contrato nuevo.');
    else {
      log('3) Dando de alta al relayer como admin…');
      await enviar('addAdmin(' + o.relayer + ')', () => destino.addAdmin(o.relayer));
    }
  } else {
    log('3) (sin --relayer: recuerda hacer addAdmin(relayer) en el contrato nuevo o el servidor no podra escribir)');
  }

  // ── 4. Importar por lotes ────────────────────────────────────────────────
  log('4) Importando facturas…');
  const pendientes = [];
  for (let i = 0; i < activas.length; i += MAX_LECTURA) {
    const trozo = activas.slice(i, i + MAX_LECTURA);
    const yaHay = await destino.getInvoicesSafe(trozo.map(f => f.id));
    trozo.forEach((f, k) => {
      if (Number(yaHay[k].id) !== 0) informe.yaEstaban++;
      else pendientes.push(f);
    });
  }
  if (informe.yaEstaban) log('   ' + informe.yaEstaban + ' ya estaban en el destino (se saltan).');

  let lote = Math.max(1, Math.min(LOTE_MAXIMO, Number(o.lote) || 60));
  let topeGas = null;
  try {
    const bloque = await o.provider.getBlock('latest');
    topeGas = bloque && bloque.gasLimit ? (BigInt(bloque.gasLimit) * 45n) / 100n : null;
  } catch (_) { /* sin tope conocido */ }

  let i = 0;
  while (i < pendientes.length) {
    const tanda = pendientes.slice(i, i + lote);
    if (!o.seco && !o.lote && topeGas) {
      // Si la tanda se pasa del 45 % del gas de un bloque, se parte por la
      // mitad. Una factura importada cuesta del orden de 250 000 de gas.
      let gas;
      try { gas = await destino.migrateInvoicesBatch.estimateGas(tanda); } catch (e) { gas = null; }
      if ((gas === null || gas > topeGas) && tanda.length > 1) {
        lote = Math.max(1, Math.floor(tanda.length / 2));
        continue;
      }
    }
    await enviar('migrateInvoicesBatch(' + tanda.length + ' facturas, ids ' + tanda[0].id + '…' + tanda[tanda.length - 1].id + ')',
      () => destino.migrateInvoicesBatch(tanda));
    informe.migradas += tanda.length;
    i += tanda.length;
  }

  for (const tipo of deprecadas) {
    await enviar('deprecateTipo("' + tipo + '") (estaba deprecada en el viejo)', () => destino.deprecateTipo(tipo));
  }

  // ── 5. Verificar ─────────────────────────────────────────────────────────
  log('5) Comparando tabla por tabla…');
  let cuadra = true;
  if (!o.seco) {
    for (const tipo of Object.keys(informe.tablas)) {
      const esperado = activas.filter(f => f.tipo === tipo).reduce((s, f) => s + f.cantidad, 0n);
      const n = await destino.getTipoStats(tipo);
      const ok = BigInt(n.totalQuantity) >= esperado;
      if (!ok) cuadra = false;
      informe.tablas[tipo].esperado = String(esperado);
      informe.tablas[tipo].enDestino = String(n.totalQuantity);
      log('   ' + (ok ? '✓' : '✗') + ' ' + tipo + ': ' + esperado + ' en el viejo, ' + n.totalQuantity + ' en el nuevo');
    }
    // Y una a una: que cada factura activa este en el destino con su dueno y cantidad.
    for (let k = 0; k < activas.length; k += MAX_LECTURA) {
      const trozo = activas.slice(k, k + MAX_LECTURA);
      const nuevas = await destino.getInvoicesSafe(trozo.map(f => f.id));
      trozo.forEach((f, j) => {
        const n = nuevas[j];
        if (Number(n.id) === 0 || String(n.owner).toLowerCase() !== f.owner.toLowerCase() ||
            BigInt(n.cantidad) !== f.cantidad || String(n.manualId) !== f.manualId) {
          cuadra = false;
          log('   ✗ la factura ' + f.id + ' (' + f.manualId + ') no cuadra en el destino');
        }
      });
    }
  }
  informe.cuadra = cuadra && !o.seco;

  // ── 6. Sellar ────────────────────────────────────────────────────────────
  if (o.sellar) {
    if (!informe.cuadra) {
      log('6) NO se sella: la verificacion no salio bien (o es un ensayo en seco).');
    } else {
      log('6) Sellando la migracion (ya no se podran importar mas facturas)…');
      await enviar('sealMigration()', () => destino.sealMigration());
      informe.sellado = true;
    }
  }
  return informe;
}

// ── Linea de comandos ─────────────────────────────────────────────────────
function leerArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith('--')) continue;
    const clave = k.slice(2);
    const sig = argv[i + 1];
    if (sig === undefined || sig.startsWith('--')) a[clave] = true;
    else { a[clave] = sig; i++; }
  }
  return a;
}

async function main() {
  const args = leerArgs(process.argv.slice(2));
  const ethers = cargarEthers();
  const esDir = (v) => typeof v === 'string' && ethers.isAddress(v);
  if (!esDir(args.origen) || !esDir(args.destino)) {
    console.log('Uso: node migrar-contrato-v3.js --origen 0xVIEJO --destino 0xNUEVO [--relayer 0x..] [--seco] [--sellar]');
    process.exit(1);
  }
  if (args.relayer && !esDir(args.relayer)) { console.error('--relayer no es una direccion'); process.exit(1); }
  const provider = new ethers.JsonRpcProvider(args.rpc || process.env.RPC_URL || RPC_POR_DEFECTO);
  const red = await provider.getNetwork();
  console.log('Red: chainId ' + red.chainId + (args.seco ? '   (ENSAYO EN SECO: no se envia nada)' : ''));

  let firmante = provider;
  if (!args.seco) {
    const clave = process.env.OWNER_PRIVATE_KEY;
    if (!clave) { console.error('Falta OWNER_PRIVATE_KEY (la clave de la cartera OWNER del contrato nuevo).'); process.exit(1); }
    firmante = new ethers.Wallet(clave, provider);
    console.log('Firma: ' + firmante.address);
  }
  const origen = new ethers.Contract(args.origen, ABI, provider);
  const destino = new ethers.Contract(args.destino, ABI, firmante);

  const informe = await migrar({
    origen, destino, provider,
    seco: !!args.seco, sellar: !!args.sellar,
    relayer: args.relayer || null,
    lote: args.lote ? Number(args.lote) : null,
    tiposExtra: typeof args.tipos === 'string' ? args.tipos.split(',').map(s => s.trim()) : []
  });
  const archivo = path.join(__dirname, 'migracion-informe-' + Date.now() + '.json');
  fs.writeFileSync(archivo, JSON.stringify(informe, null, 2));
  console.log('\nResumen: ' + informe.activas + ' activas · ' + informe.migradas + ' importadas ahora · ' +
              informe.yaEstaban + ' ya estaban · ' + informe.transacciones + ' transacciones');
  console.log(informe.cuadra ? 'TODO CUADRA.' : (args.seco ? 'Ensayo terminado.' : 'ATENCION: algo no cuadra, mira arriba.'));
  console.log('Informe: ' + archivo);
}

if (require.main === module) {
  main().catch(e => { console.error('\nERROR: ' + (e.shortMessage || e.message || e)); process.exit(1); });
}

module.exports = { migrar, ABI };
