/**
 * limpiar-bloqueos.js — vacía la lista de IPs bloqueadas SIN redesplegar.
 *
 * server2.js ya hace esta misma limpieza cada vez que arranca (ver la sección
 * "LIMPIEZA DE ARRANQUE"). Este script sirve para desbloquear a la gente ya
 * mismo, contra la base de producción, sin reiniciar el servidor.
 *
 *   MONGO_URL="mongodb+srv://..." node limpiar-bloqueos.js
 *
 * Ojo: el proceso del servidor que esté vivo guarda una copia en memoria de las
 * IPs bloqueadas, así que además hay que reiniciarlo (o esperar al reinicio)
 * para que suelte esa copia.
 */
require('dotenv').config();
const mongoose = require('mongoose');

const MONGO = process.env.MONGO_URL || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/grassland';

(async () => {
  console.log('🔌 Conectando a', MONGO.replace(/\/\/[^@]*@/, '//***@'));
  await mongoose.connect(MONGO, { serverSelectionTimeoutMS: 10000 });
  const db = mongoose.connection.db;

  const bloqueadas = await db.collection('blockedips').countDocuments();
  console.log(`📋 IPs bloqueadas ahora mismo: ${bloqueadas}`);

  if (bloqueadas) {
    const muestra = await db.collection('blockedips')
      .find({}, { projection: { ip: 1, reason: 1, blockedUntil: 1, isPermanent: 1 } })
      .limit(20).toArray();
    muestra.forEach(d => console.log('   ·', d.ip, '|', d.reason, '| permanente:', !!d.isPermanent));
    if (bloqueadas > 20) console.log(`   … y ${bloqueadas - 20} más`);
  }

  const r1 = await db.collection('blockedips').deleteMany({});
  console.log(`🧹 blockedips borrados: ${r1.deletedCount}`);

  const r2 = await db.collection('securityincidents').deleteMany({});
  console.log(`🧹 securityincidents borrados: ${r2.deletedCount}`);

  const r3 = await db.collection('ipactivities').updateMany({}, {
    $set: {
      threatScore: 0,
      failedRequests: 0,
      failedLastMinute: 0,
      suspiciousCount: 0,
      suspiciousPaths: [],
      failedAttempts: []
    }
  });
  console.log(`🧹 contadores de amenaza reiniciados: ${r3.modifiedCount}`);

  await mongoose.disconnect();
  console.log('✅ Listo. Reinicia el backend para que suelte la copia en memoria.');
})().catch(e => { console.error('❌', e.message); process.exit(1); });
