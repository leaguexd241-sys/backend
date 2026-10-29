'use strict';
module.exports=function mountCropAdministration(d){
 const {app,catalog,adminAuth,apiLimiter,strictLimiter,csrfProtection}=d,cache=new Map(),pending=new Map();
 async function read(type){
  const cached=cache.get(type);if(cached&&Date.now()-cached.at<15000)return cached.data;
  let work=pending.get(type);
  if(!work){work=(async()=>{try{
    const s=await d.contract().getTipoStats(type),limit=BigInt(s.limit),total=BigInt(s.totalQuantity),exists=!!s.exists;
    return {available:true,configured:exists,limit:String(limit),total:String(total),remaining:String(limit>total?limit-total:0n),perInvoice:String(s.perInvoiceLimit),invoiceCount:String(s.invoiceCount),totalBurned:String(s.totalBurned),occupancy:limit>0n?Number(total*10000n/limit)/100:0};
   }catch(_){return {available:false,configured:null};}})().then(data=>{cache.set(type,{at:Date.now(),data});return data;}).finally(()=>pending.delete(type));pending.set(type,work);}
  let timer;try{return await Promise.race([work,new Promise(resolve=>{timer=setTimeout(()=>resolve({available:false,configured:null}),8000);timer.unref?.();})]);}finally{clearTimeout(timer);}
 }
 app.get('/api/admin/cultivos',adminAuth,apiLimiter,async(req,res)=>{try{
  const query=String(req.query.q||'').slice(0,80).toLowerCase(),page=Math.max(0,Math.floor(Number(req.query.page)||0)),limit=8;
  const matching=catalog.plants.filter(p=>!query||[p.name,p.nameEs,p.key,String(p.level)].some(v=>v.toLowerCase().includes(query))),plants=matching.slice(page*limit,(page+1)*limit);
  const ids=plants.flatMap(p=>[p.seedId,p.freshId,p.rottenId,p.shortId]),rows=ids.map(id=>({id,...catalog.items[id],nameEs:catalog.plants.find(p=>p.key===catalog.items[id].plantKey).nameEs,recommended:catalog.tables.find(t=>t.tipo===id),price:d.prices().items[id]||null}));
  let cursor=0;await Promise.all(Array.from({length:Math.min(4,rows.length)},async()=>{while(cursor<rows.length){const index=cursor++;rows[index].chain=await read(rows[index].id);}}));
  const [receipts,burns,active]=await Promise.all([
   d.Services.find({itemId:{$in:ids},tipo:{$in:['tienda_compra','tienda_venta']}}).select('playerName tipo itemId cantidad confirmadas bronce estado t').sort({t:-1}).limit(20).lean(),
   d.Burns.find({tipo:'objetos',itemId:{$in:ids}}).select('itemId cantidad bronce playerName origen t').sort({t:-1}).limit(20).lean(),
   d.Jobs.find({kind:'farm',active:true}).select('_id playerName wallet recipe quantity status error createdAt').sort({createdAt:1}).limit(20).lean()
  ]);
  const players=await d.Players.find({playerName:{$in:[...new Set(receipts.map(r=>r.playerName))]}}).select('playerName address Username').lean(),who=new Map(players.map(p=>[p.playerName,p]));
  const operations=receipts.map(r=>({...r,tienda:'juego',op:r.tipo==='tienda_compra'?'compra':'venta',username:who.get(r.playerName)?.Username || '',address:who.get(r.playerName)?.address || ''}));
  res.set('Cache-Control','no-store');res.json({ok:true,rows,page,pageSize:limit,total:matching.length,observedAt:new Date(),cacheSeconds:15,contract:await d.contract().getAddress(),chainId:d.chainId,operations,burns,pending:active});
 }catch(_){res.status(503).json({error:'crop_administration_unavailable'});}});
 app.post('/api/admin/cultivos/preparar',adminAuth,strictLimiter,csrfProtection,async(req,res)=>{try{
  const plant=catalog.plants.find(p=>p.key===req.body.key);if(!plant)return res.status(400).json({error:'unknown_crop'});
  const rows=[];for(const id of [plant.seedId,plant.freshId,plant.rottenId,plant.shortId]){const ok=await d.ensure(id);cache.delete(id);rows.push({id,ok});}
  res.set('Cache-Control','no-store');res.json({ok:rows.every(r=>r.ok),rows});
 }catch(_){res.status(503).json({error:'crop_table_setup_unavailable'});}});
 return {clear:type=>cache.delete(type)};
};
