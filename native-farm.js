'use strict';
// Additive authority for the expanded plants. A plot reservation is committed
// with its durable job; its seed/output is reconciled before the plot changes.
module.exports=function createNativeFarm(d){
 const {mongoose,catalog,Crop,History,Stats,Tools}=d,fail=(code,status=409)=>Object.assign(Error(code),{code,status});
 const schema=new mongoose.Schema({_id:String,operationId:String,playerName:String,plotId:String,createdAt:{type:Date,default:Date.now}},{collection:'native_crop_plot_locks',versionKey:false});
 schema.index({operationId:1});const Lock=mongoose.models.NativeCropLock || mongoose.model('NativeCropLock',schema);
 const recipes=[];
 for(const p of catalog.plants){
  recipes.push({id:'farm_plant_'+p.key,kind:'farm',farm:{action:'plant',key:p.key},free:true,level:p.level,itemId:p.seedId,quantity:0,resources:[{itemId:p.seedId,quantity:1}]});
  for(const [state,itemId] of [['fresh',p.freshId],['rotten',p.rottenId],['unripe',p.shortId]])recipes.push({id:'farm_harvest_'+p.key+'_'+state,kind:'farm',farm:{action:'harvest',key:p.key,state},free:true,level:0,itemId,quantity:1,resources:[]});
 }
 recipes.push({id:'farm_water_can',kind:'farm',farm:{action:'water',mode:'can'},free:true,level:0,itemId:null,quantity:0,resources:[]});
 recipes.push({id:'farm_water_bucket',kind:'farm',farm:{action:'water',mode:'bucket'},free:true,level:0,itemId:'balde_vacio',quantity:1,resources:[{itemId:'balde_con_agua',quantity:1}]});
 const recipeMap=new Map(recipes.map(r=>[r.id,r]));
 const fingerprint=(r,body)=>{
  if(!Array.isArray(body.plotIds)||!body.plotIds.length||body.plotIds.length>50||body.plotIds.some(p=>typeof p!=='string'||p.length>80))throw fail('farm_invalid_plots',400);
  const plots=[...new Set(body.plotIds)].sort();if(plots.length!==body.plotIds.length)throw fail('farm_duplicate_plot',400);return plots;
 };
 const owner=gp=>String(gp.address).toLowerCase();
 const lockKey=(wallet,plotId)=>wallet+':'+plotId;
 async function assertPlots(gp,plots){
  for(const plot of plots){
   if(plot.startsWith('isla_')){if(!await d.island(gp,plot))throw fail('farm_plot_not_owned',403);}
   else if(!d.townPlots.has(plot))throw fail('farm_plot_unknown',400);
  }
 }
 const cropQuery=(gp,plots)=>({userId:{$in:[owner(gp),gp.playerName]},plotId:{$in:plots},isHarvested:false});
 async function assertTool(gp,itemId,cost){
  if(!Tools)throw fail('farm_tool_authority_unavailable',503);await Tools.init();
  const owned=await d.freeInvoices(owner(gp));
  for(const invoice of owned.filter(i=>i.tipo===d.itemType(itemId)&&BigInt(i.cantidad)>0n)){
   const before=await Tools.findOne({invoiceId:Number(invoice.id)}).lean();if(before?.nativeOperation)continue;
   const quantity=Number(invoice.cantidad),max=20;
   const usedBroken=before?.rota && before.issuedQuantity!=null && quantity<before.issuedQuantity;
   const uses=usedBroken?max:before?Math.max(0,Math.min(max,Number(before.usos))):max;
   if(uses+(quantity-1)*max<cost)continue;
   const breaks=Math.floor((cost+max-uses)/max),remaining=quantity-breaks;
   const afterUses=remaining>0?uses-cost+breaks*max:0;
   return {itemId,invoiceId:Number(invoice.id),before:before?{usos:before.usos,maxUsos:before.maxUsos,rota:before.rota,issuedQuantity:before.issuedQuantity ?? null}:null,
    beforeQuantity:quantity,breaks,afterQuantity:remaining,afterUses,max};
  }
  throw fail('farm_tool_required_or_worn',403);
 }
 async function prepare(gp,recipe,key,body){
  await Lock.init();const plots=fingerprint(recipe,body),wallet=owner(gp),quantity=Number(body.quantity);
  await assertPlots(gp,plots);const action=recipe.farm.action;
  const expected=action==='water'&&recipe.farm.mode==='bucket'?Math.ceil(plots.length/2):plots.length;
  if(quantity!==expected)throw fail('farm_quantity_mismatch',400);
  await refresh(gp,plots);
  const rows=await Crop.find(cropQuery(gp,plots)).lean(),byPlot=new Map(rows.map(c=>[c.plotId,c]));
  if(rows.length!==byPlot.size)throw fail('farm_duplicate_crop_requires_review');
  if(await Lock.exists({_id:{$in:plots.map(p=>lockKey(wallet,p))}}))throw fail('farm_plot_busy');
  const metadata={action,plots,mode:recipe.farm.mode || null,key:recipe.farm.key || null,state:recipe.farm.state || null,crops:[],vitals:{}};
  if(action==='plant'){
   if(rows.length)throw fail('farm_plot_occupied');
   const config=catalog.crops['seed_'+recipe.farm.key],settings=await d.settings(),chance=settings.deathEnabled===false?100:Math.max(1,Math.min(100,await d.chance(config.id)));
   metadata.duration=Math.max(5,Math.round(config.growthTime*(Number(settings.growthMultiplier)>0?settings.growthMultiplier:1)));metadata.chance=chance;
   metadata.vitals={agua:config.waterCost*plots.length,comida:config.foodCost*plots.length};metadata.seedType=config.id;
  }else{
   if(rows.length!==plots.length)throw fail('farm_crop_missing');
   if(rows.some(c=>!catalog.crops[c.cropType] || c.nativeLocked))throw fail('farm_crop_not_native_or_busy');
   metadata.crops=plots.map(plot=>{const c=byPlot.get(plot);return {id:String(c._id),plotId:plot,cropType:c.cropType,isDead:c.isDead,isCompleted:c.isCompleted,isWatered:c.isWatered};});
   if(action==='harvest'){
    metadata.tool=await assertTool(gp,'Tijerasx',plots.length);
    for(const c of rows){const cfg=catalog.crops[c.cropType],state=c.isDead?'rotten':c.isCompleted?'fresh':'unripe';if(cfg.id!=='seed_'+recipe.farm.key || state!==recipe.farm.state)throw fail('farm_crop_state_changed');}
    if(d.room && !await d.room(gp,recipe.itemId,quantity))throw fail('farm_inventory_full');
   }else{
    if(rows.some(c=>c.isDead||c.isCompleted||c.isWatered))throw fail('farm_not_waterable');
    if(recipe.farm.mode==='can'){metadata.tool=await assertTool(gp,'Regaderax',1);metadata.vitals={agua:rows.reduce((n,c)=>n+catalog.crops[c.cropType].wateringCost,0)};}
    else if(!await d.table('balde_vacio'))throw fail('farm_bucket_table_unavailable',503);
   }
  }
  if(action==='harvest' && !await d.table(recipe.itemId))throw fail('farm_result_table_unavailable',503);
  return metadata;
 }
 async function reserve(job,gp,recipe,session){
  const m=job.metadata;await Lock.create(m.plots.map(plotId=>({_id:lockKey(job.wallet,plotId),operationId:job._id,playerName:job.playerName,plotId})),{session});
  const current=await Crop.find(cropQuery(gp,m.plots)).session(session).lean();
  if(m.action==='plant'){if(current.length)throw fail('farm_plot_occupied');}
  else{
   if(current.length!==m.crops.length)throw fail('farm_crop_state_changed');
   for(const expected of m.crops){const row=current.find(c=>String(c._id)===expected.id);if(!row || row.nativeLocked || row.isDead!==expected.isDead || row.isCompleted!==expected.isCompleted || row.isWatered!==expected.isWatered)throw fail('farm_crop_state_changed');}
   const locked=await Crop.updateMany({_id:{$in:m.crops.map(c=>c.id)},nativeLocked:{$ne:true}},{$set:{nativeLocked:true}},{session});if(locked.modifiedCount!==m.crops.length)throw fail('farm_crop_state_changed');
  }
  if(m.tool){
   const t=m.tool,filter={invoiceId:t.invoiceId,nativeOperation:null};
   if(t.before){Object.assign(filter,t.before);const changed=await Tools.updateOne(filter,{$set:{usos:t.afterUses,maxUsos:t.max,rota:t.afterUses===0,issuedQuantity:t.afterQuantity,nativeOperation:job._id}},{session});if(changed.matchedCount!==1)throw fail('farm_tool_changed');}
   else await Tools.create([{invoiceId:t.invoiceId,usos:t.afterUses,maxUsos:t.max,rota:t.afterUses===0,issuedQuantity:t.afterQuantity,nativeOperation:job._id}],{session});
  }
  const stats=await Stats.findOne({playerName:job.playerName}).session(session).lean();if(!stats)throw fail('farm_stats_missing');
  const set={},paid={};for(const [stat,cost] of Object.entries(m.vitals || {})){
   const accumulated=Number(stats.vitalFractions?.[stat] || 0)+cost,whole=Math.floor(accumulated+1e-9);if(Number(stats[stat])<whole)throw fail('farm_vitals_insufficient');
   set[stat]=Number(stats[stat])-whole;set['vitalFractions.'+stat]=Math.max(0,accumulated-whole);paid[stat]={whole,fraction:cost-whole};
  }
  if(Object.keys(set).length)await Stats.updateOne({_id:stats._id},{$set:{...set,chainPendingSince:new Date()},$addToSet:{chainPending:{$each:Object.keys(m.vitals)}}},{session});
  return {...m,paid};
 }
 async function complete(job,session){
  const m=job.metadata,ids=m.plots.map(p=>lockKey(job.wallet,p)),locks=await Lock.countDocuments({_id:{$in:ids},operationId:job._id}).session(session);if(locks!==ids.length)throw fail('farm_reservation_missing');
  if(m.action==='plant'){
   const cfg=catalog.crops[m.seedType],now=Date.now();
   await Crop.create(m.plots.map(plotId=>({userId:job.wallet,plotId,cropType:m.seedType,seedType:m.seedType,nativeFarm:true,growthDuration:m.duration,successChance:m.chance,rewards:cfg.rewards,sedientaHasta:new Date(now+d.thirstMs())})),{session});
   await d.award(job.playerName,job._id,20*m.plots.length,null,0,session);
  }else if(m.action==='water'){
   const now=new Date();
   for(const c of m.crops){const row=await Crop.findOne({_id:c.id,nativeLocked:true}).session(session).lean();if(!row)throw fail('farm_crop_missing');
    await Crop.updateOne({_id:c.id,nativeLocked:true},{$set:{isWatered:true,nativeLocked:false,nativeWateredAt:now,nativeReadyAt:new Date(now.getTime()+row.growthDuration*1000),sedientaHasta:null}},{session});}
   await d.award(job.playerName,job._id,5*m.plots.length,null,0,session);
  }else{
   for(const c of m.crops){const row=await Crop.findOne({_id:c.id,nativeLocked:true}).session(session).lean();if(!row)throw fail('farm_crop_missing');
    await History.create([{userId:row.userId,plotId:row.plotId,cropType:row.cropType,seedType:row.seedType,plantedAt:row.plantedAt,harvestedAt:new Date(),growthDuration:row.growthDuration,wasCompleted:row.isCompleted,wasDead:row.isDead,rewards:{item:job.itemId,quantity:1}}],{session});}
   const removed=await Crop.deleteMany({_id:{$in:m.crops.map(c=>c.id)},nativeLocked:true},{session});if(removed.deletedCount!==m.crops.length)throw fail('farm_crop_missing');
   await d.award(job.playerName,job._id,0,'agricultura',25*m.plots.length,session);
  }
  await Lock.deleteMany({_id:{$in:ids},operationId:job._id},{session});
  if(m.tool){const unlocked=await Tools.updateOne({invoiceId:m.tool.invoiceId,nativeOperation:job._id,usos:m.tool.afterUses,issuedQuantity:m.tool.afterQuantity},{$set:{nativeOperation:null}},{session});if(unlocked.matchedCount!==1)throw fail('farm_tool_reservation_changed');}
 }
 async function cancel(job,session){
  const m=job.metadata;await Crop.updateMany({_id:{$in:m.crops.map(c=>c.id)},nativeLocked:true},{$set:{nativeLocked:false}},{session});
  if(m.tool){const filter={invoiceId:m.tool.invoiceId,nativeOperation:job._id};if(m.tool.before)await Tools.updateOne(filter,{$set:{...m.tool.before,nativeOperation:null}},{session});else await Tools.deleteOne(filter,{session});}
  for(const [stat,paid] of Object.entries(m.paid || {})){
   const stats=await Stats.findOne({playerName:job.playerName}).session(session).lean();
   // Return this job's exact fractional cost. Normalize it with the existing
   // accumulator, so repeated cancelled 0.2-cost plantings cannot create food.
   let fraction=Number(stats.vitalFractions?.[stat] || 0)-paid.fraction,whole=paid.whole;
   if(fraction< -1e-8){whole++;fraction++;}if(fraction>1-1e-8){whole--;fraction--;}
   await Stats.updateOne({_id:stats._id},{$set:{[stat]:Math.min(100,Number(stats[stat])+whole),['vitalFractions.'+stat]:Math.max(0,fraction),chainPendingSince:new Date()},$addToSet:{chainPending:stat}},{session});
  }
  await Lock.deleteMany({operationId:job._id},{session});
 }
 function dto(c){const value=c.toObject?c.toObject():{...c};delete value.nativeLocked;delete value.expiresAt;delete value.sedientaHasta;
  if(c.nativeWateredAt&&!c.isCompleted&&!c.isDead)value.currentGrowthTime=Math.min(c.growthDuration,Math.max(0,Math.floor((Date.now()-new Date(c.nativeWateredAt).getTime())/1000)));
  return {...value,cropConfig:catalog.crops[c.cropType]};}
 async function describe(job){const m=job.metadata,rows=await Crop.find({userId:job.wallet,plotId:{$in:m.plots},isHarvested:false}).lean();
  const tool=m.tool?await Tools.findOne({invoiceId:m.tool.invoiceId}).select('invoiceId usos maxUsos').lean():null;
  return {farm:{action:m.action,seedType:m.seedType,mode:m.mode,plotIds:m.plots,crops:rows.map(dto)},toolUses:tool?[tool]:[],...(d.progress?{progress:await d.progress(job.playerName)}:{})};}

 let sweeping=false;
 async function mature(row){
  const dead=Math.random()*100>row.successChance,fields={isCompleted:true,isDead:dead,growthStage:dead?5:4,currentGrowthTime:row.growthDuration,expiresAt:dead?null:d.expiry()};
  const changed=await Crop.updateOne({_id:row._id,nativeLocked:{$ne:true},isCompleted:false},{$set:fields});
  if(changed.modifiedCount===1){const {expiresAt,...publicFields}=fields;d.notify(row.userId,'cropGrowth',{userId:row.userId,plotId:row.plotId,...publicFields,isHalfway:true,timeRemaining:0,cropConfig:catalog.crops[row.cropType]});}
 }
 async function refresh(gp,plots){
  const rows=await Crop.find({...cropQuery(gp,plots),nativeFarm:true,nativeLocked:{$ne:true},isWatered:true,isCompleted:false,isDead:false,nativeReadyAt:{$lte:new Date()}}).limit(50).lean();
  for(const row of rows)await mature(row);
 }
 async function sweep(){if(sweeping || mongoose.connection.readyState!==1)return;sweeping=true;try{
  const now=new Date(),rows=await Crop.find({nativeFarm:true,nativeLocked:{$ne:true},isWatered:true,isCompleted:false,isDead:false,isHarvested:false,nativeReadyAt:{$lte:now}}).sort({nativeReadyAt:1}).limit(100).lean();
  for(const row of rows)await mature(row);
 }finally{sweeping=false;}}
 const plan=(recipe,metadata)=>metadata.tool?.breaks?{...recipe,resources:[...recipe.resources,{itemId:metadata.tool.itemId,quantity:metadata.tool.breaks,absolute:true,invoiceId:metadata.tool.invoiceId}]}:recipe;
 return {Lock,recipes,recipeMap,fingerprint,prepare,reserve,complete,cancel,describe,dto,sweep,refresh,plan,isReserved:async(wallet,plotId)=>!!await Lock.exists({_id:lockKey(String(wallet).toLowerCase(),plotId)})};
};
