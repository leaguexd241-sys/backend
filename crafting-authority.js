'use strict';
// Durable crafting orchestration. MongoDB and the chain are independent: an
// uncertain signed step stays recoverable; it is never replaced by a new mint.
module.exports=function createCraftingAuthority(d){
 const {mongoose,ethers,crypto,recipes,app,authMiddleware,adminAuth,csrfProtection,strictLimiter,apiLimiter}=d;
 const fail=(code,status=409)=>Object.assign(new Error(code),{code,status});
 const recipeMap=new Map([...recipes,...(d.consumables || []),...(d.services || [])].map(r=>[r.id,Object.freeze(r)]));
 const schema=new mongoose.Schema({_id:String,wallet:{type:String,index:true},playerName:String,recipe:String,quantity:Number,option:Number,
  itemId:String,resultQuantity:Number,fingerprint:String,fee:Number,serviceId:String,kind:String,metadata:mongoose.Schema.Types.Mixed,charge:mongoose.Schema.Types.Mixed,origin:String,status:{type:String,default:'prepared'},active:{type:Boolean,default:true},
  privateSteps:{type:[mongoose.Schema.Types.Mixed],select:false},leaseToken:String,leaseUntil:Date,error:String,needsManual:Boolean,retryAt:Date,
  createdAt:{type:Date,default:Date.now},updatedAt:Date},{collection:'authoritative_crafts',versionKey:false});
 schema.index({wallet:1,active:1},{unique:true,partialFilterExpression:{active:true}});
 const Job=mongoose.models.AuthoritativeCraft || mongoose.model('AuthoritativeCraft',schema);
 const outputTypes=new Set(recipes.map(r=>d.itemType(r.itemId)));
 const running=new Set();
 function materials(recipe,quantity,option){
  const need=new Map();const add=x=>{
   const amount=x.quantity*(x.absolute?1:quantity);if(!Number.isSafeInteger(amount)||amount<1)throw fail('craft_invalid_material_quantity');
   const key=x.itemId+':'+(x.invoiceId || ''),entry=need.get(key)||{itemId:x.itemId,amount:0,...(x.invoiceId?{invoiceId:x.invoiceId}:{})};entry.amount+=amount;need.set(key,entry);
  };
  recipe.resources.forEach(add);
  if(recipe.options?.length){if(!Number.isInteger(option) || !recipe.options[0]?.[option])throw fail('craft_option_required',400);add(recipe.options[0][option]);}
  return [...need.values()];
 }
 async function plan(wallet,recipe,quantity,option,key,metadata){
  const c=d.items(),invoices=recipe.resources.length || recipe.options?.length?await d.freeInvoices(wallet):[],steps=[];
  if(recipe.options?.length && option==null){
   option=recipe.options[0].findIndex(choice=>invoices.reduce((sum,invoice)=>sum+(String(invoice.owner).toLowerCase()===wallet&&invoice.active!==false&&invoice.tipo===d.itemType(choice.itemId)?Number(invoice.cantidad):0),0)>=choice.quantity*quantity);
   if(option<0)throw fail('craft_materials_missing');
  }
  for(const need of materials(recipe,quantity,option)){
   let remaining=need.amount;const tipo=d.itemType(need.itemId);
   for(const invoice of invoices){
    if(!remaining)break;
    if(need.invoiceId && Number(invoice.id)!==need.invoiceId)continue;
    if(String(invoice.owner).toLowerCase()!==wallet || invoice.tipo!==tipo || invoice.active===false || BigInt(invoice.cantidad)<=0n)continue;
    const amount=Number(BigInt(invoice.cantidad)<BigInt(remaining)?BigInt(invoice.cantidad):BigInt(remaining));
    if(!Number.isSafeInteger(Number(invoice.id)) || Number(invoice.id)<1)throw fail('craft_invoice_id_unrepresentable');
    const source=steps.length,manualId='cf:'+key.slice(0,32)+':'+source;
    steps.push({kind:'take',itemId:need.itemId,tipo,sourceId:Number(invoice.id),sourceManual:String(invoice.manualId),amount,manualId,status:'planned'});
    steps.push({kind:'burn',itemId:need.itemId,tipo,sourceStep:source,amount,status:'planned'});remaining-=amount;
   }
   if(remaining)throw fail('craft_materials_missing');
  }
  const resultQuantity=recipe.quantity*quantity;
  if(!resultQuantity){if(steps.length>192)throw fail('craft_batch_too_large',400);return {steps,resultQuantity:0,option};}
  const tipo=recipe.outputType || d.itemType(recipe.itemId),stats=await c.getTipoStats(tipo);
  if(!stats.exists || BigInt(stats.limit)-BigInt(stats.totalQuantity)<BigInt(resultQuantity) || BigInt(stats.perInvoiceLimit)<1n)throw fail('craft_result_capacity_unavailable');
  if(recipe.singleInvoice && BigInt(stats.perInvoiceLimit)<BigInt(resultQuantity))throw fail('craft_result_capacity_unavailable');
  const max=Math.min(recipe.outputMax || d.maxStack(recipe.itemId),Number(BigInt(stats.perInvoiceLimit)<BigInt(resultQuantity)?BigInt(stats.perInvoiceLimit):BigInt(resultQuantity)));
  if(!Number.isSafeInteger(max) || max<1)throw fail('craft_invalid_result_stack');
  for(let n=0;n<resultQuantity;n+=max)steps.push({kind:'mint',itemId:recipe.itemId,tipo,amount:Math.min(max,resultQuantity-n),manualId:recipe.singleInvoice?metadata.manualId:'cf:'+key.slice(0,32)+':'+steps.length,status:'planned'});
  if(steps.length>192)throw fail('craft_batch_too_large',400);
  return {steps,resultQuantity,option};
 }
 async function create(gp,body){
  // The single-pending-operation constraint must exist before the first debit,
  // including immediately after deployment or on a second backend instance.
  await Job.init();
  const wallet=String(gp.address).toLowerCase(),r=recipeMap.get(body.recipeId),q=Number(body.quantity),option=body.option==null?null:Number(body.option),ref=String(body.ref||'');
  if(!r || !Number.isSafeInteger(q)||q<1||q>(r.maxQuantity || 99)||!/^[A-Za-z0-9_-]{8,64}$/.test(ref))throw fail('craft_invalid_request',400);
  const key=crypto.createHash('sha256').update(wallet+':'+ref).digest('hex'),id='craft_'+key,fingerprint=JSON.stringify([r.id,q,option,...(r.farm?[d.serviceFingerprint(r,body)]:[])]);
  let previous=await Job.findById(id).lean();if(previous){if(previous.fingerprint!==fingerprint)throw fail('craft_reference_conflict');return previous;}
  if(!r.allowGhost && await d.ghost(gp))throw fail('fantasma',403);
  if(await d.level(gp)<r.level)throw fail('craft_level_required',403);
  const pending=await Job.findOne({wallet,active:true}).select('_id').lean();if(pending)throw fail('craft_previous_pending');
  const metadata=r.kind?await d.prepareService(gp,r,key,body):null;
  const prepared=await plan(wallet,r.farm&&d.planService?d.planService(r,metadata):r,q,option,key,metadata);await d.loadEconomy();
  const origin=r.kind==='vip'?'vip':'servicios',charge=r.payment || null;
  const fee=charge?charge.bronze:r.consume||r.free?0:d.price('craftear',r.itemId,prepared.resultQuantity);if(!Number.isSafeInteger(fee)||fee<(r.consume||r.free?0:1))throw fail('craft_invalid_price',503);
  const serviceId=gp.playerName+':craft_'+ref;
  try {return await d.transaction(async session=>{
   const old=await Job.findById(id).session(session).lean();if(old){if(old.fingerprint!==fingerprint)throw fail('craft_reference_conflict');return old;}
   const stats=await d.Stats.findOne({playerName:gp.playerName}).session(session).lean();
   const pay=!stats?null:charge?(Number.isSafeInteger(stats[charge.stat]) && stats[charge.stat]>=charge.amount?{oro:stats.oro,plata:stats.plata,bronce:stats.bronce,[charge.stat]:stats[charge.stat]-charge.amount}:null):d.planPayment(fee,stats);
   if(!pay)throw fail('saldo_insuficiente');
   if(fee){
    const paid=await d.Stats.updateOne({_id:stats._id,oro:stats.oro,plata:stats.plata,bronce:stats.bronce},{$set:{...pay,chainPendingSince:new Date()},$addToSet:{chainPending:{$each:['oro','plata','bronce']}}},{session});
    if(paid.matchedCount!==1)throw fail('craft_balance_changed');
    await d.Treasury.updateOne({_id:d.treasuryId},{$inc:{saldo:fee,retenidoServicios:fee,['ingresado.'+origin]:fee,['ingresos.'+origin]:1}},{session,upsert:true});
   }
   await d.Service.create([{_id:serviceId,playerName:gp.playerName,tipo:r.kind || 'craftear',itemId:r.itemId,cantidad:prepared.resultQuantity,bronce:fee,estado:'cobrado',serverOwned:true}],{session});
   if(fee)await d.Mov.create([{tesoro:'juego',tipo:'ingreso',origen:origin,bronce:fee,playerName:gp.playerName,detalle:'authoritative craft '+id}],{session});
   const [job]=await Job.create([{_id:id,wallet,playerName:gp.playerName,recipe:r.id,quantity:q,option:prepared.option,itemId:r.itemId,resultQuantity:prepared.resultQuantity,fingerprint,fee,serviceId,kind:r.kind || 'craft',metadata,charge,origin,privateSteps:prepared.steps,status:'prepared',active:true}],{session});
   if(r.farm && d.reserveService){const metadata=await d.reserveService(job.toObject(),gp,r,session);await Job.updateOne({_id:id},{$set:{metadata}},{session});job.metadata=metadata;}
   return job.toObject();
  });}catch(e){if(e.code===11000){previous=await Job.findById(id).lean();if(previous && previous.fingerprint===fingerprint)return previous;throw fail('craft_previous_pending');}throw e;}
 }
 async function stepReceipt(job,index,lease){
  const step=job.privateSteps[index],c=d.items(),provider=d.wallet().provider,relayer=String(d.wallet().address).toLowerCase();
  let method,args;
  if(step.kind==='take'){method='transferInvoice';args=[job.wallet,relayer,step.sourceId,step.amount,step.manualId];}
  else if(step.kind==='burn'){const source=job.privateSteps[step.sourceStep];if(source.status!=='confirmed'||!source.invoiceId)throw fail('craft_material_escrow_unconfirmed');method='decreaseInvoiceQuantity';args=[source.invoiceId,step.amount];}
  else {method='createInvoice';args=[job.wallet,step.tipo,step.amount,step.manualId];}
  const patch=async fields=>{const result=await Job.updateOne({_id:job._id,leaseToken:lease},{$set:Object.fromEntries(Object.entries(fields).map(([k,v])=>['privateSteps.'+index+'.'+k,v]))});if(result.matchedCount!==1)throw fail('craft_lease_changed');Object.assign(step,fields);};
  let receipt;
  if(step.txHash){
   receipt=await provider.getTransactionReceipt(step.txHash);
   if(!receipt){
    if(!step.rawTx)throw fail('craft_signed_intent_missing');
    const signed=ethers.Transaction.from(step.rawTx),expected=c.interface.encodeFunctionData(method,args);
    if(ethers.keccak256(step.rawTx)!==step.txHash || signed.from?.toLowerCase()!==relayer || signed.to?.toLowerCase()!==String(await c.getAddress()).toLowerCase() || signed.data!==expected || signed.value!==0n)throw fail('craft_signed_intent_mismatch');
    try{await provider.broadcastTransaction(step.rawTx);}catch(e){if(!/already known|nonce too low/i.test(String(e.message)))throw e;}
    receipt=await provider.waitForTransaction(step.txHash,1,120000);if(!receipt)throw fail('craft_confirmation_pending');
   }
  }else{
   const ticket='craft:'+job._id+':'+index;
   if(step.status!=='planned' && !(step.status==='signing' && step.nonceTicket===ticket))throw fail('craft_unsigned_step_requires_review');
   if(method!=='createInvoice'){
    const source=await c.getInvoice(args[method==='transferInvoice'?2:0]);
    const owner=step.kind==='take'?job.wallet:relayer;
    if(!source.active || String(source.owner).toLowerCase()!==owner || source.tipo!==step.tipo || BigInt(source.cantidad)<BigInt(step.amount))throw fail('craft_source_changed');
    if(step.kind==='burn' && BigInt(source.cantidad)!==BigInt(step.amount))throw fail('craft_escrow_quantity_changed');
   }
   const tx=await c[method].populateTransaction(...args);tx.gasPrice=await d.gasPrice();tx.gasLimit=(await provider.estimateGas({...tx,from:relayer}))*120n/100n;tx.chainId=(await provider.getNetwork()).chainId;
   await patch({status:'signing',nonceTicket:ticket});const nonce=await d.nonce(ticket);const rawTx=await d.wallet().signTransaction({...tx,nonce}),txHash=ethers.keccak256(rawTx);
   await patch({status:'signed',nonce,rawTx,txHash});const sent=await provider.broadcastTransaction(rawTx);receipt=await sent.wait(1,120000);
  }
  if(!receipt)throw fail('craft_confirmation_pending');
  if(Number(receipt.status)!==1){await patch({status:'failed'});throw fail('craft_transaction_reverted');}
  let proved=false,invoiceId=null;
  for(const log of receipt.logs || []){
   if(String(log.address).toLowerCase()!==String(await c.getAddress()).toLowerCase())continue;
   let event;try{event=c.interface.parseLog(log);}catch(_){continue;}
   if(step.kind==='take' && event?.name==='InvoiceTransferred' && Number(event.args.originalId)===step.sourceId && String(event.args.to).toLowerCase()===relayer && BigInt(event.args.amount)===BigInt(step.amount)){proved=true;invoiceId=Number(event.args.newId);}
   if(step.kind==='burn' && ((event?.name==='InvoiceQuantityDecreased' && BigInt(event.args.decreaseAmount)===BigInt(step.amount)) || event?.name==='InvoiceDeleted') && Number(event.args.id)===Number(args[0]))proved=true;
   if(step.kind==='mint' && event?.name==='InvoiceCreated' && String(event.args.manualId)===step.manualId && String(event.args.owner).toLowerCase()===job.wallet && BigInt(event.args.cantidad)===BigInt(step.amount)){proved=true;invoiceId=Number(event.args.id);}
  }
  if(!proved || step.kind!=='burn' && (!Number.isSafeInteger(invoiceId)||invoiceId<1))throw fail('craft_receipt_requires_review');
  await patch({status:'confirmed',invoiceId});return step;
 }
 async function execute(id){
  if(running.size>=16 || running.has(id))return Job.findById(id).lean();running.add(id);
  const token=crypto.randomUUID();let job;
  try{
   job=await Job.findOneAndUpdate({_id:id,active:true,$or:[{leaseUntil:{$lte:new Date()}},{leaseUntil:null}]},{$set:{leaseToken:token,leaseUntil:new Date(Date.now()+180000),status:'processing'}},{new:true}).select('+privateSteps').lean();
   if(!job)return Job.findById(id).lean();
   for(let index=0;index<job.privateSteps.length;index++){
    const step=job.privateSteps[index];if(step.status==='confirmed')continue;
    const owned=await Job.updateOne({_id:id,leaseToken:token},{$set:{leaseUntil:new Date(Date.now()+180000)}});if(owned.matchedCount!==1)throw fail('craft_lease_changed');
    await stepReceipt(job,index,token);
   }
   await d.transaction(async session=>{
    const done=await Job.updateOne({_id:id,leaseToken:token,active:true},{$set:{status:'completed',active:false,updatedAt:new Date(),error:''}},{session});if(done.modifiedCount!==1)return;
    const service=await d.Service.findOneAndUpdate({_id:job.serviceId,estado:'cobrado',serverOwned:true},{$set:{estado:'completado'}},{new:true,session}).lean();
    if(!service){
     // Legacy service summaries expire; the durable charged job does not.
     // A missing summary can be rebuilt, but a contradictory state requires review.
     if(await d.Service.exists({_id:job.serviceId}).session(session))throw fail('craft_fee_state_changed');
     await d.Service.create([{_id:job.serviceId,playerName:job.playerName,tipo:job.kind==='vip'?'vip':'craftear',itemId:job.itemId,cantidad:job.resultQuantity,bronce:job.fee,estado:'completado',serverOwned:true}],{session});
    }
    if(job.fee){const released=await d.Treasury.updateOne({_id:d.treasuryId,retenidoServicios:{$gte:job.fee}},{$inc:{retenidoServicios:-job.fee}},{session});if(released.matchedCount!==1)throw fail('craft_fee_reservation_missing');}
    const recipe=recipeMap.get(job.recipe);
    if(job.kind==='vip'||job.kind==='farm'){if(!d.completeService)throw fail('service_completion_unavailable');await d.completeService(job,session);}
    else if(recipe?.consume){if(!d.gain)throw fail('craft_consumer_unavailable');await d.gain(job.playerName,recipe.consume.stat,recipe.consume.gain*job.quantity,session);}
    else if(d.award)await d.award(job.playerName,'craft:'+id,30,'cocina',0,session);
   });
   if(job.kind!=='vip'){try{await d.persistInventory(job.wallet);}catch(_){}}
   const finished=await Job.findById(id).lean();
   if(finished?.status==='completed' && job.kind==='farm' && d.afterService){try{await d.afterService(finished);}catch(_){}}
   return finished;
  }catch(e){if(job)await Job.updateOne({_id:id,leaseToken:token,active:true},{$set:{status:'review',error:String(e.code || e.message).slice(0,160),
    needsManual:/craft_(unsigned_step|signed_intent|receipt|source_changed|escrow_quantity|transaction_reverted|fee_state)/.test(String(e.code||e.message)),retryAt:new Date(Date.now()+30000),updatedAt:new Date()}}).catch(()=>{});return Job.findById(id).lean();}
  finally{running.delete(id);if(job)await Job.updateOne({_id:id,leaseToken:token},{$set:{leaseUntil:new Date(0)},$unset:{leaseToken:1}}).catch(()=>{});}
 }
 async function describe(job){
  const stats=await d.Stats.findOne({playerName:job.playerName}).lean();
  const result={ok:job.status==='completed',operationId:job._id,status:job.status,recipeId:job.recipe,quantity:job.quantity,option:job.option,itemId:job.itemId,resultQuantity:job.resultQuantity,fee:job.fee,stats:stats && d.statsResponse(stats)};
  if(result.ok && job.kind==='vip'){if(d.describeService)Object.assign(result,await d.describeService(job));}
  else if(result.ok){
   const full=await Job.findById(job._id).select('+privateSteps').lean(),invoices=await d.freeInvoices(job.wallet),byId=new Map(invoices.map(i=>[Number(i.id),Number(i.cantidad)]));
   result.sourceInvoices=full.privateSteps.filter(s=>s.kind==='take').map(s=>({id:s.sourceId,remaining:byId.get(s.sourceId)||0}));
   result.rewards=full.privateSteps.filter(s=>s.kind==='mint'&&s.status==='confirmed'&&byId.has(s.invoiceId)).map(s=>({itemId:s.itemId,invoiceId:s.invoiceId,manualId:s.manualId,quantity:s.amount,newTotal:byId.get(s.invoiceId)}));
   const gp=await d.Player.findOne({playerName:job.playerName}).select('marketWriteAt').lean();result.inventoryLoadedAt=gp?.marketWriteAt || null;
  }
  if(job.kind==='farm' && d.describeService)Object.assign(result,await d.describeService(job));
  return result;
 }
 app.post('/api/craft/execute',strictLimiter,authMiddleware,csrfProtection,async(req,res)=>{
  try{const gp=await d.player(req);if(!gp)return res.status(403).json({error:'no_autorizado'});const prepared=await d.queue('inventory:'+String(gp.address).toLowerCase(),()=>create(gp,req.body || {}));
   const done=prepared.status==='completed'?prepared:await execute(prepared._id);res.set('Cache-Control','no-store');return res.status(done.status==='completed'?200:202).json(await describe(done));
  }catch(e){return res.status(e.status || 503).json({error:e.code || 'craft_unavailable',message:'Crafting could not be confirmed. Check pending crafts before sending another reference.'});}
 });
 app.get('/api/craft/pending',apiLimiter,authMiddleware,async(req,res)=>{try{const wallet=String(req.user.address).toLowerCase(),rows=await Job.find({wallet,active:true}).select('_id recipe quantity option status itemId resultQuantity fee createdAt').limit(5).lean();res.set('Cache-Control','no-store');res.json({ok:true,rows});}catch(_){res.status(503).json({error:'craft_status_unavailable'});}});
 app.post('/api/craft/reconcile',strictLimiter,authMiddleware,csrfProtection,async(req,res)=>{try{const job=await Job.findOne({_id:String(req.body.operationId),wallet:String(req.user.address).toLowerCase()}).lean();if(!job)return res.status(404).json({error:'craft_not_found'});const done=await execute(job._id);res.set('Cache-Control','no-store');res.status(done.status==='completed'?200:202).json(await describe(done));}catch(_){res.status(503).json({error:'craft_status_unavailable'});}});
 app.get('/api/admin/craft/pending',adminAuth,apiLimiter,async(req,res)=>{try{const rows=await Job.find({active:true}).select('_id wallet playerName recipe quantity status fee error createdAt').sort({createdAt:1}).limit(50).maxTimeMS(5000).lean();res.set('Cache-Control','no-store');res.json({ok:true,rows});}catch(_){res.status(503).json({error:'craft_review_unavailable'});}});
 app.post('/api/admin/craft/reconcile',adminAuth,strictLimiter,csrfProtection,async(req,res)=>{try{const id=String(req.body.operationId || '');if(!/^craft_[a-f0-9]{64}$/.test(id))return res.status(400).json({error:'invalid_operation'});const job=await execute(id);if(!job)return res.status(404).json({error:'craft_not_found'});res.set('Cache-Control','no-store');res.json({ok:job.status==='completed',status:job.status});}catch(_){res.status(503).json({error:'craft_review_unavailable'});}});
 // Only an untouched job can be refunded. Signed or consumed steps must be
 // reconciled first; absence of an RPC response never proves non-execution.
 async function cancelUntouched(id){
  const token=crypto.randomUUID(),job=await Job.findOneAndUpdate({_id:id,active:true,$or:[{leaseUntil:{$lte:new Date()}},{leaseUntil:null}]},{$set:{leaseToken:token,leaseUntil:new Date(Date.now()+180000)}},{new:true}).select('+privateSteps').lean();
  if(!job)throw fail('craft_busy_or_settled');
  try{
   if(job.privateSteps.some(step=>step.status!=='planned'||step.txHash||step.rawTx))throw fail('craft_must_reconcile');
   await d.transaction(async session=>{
    const changed=await Job.updateOne({_id:id,active:true,leaseToken:token},{$set:{status:'cancelled',active:false,updatedAt:new Date()}},{session});if(changed.modifiedCount!==1)throw fail('craft_lease_changed');
    if(job.kind==='farm' && d.cancelService)await d.cancelService(job,session);
    const service=await d.Service.findOneAndUpdate({_id:job.serviceId,serverOwned:true,estado:'cobrado',devuelto:{$ne:true}},{$set:{estado:'devuelto',devuelto:true,tDevuelto:new Date()}},{new:true,session}).lean();
    if(!service){if(await d.Service.exists({_id:job.serviceId}).session(session))throw fail('craft_fee_state_changed');await d.Service.create([{_id:job.serviceId,playerName:job.playerName,tipo:job.kind==='vip'?'vip':'craftear',itemId:job.itemId,cantidad:job.resultQuantity,bronce:job.fee,estado:'devuelto',devuelto:true,serverOwned:true,tDevuelto:new Date()}],{session});}
    if(job.fee){
     const treasury=await d.Treasury.updateOne({_id:d.treasuryId,saldo:{$gte:job.fee},retenidoServicios:{$gte:job.fee}},{$inc:{saldo:-job.fee,retenidoServicios:-job.fee,['ingresado.'+(job.origin || 'servicios')]:-job.fee}},{session});if(treasury.matchedCount!==1)throw fail('craft_fee_reservation_missing');
     const refund=await d.Stats.updateOne({playerName:job.playerName},{$inc:{[job.charge?.stat || 'bronce']:job.charge?.amount || job.fee},$set:{chainPendingSince:new Date()},$addToSet:{chainPending:job.charge?.stat || 'bronce'}},{session});if(refund.matchedCount!==1)throw fail('craft_player_missing');
     await d.Mov.create([{tesoro:'juego',tipo:'ajuste',origen:job.origin || 'servicios',bronce:-job.fee,playerName:job.playerName,detalle:'unstarted craft cancelled '+id}],{session});
    }
   });return {ok:true,status:'cancelled'};
  }finally{await Job.updateOne({_id:id,leaseToken:token},{$set:{leaseUntil:new Date(0)},$unset:{leaseToken:1}});}
 }
 app.post('/api/admin/craft/cancel-unstarted',adminAuth,strictLimiter,csrfProtection,async(req,res)=>{try{const id=String(req.body.operationId||'');if(!/^craft_[a-f0-9]{64}$/.test(id))return res.status(400).json({error:'invalid_operation'});res.json(await cancelUntouched(id));}catch(e){res.status(e.status||503).json({error:e.code||'craft_review_unavailable'});}});
 let sweeping=false;
 async function sweep(){if(sweeping || mongoose.connection.readyState!==1)return;sweeping=true;try{const jobs=await Job.find({active:true,needsManual:{$ne:true},status:{$in:['prepared','processing','review']},$or:[{retryAt:{$lte:new Date()}},{retryAt:null}]}).select('_id').sort({createdAt:1}).limit(5).lean();for(const job of jobs)await execute(job._id);}finally{sweeping=false;}}
 return {Job,create,execute,describe,materials,sweep,cancelUntouched,isCraftedType:tipo=>outputTypes.has(tipo)};
};
