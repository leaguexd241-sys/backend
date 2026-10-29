'use strict';
// One durable intent per stats invoice. The target is absolute, while the
// signed on-chain operation is a delta: never recompute that delta while an
// earlier signed intent can still execute.
module.exports=function createStatChainJournal(d){
 const {mongoose,ethers,crypto}=d;
 const schema=new mongoose.Schema({_id:String,stat:String,invoiceId:Number,chainId:String,to:String,status:String,
  current:Number,target:Number,ticket:String,tx:{type:mongoose.Schema.Types.Mixed,select:false},raw:{type:String,select:false},hash:String,
  lease:String,leaseUntil:Date,updatedAt:Date},{collection:'authoritative_stat_intents',versionKey:false});
 const Intent=mongoose.models.AuthoritativeStatIntent || mongoose.model('AuthoritativeStatIntent',schema),running=new Set();
 const fail=code=>Object.assign(Error(code),{code});
 async function bounded(fn,ms=15000){let timer;try{return await Promise.race([Promise.resolve().then(fn),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('stat_rpc_pending')),ms);timer.unref?.();})]);}finally{clearTimeout(timer);}}
 async function apply(contract,stat,invoiceId,target,gasPrice){
  if(!Number.isSafeInteger(invoiceId)||invoiceId<1||!Number.isSafeInteger(target)||target<1)throw fail('stat_invalid_target');
  await Intent.init();const wallet=d.wallet(),provider=wallet.provider,to=String(await bounded(()=>contract.getAddress())).toLowerCase(),chainId=String((await bounded(()=>provider.getNetwork())).chainId);
  const id=crypto.createHash('sha256').update(chainId+':'+to+':'+invoiceId).digest('hex');
  if(running.has(id)||running.size>=16)return {ok:false,chainQty:null,pending:true,error:'stat_busy'};
  running.add(id);const lease=crypto.randomUUID();let row;
  try{
   try{row=await Intent.findOneAndUpdate({_id:id,$or:[{leaseUntil:{$lte:new Date()}},{leaseUntil:null}]},{$set:{lease,leaseUntil:new Date(Date.now()+180000)},$setOnInsert:{stat,invoiceId,to,chainId,status:'idle'}},{upsert:true,new:true}).select('+tx +raw').lean();}
   catch(e){if(e.code===11000)return {ok:false,chainQty:null,pending:true,error:'stat_busy'};throw e;}
   if(row.stat!==stat || row.invoiceId!==invoiceId || row.to!==to || row.chainId!==chainId)throw fail('stat_intent_identity_mismatch');
   const patch=async fields=>{const changed=await Intent.updateOne({_id:id,lease},{$set:{...fields,updatedAt:new Date()}});if(changed.matchedCount!==1)throw fail('stat_lease_changed');Object.assign(row,fields);};
   const quantity=async()=>{const invoice=await bounded(()=>contract.getInvoice(invoiceId));if(!invoice?.active || invoice.tipo!==stat)throw fail('stat_invoice_not_active');const n=Number(invoice.cantidad);if(!Number.isSafeInteger(n)||n<1)throw fail('stat_invoice_quantity_invalid');return n;};
   if(['idle','confirmed','reverted'].includes(row.status)){
    const current=await quantity();if(current===target)return {ok:true,chainQty:current};
    const method=target>current?'increaseInvoiceQuantity':'decreaseInvoiceQuantity',delta=Math.abs(target-current);
    const unsigned=await bounded(()=>contract[method].populateTransaction(invoiceId,delta));
    const estimate=await bounded(()=>provider.estimateGas({...unsigned,from:wallet.address,gasPrice}));
    const tx={to,data:unsigned.data,value:'0',gasLimit:String(BigInt(estimate)*120n/100n),gasPrice:String(gasPrice),chainId};
    await patch({status:'planned',current,target,ticket:'stat:'+id+':'+crypto.randomUUID(),tx,raw:null,hash:null});
   }
   if(!['planned','signed'].includes(row.status) || !row.ticket || !row.tx)throw fail('stat_intent_requires_review');
   const method=row.target>row.current?'increaseInvoiceQuantity':'decreaseInvoiceQuantity',expected=contract.interface.encodeFunctionData(method,[invoiceId,Math.abs(row.target-row.current)]);
   if(row.tx.to!==to || row.tx.data!==expected || String(row.tx.chainId)!==chainId || row.tx.value!=='0')throw fail('stat_unsigned_intent_mismatch');
   if(row.status==='planned'){
    const nonce=await d.nonce(row.ticket),raw=await wallet.signTransaction({...row.tx,nonce});
    await patch({status:'signed',raw,hash:ethers.keccak256(raw)});
   }
   const signed=ethers.Transaction.from(row.raw);
   if(ethers.keccak256(row.raw)!==row.hash || signed.from?.toLowerCase()!==String(wallet.address).toLowerCase() || signed.to?.toLowerCase()!==to || String(signed.chainId)!==chainId || signed.data!==expected || signed.value!==0n)throw fail('stat_signed_intent_mismatch');
   let receipt=await bounded(()=>provider.getTransactionReceipt(row.hash));
   if(!receipt){
    try{await bounded(()=>provider.broadcastTransaction(row.raw));}catch(e){if(!/already known|nonce too low/i.test(String(e.message)))throw e;}
    receipt=await provider.waitForTransaction(row.hash,1,90000);if(!receipt)throw fail('stat_confirmation_pending');
   }
   if(Number(receipt.status)!==1){await patch({status:'reverted'});return {ok:false,chainQty:await quantity(),error:'stat_transaction_reverted'};}
   // Check the effect again; do not report the new caller's target as settled
   // merely because an older, already signed target has just recovered.
   await patch({status:'confirmed'});const chainQty=await quantity();
   return {ok:chainQty===target,chainQty,...(chainQty===target?{}:{error:'stat_prior_intent_settled'})};
  }catch(e){d.onError?.(e);return {ok:false,chainQty:null,pending:!!row && ['planned','signed'].includes(row.status),error:String(e.shortMessage || e.code || e.message).slice(0,240)};}
  finally{running.delete(id);if(row)await Intent.updateOne({_id:id,lease},{$set:{leaseUntil:new Date(0)},$unset:{lease:1}}).catch(()=>{});}
 }
 return {Intent,apply};
};
