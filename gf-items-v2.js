/* ===========================================================================
 * gf-items-v2.js — LOS OBJETOS NUEVOS DEL JUEGO                    (2026-11-02)
 * ===========================================================================
 *
 * Panes de Martha, tortas de Tobias, ingredientes, leche, armas, cañas, peces,
 * construcciones de las Lands y monturas. Es UN solo catálogo que comparten el
 * servidor y el juego, como gf-crop-catalog.js y con su misma forma: al cargarse
 * se FUNDE con el de las plantas (`fusionar`), y así cada sitio que ya leía
 * ese catálogo (tipos on-chain, pilas, niveles, precios, reglas del suelo, P2P,
 * nombres, comida) conoce los objetos nuevos sin tocarlo uno a uno.
 *
 * Las tablas del contrato se crean solas la primera vez que hacen falta
 * (`plantKey`, como las de los cultivos): no se gasta gas en 200 tablas al
 * arrancar, pero nadie tiene que crearlas a mano.
 *
 * LOS PRECIOS NO ESTÁN A MANO en lo cocinado. Salen de lo que cuestan sus
 * ingredientes, con dos reglas que vigila tools/items-v2.test.cjs:
 *   · No hay dinero gratis: comprar los ingredientes, cocinar y vender a la tienda
 *     da siempre pérdida, aunque la demanda (±10 %) juegue a favor.
 *   · Cocinar compensa: lo hecho con la cosecha propia vale más que la cosecha, y
 *     comprarlo hecho sale más caro que hacerlo.
 * La inflación y la demanda las pone el servidor encima (eco2PrecioTienda): esto
 * es solo el precio base.
 * ======================================================================== */
(function(root,factory){
 'use strict';
 const enNode=typeof module==='object'&&module.exports;
 const base=enNode?require('./gf-crop-catalog'):root.GFPlantCatalog;
 const cat=factory(base);
 if(enNode)module.exports=cat;
 else{root.GFItemsV2=cat;if(base)root.GFPlantCatalog=cat.fusionar(base);}
})(typeof globalThis!=='undefined'?globalThis:this,function(base){
 'use strict';
 const RUTA='./Game/newpro/objetosv2/';
 const items={},food={},levels={},itemTypes={},maxStacks={},shopPrices={},referenceValues={},names={},tables=[],consumables=[],recipes=[];
 const shop={alimentos:[],equipo:[],construccion:[],monturas:[]};
 // Lo que ya existía y entra en las recetas: [compra, venta, nivel] (TIENDA_PRECIOS y GF_NIVEL_OBJETO).
 const VIEJOS={zanahoria_buena:[20,14,1],tomate_buena:[28,20,3],fresa_buena:[40,28,3],trigo_buena:[13,9,5],calabaza_buena:[48,34,6]};

 function alta(id,name,kind,src,level,maxStack,buy,sell,extra){
  items[id]={src,maxStack,tipo:id,name,level,kind,...(extra||{})};
  levels[id]=level;itemTypes[id]=id;maxStacks[id]=maxStack;names[id]=[name,src];
  shopPrices[id]=[buy,sell,'p'];referenceValues[id]=Math.max(1,sell)*1000;
  tables.push({tipo:id,limit:1000000,perInvoiceLimit:maxStack,para:name+' · '+kind,plantKey:'v2',nivel:level});
 }
 function ficha(id,categoria,descripcion,extra){
  const it=items[id],p=shopPrices[id];
  return {id,name:it.name,image:it.src,buyPrice:p[0],sellPrice:p[1],currency:'silver',categoria,comision:5,limiteDiario:0,nivelRequerido:it.level,descripcion,...(extra||{})};
 }
 function precioDe(id){
  if(VIEJOS[id])return {compra:VIEJOS[id][0],venta:VIEJOS[id][1],nivel:VIEJOS[id][2]};
  if(items[id])return {compra:shopPrices[id][0],venta:shopPrices[id][1],nivel:levels[id]};
  if(base&&base.shopPrices[id])return {compra:base.shopPrices[id][0],venta:base.shopPrices[id][1],nivel:base.levels[id]};
  throw new Error('gf-items-v2: ingrediente desconocido '+id);
 }

 // ── INGREDIENTES ─────────────────────────────────────────────────────────────
 // [id, nombre, nivel, compra, venta, pila, de dónde sale]
 const INGREDIENTES=[
  ['levadura','Yeast',3,6,2,50,'Makes the dough rise. Sold by Martha.'],
  ['azucar','Sugar',3,8,3,50,'For anything sweet. Sold by Martha and Tobias.'],
  ['huevo','Eggs',4,10,4,50,'Fresh eggs for dough and sponge. Sold by Martha and Tobias.'],
  ['harina','Flour',5,30,12,50,'Grind two Fresh Wheat at Martha\'s, or buy it from her.'],
  ['chocolate','Chocolate',8,24,10,50,'A bar of dark chocolate. Sold by Tobias.'],
  ['balde_leche','Bucket of Milk',2,25,10,5,'Milk the cow in the village with an Empty Bucket. Drink it for a little life, or use it in recipes.'],
  ['mantequilla','Butter',6,18,6,50,'Churn a Bucket of Milk at Martha\'s, or buy it.'],
  ['crema','Cream',6,16,5,50,'Whip a Bucket of Milk at Tobias\'s, or buy it.']
 ];
 for(const [id,name,nivel,buy,sell,pila,desc] of INGREDIENTES){
  alta(id,name,'ingrediente',RUTA+'comida/'+id+'.png',nivel,pila,buy,sell);
  shop.alimentos.push(ficha(id,'alimentos',desc,{soloVenta:true}));
 }
 // La leche se bebe: sube un poco la vida y devuelve el cubo vacío.
 const VIDA_LECHE=8;
 consumables.push({id:'consume_balde_leche',itemId:'balde_vacio',quantity:1,level:0,resources:[{itemId:'balde_leche',quantity:1}],consume:{stat:'vida',gain:VIDA_LECHE}});
 // Ordeñar: un cubo vacío se vuelve de leche. Sin comisión, y solo desde su ruta (suerte y espera en el servidor).
 const RECETA_ORDENAR={id:'ordenar_vaca',itemId:'balde_leche',quantity:1,level:2,resources:[{itemId:'balde_vacio',quantity:1}],options:null,free:true,internal:true,maxQuantity:1};
 recipes.push(RECETA_ORDENAR);

 // ── RECETAS DE INGREDIENTES ─────────────────────────────────────────────────
 const DEL_CUBO=[{itemId:'balde_vacio',quantity:1}];
 const BASICAS=[
  ['harina','martha',1,{trigo_buena:2},null],
  ['mantequilla','martha',3,{balde_leche:1},DEL_CUBO],
  ['crema','tobias',3,{balde_leche:1},DEL_CUBO]
 ];
 function receta(id,itemId,npc,qty,ing,level,devuelve){
  const r={id,itemId,quantity:qty,level,npc,resources:Object.entries(ing).map(([i,q])=>({itemId:i,quantity:q})),options:null};
  if(devuelve)r.returns=devuelve;
  recipes.push(r);return r;
 }
 for(const [id,npc,qty,ing,dev] of BASICAS)receta('receta_'+id,id,npc,qty,ing,levels[id],dev);

 // ── LO COCINADO ──────────────────────────────────────────────────────────────
 // [id, nombre, nivel mínimo, cuántos salen, ingredientes, ¿devuelve cubo?]
 const PANES=[
  ['pan_plano','Flatbread',5,2,{trigo_buena:3}],
  ['pan_hogaza','Country Loaf',5,2,{harina:2,levadura:1}],
  ['pan_molde','Sandwich Loaf',6,2,{harina:2,levadura:1,mantequilla:1}],
  ['pan_zanahoria','Carrot Loaf',6,2,{harina:2,levadura:1,zanahoria_buena:3}],
  ['pan_baguette','Baguette',7,3,{harina:3,levadura:1}],
  ['pan_bollo','Milk Bun',7,3,{harina:2,azucar:1,balde_leche:1},DEL_CUBO],
  ['pan_integral','Whole Wheat Loaf',8,2,{trigo_buena:4,levadura:1}],
  ['pan_tomate','Tomato Focaccia',8,2,{harina:2,levadura:1,tomate_buena:2}],
  ['pan_calabaza','Pumpkin Loaf',8,2,{harina:2,levadura:1,calabaza_buena:2}],
  ['pan_pretzel','Pretzel',9,3,{harina:2,mantequilla:1,levadura:1}],
  ['pan_croissant','Butter Croissant',10,3,{harina:2,mantequilla:2,azucar:1}],
  ['pan_trenza','Egg Braid',10,3,{harina:3,huevo:2,levadura:1}],
  ['pan_chocolate','Chocolate Brioche',12,2,{harina:2,chocolate:1,mantequilla:1,huevo:1}],
  ['pan_cebolla','Onion Roll',14,3,{harina:2,levadura:1,cebolla_buena:1}],
  ['pan_ajo','Garlic Bread',17,2,{harina:2,mantequilla:1,ajo_buena:1}],
  ['pan_espinaca','Spinach Twist',19,2,{harina:2,huevo:1,espinaca_buena:1}],
  ['pan_romero','Rosemary Focaccia',63,3,{harina:3,levadura:1,romero_buena:1}],
  ['pan_patata','Potato Ring',77,3,{harina:2,huevo:1,patata_buena:1}],
  ['pan_manzana','Apple Spiral',121,2,{harina:2,azucar:1,mantequilla:1,manzana_buena:1}],
  ['pan_platano','Banana Bread',133,2,{harina:2,azucar:1,huevo:1,platano_buena:1}]
 ];
 const TORTAS=[
  ['torta_cupcake','Cream Cupcake',8,2,{harina:1,crema:1,azucar:1}],
  ['torta_vainilla','Vanilla Sponge',9,2,{harina:2,huevo:2,azucar:2}],
  ['torta_fresa','Strawberry Cake',10,2,{harina:2,huevo:2,crema:1,fresa_buena:3}],
  ['torta_zanahoria','Carrot Cake',10,2,{harina:2,huevo:2,azucar:1,zanahoria_buena:4}],
  ['torta_calabaza','Pumpkin Pie',11,2,{harina:2,mantequilla:1,azucar:1,calabaza_buena:3}],
  ['torta_chocolate','Chocolate Cake',12,2,{harina:2,huevo:2,chocolate:2,crema:1}],
  ['torta_rollo','Cream Roll',13,2,{harina:1,huevo:2,crema:2,azucar:1}],
  ['torta_boda','Royal Tier Cake',40,1,{harina:4,huevo:4,crema:3,azucar:3,fresa_buena:4,chocolate:2}],
  ['torta_melon','Melon Chiffon',92,2,{harina:2,huevo:2,crema:1,melon_buena:1}],
  ['torta_sandia','Watermelon Cake',94,2,{harina:2,crema:2,azucar:1,sandia_buena:1}],
  ['torta_jengibre','Ginger Bundt',99,2,{harina:2,huevo:2,azucar:1,jengibre_buena:1}],
  ['torta_limon','Lemon Tart',116,2,{harina:2,mantequilla:1,azucar:2,limon_buena:1}],
  ['torta_naranja','Orange Bundt',118,2,{harina:2,huevo:2,azucar:1,naranja_buena:1}],
  ['torta_manzana','Apple Pie',121,2,{harina:2,mantequilla:1,azucar:1,manzana_buena:1}],
  ['torta_pera','Pear Tart',123,2,{harina:2,mantequilla:1,azucar:1,pera_buena:1}],
  ['torta_ciruela','Plum Cake',126,2,{harina:2,huevo:2,crema:1,ciruela_buena:1}],
  ['torta_melocoton','Peach Slice',128,2,{harina:2,crema:2,azucar:1,melocoton_buena:1}],
  ['torta_higo','Fig Slice',131,2,{harina:2,crema:1,azucar:1,higo_buena:1}],
  ['torta_platano','Banana Cream Cake',133,2,{harina:2,crema:2,huevo:1,platano_buena:1}],
  ['torta_mango','Mango Cheesecake',138,2,{harina:1,crema:3,azucar:1,mango_buena:1}]
 ];
 function cocinado(lista,npc,factorComida){
  for(const [id,name,minimo,qty,ing,dev] of lista){
   let cBuy=0,cSell=0,nivel=minimo;
   for(const [i,q] of Object.entries(ing)){const p=precioDe(i);cBuy+=p.compra*q;cSell+=p.venta*q;nivel=Math.max(nivel,p.nivel);}
   cBuy/=qty;cSell/=qty;
   const sell=Math.max(1,Math.floor(Math.min(cSell*1.25,cBuy*.85))),buy=Math.ceil(cBuy*1.35);
   const gain=Math.max(6,Math.min(45,Math.round((4+2.3*Math.sqrt(cSell))*factorComida)));
   alta(id,name,npc==='martha'?'pan':'torta',RUTA+'comida/'+id+'.png',nivel,20,buy,sell);
   food[id]=gain;
   consumables.push({id:'consume_'+id,itemId:null,quantity:0,level:nivel,resources:[{itemId:id,quantity:1}],consume:{stat:'comida',gain}});
   receta('receta_'+id,id,npc,qty,ing,nivel,dev);
   shop.alimentos.push(ficha(id,'alimentos',(npc==='martha'?'Baked by Martha':'Made by Tobias')+'. Restores '+gain+' food.',{soloVenta:true}));
  }
 }
 cocinado(PANES,'martha',1);
 cocinado(TORTAS,'tobias',1.2);

 // Lo que vende cada uno en su panel.
 const NPC_VENDE={
  martha:{nombre:'Martha the Baker',saludo:'Bring me the ingredients and I will bake for you. Or just buy a loaf, dear.',
   venta:[...PANES.map(p=>p[0]),'harina','levadura','azucar','huevo','mantequilla','balde_leche'],
   recetas:recipes.filter(r=>r.npc==='martha').map(r=>r.id)},
  tobias:{nombre:'Tobias the Pastry Chef',saludo:'Every cake starts with good butter and a patient hand. What can I make you?',
   venta:[...TORTAS.map(p=>p[0]),'crema','chocolate','azucar','huevo','mantequilla'],
   recetas:recipes.filter(r=>r.npc==='tobias').map(r=>r.id)}
 };

 // ── LAS ARMAS Y LAS CAÑAS ────────────────────────────────────────────────────
 // [id, nombre, nivel, compra, daño, alcance, enfriamiento, color, daño PvP]
 const ESPADAS=[
  ['espada_piedra','Stone Sword',3,150,16,48,470,0xb5b5ad,5],
  ['espada_acero','Steel Sword',10,1000,40,56,370,0xcfd8e2,11],
  ['espada_plata','Silver Rapier',13,1500,48,60,340,0xeef2f7,12],
  ['espada_oro','Golden Sword',16,2300,56,56,380,0xf5d656,13],
  ['espada_hielo','Frost Blade',20,3400,66,58,360,0xb8ecf7,15],
  ['espada_fuego','Fire Scimitar',24,5000,78,60,350,0xff8a3a,17],
  ['espada_sombra','Shadow Blade',28,7500,92,62,330,0xa58ae0,19],
  ['espada_dragon','Dragon Greatsword',33,11000,110,66,380,0xe05a4a,22]
 ];
 const ARCOS=[
  ['arco_corto','Short Bow',2,120,10,260,600,0xf2e6c8,4],
  ['arco_cazador','Hunter Bow',8,800,20,320,620,0xd9c9a0,6],
  ['arco_largo','Long Bow',12,1600,28,360,680,0xf2e6c8,8],
  ['arco_hielo','Frost Bow',18,3000,38,370,640,0xb8ecf7,10],
  ['arco_elfico','Elven Bow',24,5500,50,390,600,0xc9e68a,12],
  ['arco_dragon','Dragon Bow',31,10000,66,410,640,0xffb05a,14]
 ];
 const armasJuego={},pvpDano={},pvpAlcance={};
 for(const [id,name,nivel,buy,dano,alcance,enfria,color,pvp] of ESPADAS){
  const src=RUTA+'armas/'+id+'.png';
  alta(id,name,'arma',src,nivel,1,buy,Math.floor(buy/2),{arma:{dano}});
  armasJuego[id]={nombre:name,dano,alcance,enfria,color,src};pvpDano[id]=pvp;
  shop.equipo.push(ficha(id,'equipo','Level '+nivel+' blade. Equip it and press SPACE to swing. Damage '+dano+'.',{tabla:id,tablaSola:true}));
 }
 for(const [id,name,nivel,buy,dano,alcance,enfria,color,pvp] of ARCOS){
  const src=RUTA+'armas/'+id+'.png';
  alta(id,name,'arma',src,nivel,1,buy,Math.floor(buy/2),{arma:{dano}});
  armasJuego[id]={nombre:name,dano,alcance,enfria,color,src,distancia:'flecha'};pvpDano[id]=pvp;pvpAlcance[id]=alcance*2;
  shop.equipo.push(ficha(id,'equipo','Level '+nivel+' bow. Equip it and press SPACE to shoot. Damage '+dano+', range '+alcance+'.',{tabla:id,tablaSola:true}));
 }
 // [id, nombre, nivel, compra, suerte]: la suerte acerca la tirada a los peces raros y acorta la espera.
 const CANAS=[
  ['cana_bambu','Bamboo Rod',3,300,.05],['cana_roble','Oak Rod',7,700,.10],['cana_acero','Steel Rod',11,1400,.16],
  ['cana_plata','Silver Rod',15,2400,.22],['cana_oro','Golden Rod',20,4000,.30],['cana_leyenda','Legend Rod',27,8000,.40]
 ];
 const canasSuerte={};
 for(const [id,name,nivel,buy,suerte] of CANAS){
  alta(id,name,'cana',RUTA+'armas/'+id+'.png',nivel,1,buy,Math.floor(buy/2),{suerte});
  canasSuerte[id]=suerte;
  shop.equipo.push(ficha(id,'equipo','Level '+nivel+' fishing rod. Rare fish bite '+Math.round(suerte*100)+'% more often and sooner. It never breaks.',{tabla:id,tablaSola:true}));
 }

 // ── LOS PECES NUEVOS ─────────────────────────────────────────────────────────
 // [id, nombre, nivel, venta, comida, peso (probabilidad relativa), exp, dificultad]
 const PECES=[
  ['pes15','Polar Cod',1,15,7,.10,14,{tam:.44,vel:.30,nervio:.65,mengua:0,rafaga:0}],
  ['pes17','Sea Bass',2,24,9,.07,20,{tam:.38,vel:.40,nervio:.90,mengua:.05,rafaga:.06}],
  ['pes16','Gilthead Bream',3,28,10,.06,22,{tam:.36,vel:.42,nervio:1.0,mengua:.08,rafaga:.08}],
  ['pes18','Red Mullet',4,30,11,.05,24,{tam:.34,vel:.46,nervio:1.1,mengua:.10,rafaga:.10}],
  ['pes22','Discus Fish',6,55,12,.04,30,{tam:.32,vel:.50,nervio:1.2,mengua:.12,rafaga:.14}],
  ['pes20','Red Piranha',8,62,13,.03,34,{tam:.29,vel:.60,nervio:1.5,mengua:.16,rafaga:.20}],
  ['pes19','Barracuda',10,70,20,.025,40,{tam:.30,vel:.52,nervio:1.3,mengua:.20,rafaga:.16}],
  ['pes21','Bluefin Tuna',12,95,24,.02,50,{tam:.27,vel:.62,nervio:1.4,mengua:.22,rafaga:.24}],
  ['pes23','Blue Marlin',15,180,30,.008,80,{tam:.25,vel:.68,nervio:1.55,mengua:.26,rafaga:.28}],
  ['pes24','Swordfish',18,240,35,.004,110,{tam:.24,vel:.72,nervio:1.7,mengua:.28,rafaga:.30}]
 ];
 const pesca={};
 for(const [id,name,nivel,venta,comida,peso,exp,dif] of PECES){
  alta(id,name,'pez','./Game/Objetos/pesca/'+id+'.png',nivel,20,0,venta);
  food[id]=comida;
  consumables.push({id:'consume_'+id,itemId:null,quantity:0,level:0,resources:[{itemId:id,quantity:1}],consume:{stat:'comida',gain:comida}});
  shop.alimentos.push(ficha(id,'alimentos','Fished in the rivers and lakes. Restores '+comida+' food.',{soloVenta:true,comision:2}));
  pesca[id]={peso,exp,dificultad:dif};
 }

 // ── LO QUE SE CONSTRUYE EN LAS LANDS ─────────────────────────────────────────
 // [tipo, nombre, ancho, alto, nivel, compra, ancho que frena (px; si no, casi todo el dibujo)]
 const OBRAS=[
  ['valla','Picket Fence',2,1,2,60],['poste_senal','Signpost',2,2,2,70,12],['muro','Stone Wall',2,1,3,90],['buzon','Mailbox',2,2,3,100,12],
  ['parterre','Flower Bed',3,2,3,120],['banco','Park Bench',3,2,3,180],['lena','Wood Pile',3,2,4,110],['heno','Hay Stack',3,3,5,140],
  ['hoguera','Campfire',2,2,5,160],['abrevadero','Water Trough',3,2,6,240],['farol','Street Lamp',2,2,6,260,14],['pajarera','Bird House',2,2,7,220,14],
  ['caseta','Dog House',3,3,7,400],['colmena','Bee Hive',2,2,9,520],['pozo','Stone Well',3,3,10,900],['puesto','Market Stall',4,3,12,1400],
  ['estatua','Hero Statue',2,2,15,2400],['fuente','Garden Fountain',4,4,18,3600],['cenador','Garden Gazebo',5,5,22,6000],['invernadero','Greenhouse',6,5,26,9000]
 ];
 const obras={},colocables={};
 for(const [tipo,name,ancho,alto,nivel,buy,freno] of OBRAS){
  const id='obra_'+tipo,src=RUTA+'construcciones/'+id+'.png';
  alta(id,name,'obra',src,nivel,10,buy,Math.floor(buy/2));
  obras[id]={ancho,alto,itemId:id,tablaItem:id,tablaConstruccion:null};
  colocables[id]={nombre:name,icono:src,ancho,alto,objeto:true,...(freno?{base:freno}:{})};
  shop.construccion.push(ficha(id,'construccion','Build it on your island (Lands → Build). Needs a '+ancho+' x '+alto+' spot. Dig it up with the shovel to get it back.',{tabla:id,tablaSola:true}));
 }

 // ── LAS MONTURAS ─────────────────────────────────────────────────────────────
 // [id, nombre, especie, nivel, velocidad, silla por vista]. Salen de Game/newpro/objetosv2/catalogo.json.
 const MONTURAS=[
  ["montura_001","Chestnut Horse","horse",14,1.4,[37.0,37.0,37.0]],
  ["montura_002","Black Horse","horse",14,1.4,[37.0,37.0,37.0]],
  ["montura_003","White Horse","horse",15,1.4,[37.0,37.0,37.0]],
  ["montura_004","Palomino Horse","horse",15,1.4,[37.0,37.0,37.0]],
  ["montura_005","Dapple Grey Horse","horse",16,1.4,[37.0,37.0,37.0]],
  ["montura_006","Bay Pony","pony",6,1.22,[31.2,31.2,31.2]],
  ["montura_007","Cream Pony","pony",6,1.22,[31.2,31.2,31.2]],
  ["montura_008","Blue Roan Pony","pony",7,1.22,[31.2,31.2,31.2]],
  ["montura_009","Rose Pony","pony",7,1.22,[31.2,31.2,31.2]],
  ["montura_010","Sooty Pony","pony",8,1.22,[31.2,31.2,31.2]],
  ["montura_011","Grey Donkey","donkey",5,1.2,[33.2,33.2,33.2]],
  ["montura_012","Brown Donkey","donkey",5,1.2,[33.2,33.2,33.2]],
  ["montura_013","Silver Donkey","donkey",6,1.2,[33.2,33.2,33.2]],
  ["montura_014","Dusty Donkey","donkey",6,1.2,[33.2,33.2,33.2]],
  ["montura_015","Dark Donkey","donkey",7,1.2,[33.2,33.2,33.2]],
  ["montura_016","Plains Zebra","zebra",15,1.4,[36.0,36.0,36.0]],
  ["montura_017","Mountain Zebra","zebra",15,1.4,[36.0,36.0,36.0]],
  ["montura_018","Golden Zebra","zebra",16,1.4,[36.0,36.0,36.0]],
  ["montura_019","Azure Zebra","zebra",16,1.4,[36.0,36.0,36.0]],
  ["montura_020","Crimson Zebra","zebra",17,1.4,[36.0,36.0,36.0]],
  ["montura_021","Desert Camel","camel",12,1.3,[39.2,39.2,39.2]],
  ["montura_022","Dune Camel","camel",12,1.3,[39.2,39.2,39.2]],
  ["montura_023","Mocha Camel","camel",13,1.3,[39.2,39.2,39.2]],
  ["montura_024","Pale Camel","camel",13,1.3,[39.2,39.2,39.2]],
  ["montura_025","Rust Camel","camel",14,1.3,[39.2,39.2,39.2]],
  ["montura_026","Cream Llama","llama",8,1.25,[34.6,34.6,34.6]],
  ["montura_027","Cocoa Llama","llama",8,1.25,[34.6,34.6,34.6]],
  ["montura_028","Spotless Grey Llama","llama",9,1.25,[34.6,34.6,34.6]],
  ["montura_029","Rose Llama","llama",9,1.25,[34.6,34.6,34.6]],
  ["montura_030","Ebony Llama","llama",10,1.25,[34.6,34.6,34.6]],
  ["montura_031","Northern Reindeer","reindeer",16,1.42,[35.2,35.2,35.2]],
  ["montura_032","Snow Reindeer","reindeer",16,1.42,[35.2,35.2,35.2]],
  ["montura_033","Bark Reindeer","reindeer",17,1.42,[35.2,35.2,35.2]],
  ["montura_034","Frost Reindeer","reindeer",17,1.42,[35.2,35.2,35.2]],
  ["montura_035","Ember Reindeer","reindeer",18,1.42,[35.2,35.2,35.2]],
  ["montura_036","Bull Elk","elk",19,1.44,[39.6,39.6,39.6]],
  ["montura_037","Pale Elk","elk",19,1.44,[39.6,39.6,39.6]],
  ["montura_038","Dark Elk","elk",20,1.44,[39.6,39.6,39.6]],
  ["montura_039","Silver Elk","elk",20,1.44,[39.6,39.6,39.6]],
  ["montura_040","Royal Elk","elk",21,1.44,[39.6,39.6,39.6]],
  ["montura_041","Field Ox","ox",11,1.25,[37.1,37.1,37.1]],
  ["montura_042","White Ox","ox",11,1.25,[37.1,37.1,37.1]],
  ["montura_043","Black Ox","ox",12,1.25,[37.1,37.1,37.1]],
  ["montura_044","Red Ox","ox",12,1.25,[37.1,37.1,37.1]],
  ["montura_045","Dun Ox","ox",13,1.25,[37.1,37.1,37.1]],
  ["montura_046","Mountain Yak","yak",17,1.3,[35.1,35.1,35.1]],
  ["montura_047","Snow Yak","yak",17,1.3,[35.1,35.1,35.1]],
  ["montura_048","Rust Yak","yak",18,1.3,[35.1,35.1,35.1]],
  ["montura_049","Slate Yak","yak",18,1.3,[35.1,35.1,35.1]],
  ["montura_050","Honey Yak","yak",19,1.3,[35.1,35.1,35.1]],
  ["montura_051","Wild Boar","boar",10,1.28,[29.8,29.8,29.8]],
  ["montura_052","Bristle Boar","boar",10,1.28,[29.8,29.8,29.8]],
  ["montura_053","Ginger Boar","boar",11,1.28,[29.8,29.8,29.8]],
  ["montura_054","Ash Boar","boar",11,1.28,[29.8,29.8,29.8]],
  ["montura_055","Night Boar","boar",12,1.28,[29.8,29.8,29.8]],
  ["montura_056","Wool Ram","ram",9,1.26,[32.6,32.6,32.6]],
  ["montura_057","Black Ram","ram",9,1.26,[32.6,32.6,32.6]],
  ["montura_058","Honey Ram","ram",10,1.26,[32.6,32.6,32.6]],
  ["montura_059","Blue Ram","ram",10,1.26,[32.6,32.6,32.6]],
  ["montura_060","Rust Ram","ram",11,1.26,[32.6,32.6,32.6]],
  ["montura_061","Timber Wolf","wolf",22,1.5,[30.8,30.8,30.8]],
  ["montura_062","Arctic Wolf","wolf",22,1.5,[30.8,30.8,30.8]],
  ["montura_063","Black Wolf","wolf",23,1.5,[30.8,30.8,30.8]],
  ["montura_064","Red Wolf","wolf",23,1.5,[30.8,30.8,30.8]],
  ["montura_065","Storm Wolf","wolf",24,1.5,[30.8,30.8,30.8]],
  ["montura_066","Brown Bear","bear",24,1.38,[35.1,35.1,35.1]],
  ["montura_067","Polar Bear","bear",24,1.38,[35.1,35.1,35.1]],
  ["montura_068","Black Bear","bear",25,1.38,[35.1,35.1,35.1]],
  ["montura_069","Cinnamon Bear","bear",25,1.38,[35.1,35.1,35.1]],
  ["montura_070","Moon Bear","bear",26,1.38,[35.1,35.1,35.1]],
  ["montura_071","Savanna Lion","lion",30,1.56,[32.2,32.2,32.2]],
  ["montura_072","White Lion","lion",30,1.56,[32.2,32.2,32.2]],
  ["montura_073","Dusk Lion","lion",31,1.56,[32.2,32.2,32.2]],
  ["montura_074","Ash Lion","lion",31,1.56,[32.2,32.2,32.2]],
  ["montura_075","Royal Lion","lion",32,1.56,[32.2,32.2,32.2]],
  ["montura_076","Bengal Tiger","tiger",28,1.56,[31.4,31.4,31.4]],
  ["montura_077","White Tiger","tiger",28,1.56,[31.4,31.4,31.4]],
  ["montura_078","Golden Tiger","tiger",29,1.56,[31.4,31.4,31.4]],
  ["montura_079","Blue Tiger","tiger",29,1.56,[31.4,31.4,31.4]],
  ["montura_080","Red Tiger","tiger",30,1.56,[31.4,31.4,31.4]],
  ["montura_081","Night Panther","panther",26,1.56,[29.8,29.8,29.8]],
  ["montura_082","Cougar Panther","panther",26,1.56,[29.8,29.8,29.8]],
  ["montura_083","Grey Panther","panther",27,1.56,[29.8,29.8,29.8]],
  ["montura_084","Violet Panther","panther",27,1.56,[29.8,29.8,29.8]],
  ["montura_085","Teal Panther","panther",28,1.56,[29.8,29.8,29.8]],
  ["montura_086","Stone Rhino","rhino",36,1.46,[34.1,34.1,34.1]],
  ["montura_087","Dark Rhino","rhino",36,1.46,[34.1,34.1,34.1]],
  ["montura_088","Clay Rhino","rhino",37,1.46,[34.1,34.1,34.1]],
  ["montura_089","Iron Rhino","rhino",37,1.46,[34.1,34.1,34.1]],
  ["montura_090","Moss Rhino","rhino",38,1.46,[34.1,34.1,34.1]],
  ["montura_091","Black Ostrich","ostrich",20,1.5,[41.3,44.8,44.8]],
  ["montura_092","Sand Ostrich","ostrich",20,1.5,[41.3,44.8,44.8]],
  ["montura_093","Blue Ostrich","ostrich",21,1.5,[41.3,44.8,44.8]],
  ["montura_094","Rose Ostrich","ostrich",21,1.5,[41.3,44.8,44.8]],
  ["montura_095","Emerald Ostrich","ostrich",22,1.5,[41.3,44.8,44.8]],
  ["montura_096","Jungle Raptor","raptor",33,1.62,[32.9,35.0,35.0]],
  ["montura_097","Desert Raptor","raptor",33,1.62,[32.9,35.0,35.0]],
  ["montura_098","Night Raptor","raptor",34,1.62,[32.9,35.0,35.0]],
  ["montura_099","Crimson Raptor","raptor",34,1.62,[32.9,35.0,35.0]],
  ["montura_100","Teal Raptor","raptor",35,1.62,[32.9,35.0,35.0]]
 ];
 const monturas={};
 for(const [id,name,especie,nivel,velocidad,silla] of MONTURAS){
  const src=RUTA+'monturas/iconos/'+id+'.png',atlas=RUTA+'monturas/'+id+'.png',buy=Math.round(400*Math.pow(1.12,nivel)/10)*10;
  alta(id,name,'montura',src,nivel,1,buy,Math.floor(buy/2),{velocidad,especie});
  monturas[id]={id,name,especie,nivel,velocidad,silla,src,atlas,cuadro:[84,68]};
  shop.monturas.push(ficha(id,'monturas','Level '+nivel+' mount. Keep it in your bag and press H to ride: '+Math.round((velocidad-1)*100)+'% faster.',{tabla:id,tablaSola:true}));
 }

 function congelar(o){for(const v of Object.values(o))if(v&&typeof v==='object'&&!Object.isFrozen(v))congelar(v);return Object.freeze(o);}
 function fusionar(c){
  if(!c||c.__v2)return c;
  return Object.freeze({...c,__v2:true,
   items:Object.freeze({...c.items,...items}),food:Object.freeze({...c.food,...food}),levels:Object.freeze({...c.levels,...levels}),
   itemTypes:Object.freeze({...c.itemTypes,...itemTypes}),maxStacks:Object.freeze({...c.maxStacks,...maxStacks}),
   shopPrices:Object.freeze({...c.shopPrices,...shopPrices}),referenceValues:Object.freeze({...c.referenceValues,...referenceValues}),
   names:Object.freeze({...c.names,...names}),tables:Object.freeze([...c.tables,...tables]),consumables:Object.freeze([...c.consumables,...consumables]),
   recipes:Object.freeze([...recipes])});
 }
 return congelar({version:'20261102.items1',items,food,levels,itemTypes,maxStacks,shopPrices,referenceValues,names,shop,tables,consumables,recipes,
  npcs:NPC_VENDE,armasJuego,pvpDano,pvpAlcance,canasSuerte,pesca,obras,colocables,monturas,vidaLeche:VIDA_LECHE,fusionar});
});
