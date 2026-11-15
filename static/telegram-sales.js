'use strict';
(()=>{
 const el=id=>document.getElementById(id);let state=null;let offset=0;let revision=0;let loading=false;
 const labels={historical:'Histórico — sem envio retroativo',pending:'Na fila',sending:'Enviando',sent:'Enviado',retry:'Nova tentativa agendada',cancelled:'Envio cancelado'};
 const when=value=>value?new Date(value*1000).toLocaleString('pt-BR',{timeZone:'America/Sao_Paulo'}):'Data não informada';
 const money=value=>Number(value||0).toLocaleString('pt-BR',{style:'currency',currency:'BRL'});
 const message=text=>{el('status').textContent=text;};
 async function api(path='',body){const r=await fetch('/api/admin/telegram-sales'+path,{method:body?'POST':'GET',cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await r.json();if(!r.ok||!data.success)throw new Error(data.message||'Não foi possível concluir.');return data;}
 function cell(tr,text){const td=document.createElement('td');td.textContent=text;tr.append(td);return td;}
 function render(data){
  state=data;const connected=data.bot_configured&&data.destination_configured;
  el('connection').textContent=connected?'Bot conectado: @'+data.bot_username+' · Avisos '+(data.enabled?'ativados':'pausados'):'Conexão pendente: falta configurar o bot ou o destino.';
  el('activation').textContent=data.start_at?'Novas confirmações a partir de '+when(data.start_at)+' entram na fila de avisos.':'';
  el('toggle').disabled=!connected;el('toggle').textContent=data.enabled?'Pausar avisos':'Ativar avisos';el('test').disabled=!connected;
  el('counts').textContent=Object.entries(data.counts).map(([key,value])=>(labels[key]||key)+': '+value).join(' · ')||'Nenhuma venda paga registrada.';
  el('total').textContent=data.total+' venda(s) encontrada(s)';const rows=el('rows');rows.replaceChildren();
  if(!data.items.length){const tr=document.createElement('tr');const td=cell(tr,'Nenhuma venda encontrada.');td.colSpan=6;rows.append(tr);}
  data.items.forEach(item=>{const tr=document.createElement('tr');cell(tr,when(item.paid_at));cell(tr,(item.id||'')+'\n'+(item.product_name||''));cell(tr,(item.customer_name||'')+'\n'+(item.customer_email||''));cell(tr,money(item.price));cell(tr,(item.delivered_email||'Não entregue')+' · '+(item.delivery_status||''));const td=document.createElement('td');const badge=document.createElement('span');badge.className='badge '+item.notification_status;badge.textContent=labels[item.notification_status]||item.notification_status;td.append(badge);if(item.sent_at){const sent=document.createElement('div');sent.textContent=when(item.sent_at);td.append(sent);}if(item.last_error){const error=document.createElement('div');error.textContent=item.last_error;td.append(error);}tr.append(td);rows.append(tr);});
  el('prev').disabled=offset===0;el('next').disabled=offset+data.limit>=data.total;el('page').textContent='Página '+(Math.floor(offset/data.limit)+1);
 }
 async function load(){const current=++revision;loading=true;try{const data=await api('?q='+encodeURIComponent(el('query').value.trim())+'&offset='+offset);if(current===revision)render(data);}finally{if(current===revision)loading=false;}}
 el('search-form').onsubmit=event=>{event.preventDefault();offset=0;load().catch(e=>message(e.message));};
 el('refresh').onclick=()=>load().catch(e=>message(e.message));el('prev').onclick=()=>{offset=Math.max(0,offset-50);load().catch(e=>message(e.message));};el('next').onclick=()=>{offset+=50;load().catch(e=>message(e.message));};
 el('test').onclick=async()=>{el('test').disabled=true;try{const data=await api('/test',{});message(data.message);}catch(e){message(e.message);}finally{el('test').disabled=false;}};
 el('toggle').onclick=async()=>{if(!state)return;el('toggle').disabled=true;try{const data=await api('/toggle',{enabled:!state.enabled});await load();message(data.message);}catch(e){message(e.message);el('toggle').disabled=false;}};
 load().catch(e=>message(e.message));setInterval(()=>{if(!document.hidden&&!loading)load().catch(()=>{});},15000);
})();
