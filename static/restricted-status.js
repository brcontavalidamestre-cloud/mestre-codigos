'use strict';
(()=>{
 const el=document.getElementById('status');
 const button=document.getElementById('status-refresh');
 const token=location.hash.slice(1);
 const address=document.getElementById('status-email');
 const filters=document.getElementById('status-filters');
 const list=document.getElementById('status-filter-list');
 const labels={'access':'Código de acesso','sign-in':'Início de sessão','temporary':'Acesso temporário','residence':'Confirmação de residência','password-reset':'Redefinição de senha'};
 const format=new Intl.DateTimeFormat('pt-BR',{dateStyle:'short',timeStyle:'short',timeZone:'America/Sao_Paulo'});
 function renderFilters(data){
  list.replaceChildren();
  for(const [key,label] of Object.entries(labels)){
   const row=document.createElement('li');
   const date=new Date(data.filters?.[key]??NaN);
   const result=Number.isFinite(date.getTime())?'Recebida em '+format.format(date):data.status==='received_partial'?'Sem confirmação (consulta parcial)':'Nenhuma mensagem encontrada';
   row.textContent=label+' — '+result;list.append(row);
  }
  filters.hidden=false;
 }
 const copy=document.getElementById('status-copy');
 const copyFeedback=document.getElementById('status-copy-feedback');
 const copyUrl=document.getElementById('status-copy-url');
 function hideCopy(){address.hidden=true;address.textContent='';filters.hidden=true;copy.disabled=true;copyUrl.hidden=true;copyUrl.value='';copyFeedback.textContent='';}
 copy.addEventListener('click',async()=>{
  const url=location.origin+location.pathname+'#'+token;
  try{await navigator.clipboard.writeText(url);copyFeedback.textContent='Link copiado.';}
  catch{copyUrl.value=url;copyUrl.hidden=false;copyUrl.focus();copyUrl.select();copyUrl.setSelectionRange(0,url.length);copyFeedback.textContent='Copie o endereço selecionado manualmente.';}
 });
 if(!/^[A-Za-z0-9_-]{43}$/.test(token)){el.textContent='Link inválido.';return;}
 async function refresh(retry=true){
 let queued=false;
 button.disabled=true;el.textContent='Consultando a caixa de email…';
 try{
  const r=await fetch('/api/message-status',{method:'POST',cache:'no-store',headers:{Authorization:'Bearer '+token}});
  if(r.status===404||r.status===403){hideCopy();el.textContent='Link inválido, revogado ou bloqueado.';return;}
  if(r.status===429){
   const wait=Math.min(20,Math.max(1,Number(r.headers.get('Retry-After'))||20));
   el.textContent=retry?'Aguarde '+wait+' s. A consulta será retomada automaticamente.':'Aguarde alguns segundos e clique em Consultar agora.';
   if(retry){queued=true;setTimeout(()=>refresh(false),(wait+1)*1000);}
   return;
  }
  const d=await r.json();
  if(r.ok&&['received','received_partial','not_found','unavailable'].includes(d.status))copy.disabled=false;
  if(r.ok&&['received','received_partial','not_found'].includes(d.status))renderFilters(d);
  if((d.status==='received'||d.status==='received_partial')&&d.received_at){el.textContent='Mensagem recebida em '+new Intl.DateTimeFormat('pt-BR',{dateStyle:'short',timeStyle:'short',timeZone:'America/Sao_Paulo'}).format(new Date(d.received_at))+'.'+(d.status==='received_partial'?' Nem todas as caixas responderam.':'');}
  else if(d.status==='not_found'){el.textContent='Nenhuma mensagem encontrada nos últimos 30 dias.';}
  else{el.textContent='Consulta temporariamente indisponível.';}
 }catch{el.textContent='Consulta temporariamente indisponível.';}
 finally{if(!queued)button.disabled=false;}
 }
 button.addEventListener('click',()=>refresh());
 (async()=>{
  try{
   const r=await fetch('/api/message-status',{cache:'no-store',headers:{Authorization:'Bearer '+token}});
   if(r.status===404||r.status===403){hideCopy();el.textContent='Link inválido, revogado ou bloqueado.';return;}
   if(!r.ok)throw new Error();
   const d=await r.json();if(typeof d.email!=='string'||!d.email)throw new Error();
   address.textContent=d.email;address.hidden=false;copy.disabled=false;
   await refresh();
  }catch{el.textContent='Consulta temporariamente indisponível. Reabra o link para tentar novamente.';}
 })();
})();
