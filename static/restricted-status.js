'use strict';
(()=>{
 const el=document.getElementById('status');
 const button=document.getElementById('status-refresh');
 const token=location.hash.slice(1);
 if(!/^[A-Za-z0-9_-]{43}$/.test(token)){el.textContent='Link inválido.';return;}
 async function refresh(){
 button.disabled=true;el.textContent='Consultando a caixa de email…';
 try{
  const r=await fetch('/api/message-status',{method:'POST',cache:'no-store',headers:{Authorization:'Bearer '+token}});
  if(r.status===404||r.status===403){el.textContent='Link inválido, revogado ou bloqueado.';return;}
  if(r.status===429){el.textContent='Aguarde alguns segundos antes de consultar novamente.';return;}
  const d=await r.json();
  if((d.status==='received'||d.status==='received_partial')&&d.received_at){el.textContent='Mensagem recebida em '+new Intl.DateTimeFormat('pt-BR',{dateStyle:'short',timeStyle:'short',timeZone:'America/Sao_Paulo'}).format(new Date(d.received_at))+'.'+(d.status==='received_partial'?' Nem todas as caixas responderam.':'');}
  else if(d.status==='not_found'){el.textContent='Nenhuma mensagem encontrada nos últimos 30 dias.';}
  else{el.textContent='Consulta temporariamente indisponível.';}
 }catch{el.textContent='Consulta temporariamente indisponível.';}
 finally{button.disabled=false;}
 }
 button.addEventListener('click',refresh);refresh();
})();
