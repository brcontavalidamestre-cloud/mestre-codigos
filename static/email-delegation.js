'use strict';
(()=>{
 const el=id=>document.getElementById(id);let state=null;let selected=new Set();let version=0;
 const status=text=>{el('ep-status').textContent=text;};
 async function api(path,body,method){const response=await fetch(path,{method:method||(body?'POST':'GET'),cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await response.json();if(!response.ok||!data.success)throw new Error(data.message||'Não foi possível concluir.');return data;}
 function options(select,items,placeholder){select.replaceChildren();const first=document.createElement('option');first.value='';first.textContent=placeholder;select.append(first);items.forEach(item=>{const option=document.createElement('option');option.value=item.username;option.textContent=(item.name||item.username)+' ('+item.username+')';select.append(option);});}
 function render(){
  const query=el('ep-search').value.trim().toLowerCase();const rows=el('ep-rows');rows.replaceChildren();const items=state.items.filter(item=>item.email.includes(query));
  el('ep-total').textContent=state.items.length+' email(s) na lista · '+selected.size+' selecionado(s)';
  if(!items.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=5;td.textContent='Nenhum email na lista permitida. O admin principal precisa liberar os emails.';tr.append(td);rows.append(tr);}
  items.forEach(item=>{
   const tr=document.createElement('tr');const choose=document.createElement('td');
   if(!state.principal){const checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.style.width='auto';checkbox.setAttribute('aria-label','Selecionar '+item.email);checkbox.disabled=!item.can_assign||item.quarantined;checkbox.checked=selected.has(item.email);checkbox.onchange=()=>{if(checkbox.checked)selected.add(item.email);else selected.delete(item.email);el('ep-total').textContent=state.items.length+' email(s) na lista · '+selected.size+' selecionado(s)';};choose.append(checkbox);}tr.append(choose);
   [item.email,item.admin_user,item.assignment_state==='reserved'?'Reservado para distribuir':item.assigned_names.length?item.assigned_names.join(', '):'Disponível para vincular'].forEach(text=>{const td=document.createElement('td');td.textContent=text;tr.append(td);});
   const actions=document.createElement('td');const button=document.createElement('button');button.type='button';button.className='nfl-secondary';
   if(state.principal){button.textContent='Retirar da lista permitida';button.onclick=async()=>{if(!confirm('Retirar a permissão sobre '+item.email+'? O vínculo atual e o cliente serão preservados.'))return;button.disabled=true;try{const data=await api('/api/admin/email-pool/revoke',{email:item.email});await load();status(data.message);}catch(error){status(error.message);button.disabled=false;}};actions.append(button);}
   else if(!item.can_manage){actions.textContent='Vínculo de outro responsável: somente o admin principal pode corrigir.';}
   else if(item.assignment_state==='reserved'){actions.textContent='Selecione este email e escolha seu cliente para vincular.';}
   else if(item.assigned_users.length){button.textContent='Remover vínculo';button.onclick=async()=>{if(!confirm('Remover o vínculo de '+item.email+'? O cliente não será excluído e o email continuará na sua lista.'))return;button.disabled=true;try{const data=await api('/api/admin/vinculos-emails/'+encodeURIComponent(item.email),null,'DELETE');await load();status(data.message);}catch(error){status(error.message);button.disabled=false;}};actions.append(button);}
   else{actions.textContent=item.quarantined?'Em quarentena — consulta e novo vínculo bloqueados':'Disponível';}
   if(item.can_manage&&!item.quarantined){const link=document.createElement('a');link.href='/admin/netflix-links?email='+encodeURIComponent(item.email);link.textContent='🔗 Gerar / gerenciar link individual';link.style.cssText='display:block;color:#a5e3ff;margin:10px 0';actions.append(link);}
   tr.append(actions);rows.append(tr);
  });
 }
 async function load(){const id=++version;const filter=el('ep-admin').value||new URLSearchParams(location.search).get('admin_user')||'';const data=await api('/api/admin/email-pool?admin_user='+encodeURIComponent(filter));if(id!==version)return;state=data;selected=new Set();el('ep-copy-direct').hidden=!data.principal||!(data.direct_emails||[]).length;el('ep-principal').hidden=!data.principal;el('ep-transfer').hidden=data.principal;el('ep-owner').textContent=data.principal?'Você define a lista permitida de cada subadmin.':'Você só pode alterar os emails liberados nesta lista.';if(data.principal){options(el('ep-admin'),data.admins,'Selecione um subadmin');el('ep-admin').value=data.admin_user||'';}else options(el('ep-client'),data.clients,'Selecione um dos seus clientes');render();}
 el('ep-copy-direct').onclick=()=>{el('ep-emails').value=(state.direct_emails||[]).join('\n');status('Confira os emails e clique em Adicionar à lista permitida para aprovar.');};
 el('ep-admin').onchange=()=>{history.replaceState(null,'','/admin/emails-subadmins'+(el('ep-admin').value?'?admin_user='+encodeURIComponent(el('ep-admin').value):''));load().catch(error=>status(error.message));};
 el('ep-search').oninput=()=>{if(state)render();};el('ep-refresh').onclick=()=>load().catch(error=>status(error.message));
 el('ep-grant').onsubmit=async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button');if(!el('ep-admin').value){status('Selecione um subadmin.');return;}button.disabled=true;try{const result=await api('/api/admin/email-pool/grant',{admin_user:el('ep-admin').value,emails:el('ep-emails').value});el('ep-emails').value='';await load();status(result.message);}catch(error){status(error.message);}finally{button.disabled=false;}};
 el('ep-bind').onclick=async()=>{if(!selected.size||!el('ep-client').value){status('Selecione os emails disponíveis e um cliente.');return;}const button=el('ep-bind');button.disabled=true;try{const data=await api('/api/admin/vinculos-emails/import',{assigned_user:el('ep-client').value,emails:[...selected]});await load();status(data.message||'Emails vinculados.');}catch(error){status(error.message);}finally{button.disabled=false;}};
 load().catch(error=>status(error.message));
})();
