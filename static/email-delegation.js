'use strict';
(()=>{
 const el=id=>document.getElementById(id);let state=null;let selected=new Set();let version=0;let directoryMode=false;
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
   if(directoryMode){button.textContent='Retirar da lista permitida';button.onclick=async()=>{if(!confirm('Remover '+item.email+' desta lista?'))return;button.disabled=true;try{await api('/api/netflix-admin/email-directory',{action:'remove',username:item.admin_user,emails:item.email});await load();status('Email removido desta lista.');}catch(error){status(error.message);button.disabled=false;}};actions.append(button);}
   else if(state.principal){button.textContent='Retirar da lista permitida';button.onclick=async()=>{if(!confirm('Retirar a permissão sobre '+item.email+'? O vínculo atual e o cliente serão preservados.'))return;button.disabled=true;try{const data=await api('/api/admin/email-pool/revoke',{email:item.email});await load();status(data.message);}catch(error){status(error.message);button.disabled=false;}};actions.append(button);}
   else if(!item.can_manage){actions.textContent='Vínculo de outro responsável: somente o admin principal pode corrigir.';}
   else if(item.assignment_state==='reserved'){actions.textContent='Selecione este email e escolha seu cliente para vincular.';}
   else if(item.assigned_users.length){button.textContent='Remover vínculo';button.onclick=async()=>{if(!confirm('Remover o vínculo de '+item.email+'? O cliente não será excluído e o email continuará na sua lista.'))return;button.disabled=true;try{const data=await api('/api/admin/vinculos-emails/'+encodeURIComponent(item.email),null,'DELETE');await load();status(data.message);}catch(error){status(error.message);button.disabled=false;}};actions.append(button);}
   else{actions.textContent=item.quarantined?'Em quarentena — consulta e novo vínculo bloqueados':'Disponível';}
   tr.append(actions);rows.append(tr);
  });
 }
 const initialHelp=el('ep-grant-help').textContent;
 async function load(){
  const id=++version;
  const params=new URLSearchParams(location.search);
  const restricted=params.get('acesso_restrito')||'';
  const filter=params.get('admin_user')||'';
  const data=await api('/api/admin/email-pool?admin_user='+encodeURIComponent(filter));
  let directory=null;
  if(data.principal){
   try{directory=await api('/api/netflix-admin/email-directory');}
   catch(error){if(id===version)status('Não foi possível carregar os acessos restritos: '+error.message);}
  }
  if(id!==version)return;
  directoryMode=!!(data.principal&&restricted&&directory?.accounts.includes(restricted));
  state=directoryMode?{...data,items:directory.items.filter(row=>row.username===restricted).map(row=>({email:row.email,admin_user:row.username,assigned_names:['—']}))}:data;
  selected=new Set();
  el('ep-copy-direct').hidden=directoryMode||!data.principal||!(data.direct_emails||[]).length;
  el('ep-principal').hidden=!data.principal;el('ep-transfer').hidden=data.principal;
  el('ep-grant-help').textContent=directoryMode?'Até 200 por vez. O acesso restrito vê somente a própria lista. No painel do acesso restrito, os endereços desta lista podem gerar links de status, sem códigos. A lista não altera os vínculos do painel.':initialHelp;
  el('ep-owner').textContent=directoryMode?'Lista do acesso restrito: '+restricted:data.principal?'Você define a lista permitida de cada responsável.':'Você só pode alterar os emails liberados nesta lista.';
  if(data.principal){
   const select=el('ep-admin');options(select,[],'Selecione um responsável');
   const group=(label,entries,prefix)=>{const node=document.createElement('optgroup');node.label=label;entries.forEach(({username,name})=>node.append(new Option(name&&name!==username?name+' ('+username+')':username,prefix+username)));select.append(node);};
   group('Subadmins do painel',data.admins,'');
   if(directory?.accounts.length)group('Acessos restritos',directory.accounts.map(username=>({username})),'restricted:');
   select.value=directoryMode?'restricted:'+restricted:(data.admin_user||'');
  }else options(el('ep-client'),data.clients,'Selecione um dos seus clientes');
  render();
 }
 el('ep-copy-direct').onclick=()=>{el('ep-emails').value=(state.direct_emails||[]).join('\n');status('Confira os emails e clique em Adicionar à lista permitida para aprovar.');};
 el('ep-admin').onchange=()=>{const value=el('ep-admin').value;const param=value.startsWith('restricted:')?'acesso_restrito':'admin_user';const next=value.startsWith('restricted:')?value.slice(11):value;history.replaceState(null,'','/admin/emails-subadmins'+(next?'?'+param+'='+encodeURIComponent(next):''));status('');load().catch(error=>status(error.message));};
 el('ep-search').oninput=()=>{if(state)render();};el('ep-refresh').onclick=()=>load().catch(error=>status(error.message));
 el('ep-grant').onsubmit=async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button');if(!el('ep-admin').value){status('Selecione um responsável.');return;}button.disabled=true;try{const value=el('ep-admin').value;const result=await (value.startsWith('restricted:')?api('/api/netflix-admin/email-directory',{action:'assign',username:value.slice(11),emails:el('ep-emails').value}):api('/api/admin/email-pool/grant',{admin_user:value,emails:el('ep-emails').value}));el('ep-emails').value='';await load();status(result.message||'Lista permitida atualizada.');}catch(error){status(error.message);}finally{button.disabled=false;}};
 el('ep-bind').onclick=async()=>{if(!selected.size||!el('ep-client').value){status('Selecione os emails disponíveis e um cliente.');return;}const button=el('ep-bind');button.disabled=true;try{const data=await api('/api/admin/vinculos-emails/import',{assigned_user:el('ep-client').value,emails:[...selected]});await load();status(data.message||'Emails vinculados.');}catch(error){status(error.message);}finally{button.disabled=false;}};
 load().catch(error=>status(error.message));
})();
