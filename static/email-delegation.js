'use strict';
(()=>{
 const el=id=>document.getElementById(id);let state=null;let selected=new Set();let version=0;let directoryMode=false;
 const status=text=>{const node=el('ep-status');node.style.whiteSpace='pre-wrap';node.style.overflowWrap='anywhere';node.textContent=text;};
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
  if(data.principal&&!data.can_assign_globally){
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
   for (const admin of data.admins.filter(item => item.username === 'admin')) select.add(new Option(admin.name, admin.username));
   group('Subadmins do painel',data.admins.filter(item => item.username !== 'admin'),'');
   if(directory?.accounts.length)group('Acessos restritos',directory.accounts.map(username=>({username})),'restricted:');
   select.value=directoryMode?'restricted:'+restricted:(data.admin_user||'');
  }else options(el('ep-client'),data.clients,'Selecione um dos seus clientes');
  render();
 }
 let searchVersion=0;
 el('ep-global-query').oninput=()=>{searchVersion++;el('ep-global-status').textContent='';el('ep-global-results').replaceChildren();};
 el('ep-global-search').onsubmit=async event=>{
  event.preventDefault();if(!state?.principal)return;
  const id=++searchVersion, info=el('ep-global-status'), results=el('ep-global-results');
  results.replaceChildren();info.textContent='Pesquisando…';
  try{
   const data=await api('/api/admin/email-pool/search?q='+encodeURIComponent(el('ep-global-query').value.trim()));
   if(id!==searchVersion)return;
   info.textContent=data.total>50?`Mostrando 50 de ${data.total} resultados. Refine a busca.`:data.total?`${data.total} resultado(s).`:'Nenhum e-mail encontrado na Central.';
   for(const row of data.items){
    const item=document.createElement('li'), address=document.createElement('strong');address.textContent=row.email;
    const clients=row.clients.map(client=>client.name===client.username?'@'+client.username:client.name+' (@'+client.username+')').join(', ');
    const details=document.createElement('span');
    const showDetails=()=>{details.textContent=`Lista permitida: ${row.list_owner||'Sem responsável'} · Cliente vinculado: ${clients||'Nenhum'}${row.managers.length?' · Admin do cliente: '+row.managers.join(', '):''} · ${row.quarantined?'Em quarentena':'Fora da quarentena'}`;};
    showDetails();item.append(address,document.createElement('br'),details);
    const controls=document.createElement('div');controls.style.margin='6px 0 12px';
    const button=document.createElement('button');button.type='button';button.textContent='Liberar e-mail';
    const targets=document.createElement('select');targets.setAttribute('aria-label','Subadmin para '+row.email);
    const choices=(state.admins||[]).filter(admin=>row.eligible_admins.includes(admin.username));
    options(targets,choices,'Selecione um subadmin');
    const selectedOwner=el('ep-admin').value;
    if(choices.some(admin=>admin.username===selectedOwner))targets.value=selectedOwner;
    const note=document.createElement('span');note.setAttribute('role','status');
    const unavailable=row.quarantined?'Endereço em quarentena.':row.list_owner?'Já liberado para '+row.list_owner+'.':!choices.length?'Não há subadmin elegível. O vínculo atual não será transferido.':'';
    if(unavailable){button.disabled=true;controls.append(button,' ',note);note.textContent=unavailable;}
    else {
     controls.append(targets,' ',button,' ',note);
     button.onclick=async()=>{
      const target=targets.value;
      if(!target){note.textContent='Selecione um subadmin.';targets.focus();return;}
      if(!confirm('Liberar '+row.email+' na lista de '+target+'? O vínculo com o cliente não será alterado.'))return;
      button.disabled=true;targets.disabled=true;note.textContent='Salvando…';
      try{
       const response=await fetch('/api/admin/email-pool/grant',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({admin_user:target,emails:[row.email]})});
       const data=await response.json();
       if(!response.ok||!data.success)throw new Error(data.blocked_emails?.length?'Endereço em quarentena.':data.conflict_emails?.length?'O endereço já está em outra lista ou vinculado a outro responsável.':data.message||'Não foi possível liberar.');
       note.textContent='Liberado para '+target+'.';targets.hidden=true;
       row.list_owner=target;showDetails();
       if(el('ep-admin').value===target||!el('ep-admin').value)await load().catch(()=>{});
      }catch(error){note.textContent=error.message;button.disabled=false;targets.disabled=false;}
     };
    }
    if(state.can_assign_globally){
     button.hidden=true;targets.hidden=true;note.textContent='';
     const assign=document.createElement('button');assign.type='button';assign.textContent='Atribuir e-mail';
     const destination=document.createElement('select');destination.setAttribute('aria-label','Destino para '+row.email);
     options(destination,(state.binding_targets||[]).map(u=>({...u,name:(u.role==='admin'?'Admin: ':'Cliente: ')+u.name})),'Selecione um cliente ou admin');
     const reason=row.quarantined?'Endereço em quarentena.':row.clients.length?'Remova primeiro o vínculo atual.':!row.list_owner?'Endereço ainda não autorizado.':'';
     assign.disabled=Boolean(reason);destination.disabled=Boolean(reason);note.textContent=reason;
     controls.prepend(destination,' ',assign,' ');
     assign.onclick=async()=>{
      const target=destination.value;if(!target){destination.focus();return;}
      if(!confirm('Atribuir '+row.email+' a @'+target+'?'))return;
      assign.disabled=true;destination.disabled=true;note.textContent='Salvando…';
      try{const data=await api('/api/admin/email-pool/assign-authorized',{email:row.email,target});if(id===searchVersion){status(data.message);el('ep-global-search').requestSubmit();load().catch(()=>{});}}
      catch(error){note.textContent=error.message;assign.disabled=false;destination.disabled=false;}
     };
    }
    for(const client of row.clients){
     const unlink=document.createElement('button');unlink.type='button';unlink.className='nfl-secondary';
     unlink.textContent='Remover vínculo de @'+client.username;
     controls.append(' ',unlink);
     unlink.onclick=async()=>{
      if(!confirm('Remover o vínculo de '+row.email+' com @'+client.username+'? O cadastro e a lista permitida serão mantidos.'))return;
      unlink.disabled=true;note.textContent='Removendo vínculo…';
      try{
       const data=await api('/api/admin/email-pool/unlink-client',{email:row.email,client:client.username});
       if(id!==searchVersion)return;
       status(data.message);
       el('ep-global-search').requestSubmit();
       load().catch(()=>{});
      }catch(error){note.textContent=error.message;unlink.disabled=false;}
     };
    }
    item.append(controls);
    results.append(item);
   }
  }catch(error){if(id===searchVersion)info.textContent=error.message;}
 };
 el('ep-copy-direct').onclick=()=>{el('ep-emails').value=(state.direct_emails||[]).join('\n');status('Confira os emails e clique em Adicionar à lista permitida para aprovar.');};
 el('ep-admin').onchange=()=>{const value=el('ep-admin').value;const param=value.startsWith('restricted:')?'acesso_restrito':'admin_user';const next=value.startsWith('restricted:')?value.slice(11):value;history.replaceState(null,'','/admin/emails-subadmins'+(next?'?'+param+'='+encodeURIComponent(next):''));status('');load().catch(error=>status(error.message));};
 el('ep-search').oninput=()=>{if(state)render();};el('ep-refresh').onclick=()=>load().catch(error=>status(error.message));
 el('ep-grant').onsubmit=async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button');if(!el('ep-admin').value){status('Selecione um responsável.');return;}button.disabled=true;try{const value=el('ep-admin').value;const field=el('ep-emails');const submitted=field.value;
 if(value.startsWith('restricted:')){const result=await api('/api/netflix-admin/email-directory',{action:'assign',username:value.slice(11),emails:submitted});if(field.value===submitted)field.value='';await load();status(result.message||'Lista permitida atualizada.');return;}
 const response=await fetch('/api/admin/email-pool/grant',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({admin_user:value,emails:submitted})});
 const result=await response.json();if(!Array.isArray(result.added_emails))throw new Error(result.message||'Não foi possível atualizar a lista.');
 if(el('ep-admin').value!==value)return;
 const groups=[['Adicionados à lista',result.added_emails],['Já liberados para este responsável',result.already_allowed],['Em outra lista ou vinculados a outro responsável',result.conflict_emails],['Bloqueados pela quarentena',result.blocked_emails],['Endereços inválidos',result.invalid_emails]];
 if(field.value===submitted)field.value=[...result.conflict_emails,...result.blocked_emails,...result.invalid_emails].join('\n');
 const describe=email=>{
  const details=Object.hasOwn(result.details||{},email)?result.details[email]:null;
  const notes=(details?.clients||[]).map(client=>`${client.prevents_grant?'Vínculo com outro responsável':'Vínculo atual'}: ${client.name} (@${client.username})`);
  if(details?.other_list)notes.push('Já está na lista de @'+details.other_list);
  return notes.length?email+' — '+notes.join(' · '):email;
 };
 const feedback=groups.filter(([,items])=>items.length).map(([label,items])=>`${label} (${items.length}):\n${items.map(describe).join('\n')}`).join('\n\n');
 if(result.added_emails.length){try{await load();}catch{if(el('ep-admin').value===value)status(feedback+'\n\nOs dados foram salvos. Clique em Atualizar lista para recarregar a tabela.');return;}}
 if(el('ep-admin').value===value)status(feedback||result.message);}catch(error){status(error.message);}finally{button.disabled=false;}};
 el('ep-bind').onclick=async()=>{if(!selected.size||!el('ep-client').value){status('Selecione os emails disponíveis e um cliente.');return;}const button=el('ep-bind');button.disabled=true;try{const data=await api('/api/admin/vinculos-emails/import',{assigned_user:el('ep-client').value,emails:[...selected]});await load();status(data.message||'Emails vinculados.');}catch(error){status(error.message);}finally{button.disabled=false;}};
 load().catch(error=>status(error.message));
})();
