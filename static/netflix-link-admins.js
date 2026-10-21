'use strict';
(async()=>{
  if(location.hostname!=='consulta-codigos-jr7z.onrender.com'||location.pathname!=='/admin/netflix-links')return;
  let identity;
  try{identity=await(await fetch('/api/netflix-admin/me',{cache:'no-store'})).json();}catch{return;}
  if(!identity.success||!identity.principal)return;
  const main=document.querySelector('.main');if(!main)return;
  const box=document.createElement('section');box.className='nfl-admin';box.id='nfl-managers';
  box.innerHTML=`<h2>👥 Administradores desta página</h2><p>Crie um login separado para seu cliente adicionar e gerenciar apenas os próprios emails e links Netflix. Esse acesso não libera o painel principal, os dados de outros administradores, o JMP ou a loja.</p><label for="nfa-login-url">Link de entrada para esse administrador</label><input id="nfa-login-url" readonly><button id="nfa-copy-login" type="button" class="nfl-secondary">Copiar link de entrada</button><form id="nfa-create" class="nfl-account-form"><label for="nfa-name">Nome do cliente</label><input id="nfa-name" maxlength="80" autocomplete="off"><label for="nfa-username">Usuário do acesso restrito</label><input id="nfa-username" required minlength="3" maxlength="40" pattern="[a-z0-9_.\\-]{3,40}" autocomplete="off" autocapitalize="none"><label for="nfa-password">Senha do acesso restrito</label><input id="nfa-password" type="password" required minlength="8" maxlength="128" autocomplete="new-password"><small>Defina uma senha de pelo menos 8 caracteres. O usuário e a senha serão usados somente nesta área.</small><button type="submit">Criar acesso restrito</button></form><p id="nfa-status" role="status" aria-live="polite"></p><div class="nfl-scroll"><table><thead><tr><th>Usuário</th><th>Nome</th><th>Status</th><th>Gerenciar acesso</th></tr></thead><tbody id="nfa-rows"></tbody></table></div><small>Desativar o acesso impede novos logins e encerra suas sessões. Não apaga os emails nem os links já gerados.</small>`;
  const heading=main.querySelector('h1');if(heading)heading.insertAdjacentElement('afterend',box);else main.prepend(box);
  const el=id=>box.querySelector('#'+id);
  const status=text=>{el('nfa-status').textContent=text;};
  const loginUrl=location.origin+'/netflix-admin/login';el('nfa-login-url').value=loginUrl;
  async function api(path='',body){
    const response=await fetch('/api/admin/netflix-link-admins'+path,{method:body?'POST':'GET',cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});
    const data=await response.json();if(!response.ok||!data.success)throw new Error(data.message||'Não foi possível concluir.');return data;
  }
  async function load(){
    const data=await api();const rows=el('nfa-rows');rows.replaceChildren();
    if(!data.items.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=4;td.textContent='Nenhum administrador restrito cadastrado.';tr.append(td);rows.append(tr);}
    data.items.forEach(account=>{
      const tr=document.createElement('tr');[account.username,account.name,account.active?'Ativo':'Desativado'].forEach(text=>{const td=document.createElement('td');td.textContent=text;tr.append(td);});
      const actions=document.createElement('td');
      const toggle=document.createElement('button');toggle.type='button';toggle.className='nfl-secondary';toggle.textContent=account.active?'Desativar acesso':'Reativar acesso';
      toggle.onclick=async()=>{if(!confirm((account.active?'Desativar':'Reativar')+' o acesso de '+account.username+'?'))return;toggle.disabled=true;try{await api('/update',{id:account.id,active:!account.active});await load();status('Acesso atualizado.');}catch(error){status(error.message);toggle.disabled=false;}};
      const form=document.createElement('form');form.className='nfl-account-password';
      const password=document.createElement('input');password.type='password';password.required=true;password.minLength=8;password.maxLength=128;password.autocomplete='new-password';password.placeholder='Nova senha';password.setAttribute('aria-label','Nova senha de '+account.username);
      const reset=document.createElement('button');reset.type='submit';reset.className='nfl-secondary';reset.textContent='Alterar senha';
      form.append(password,reset);form.onsubmit=async(event)=>{event.preventDefault();reset.disabled=true;try{await api('/update',{id:account.id,password:password.value});password.value='';status('Senha alterada. As sessões antigas foram encerradas.');}catch(error){status(error.message);}finally{reset.disabled=false;}};
      actions.append(toggle,form);tr.append(actions);rows.append(tr);
    });
  }
  el('nfa-copy-login').onclick=async()=>{try{await navigator.clipboard.writeText(loginUrl);status('Link de entrada copiado.');}catch{el('nfa-login-url').select();status('Selecione e copie o link de entrada.');}};
  el('nfa-create').onsubmit=async(event)=>{
    event.preventDefault();const button=event.currentTarget.querySelector('button');button.disabled=true;
    try{const data=await api('',{name:el('nfa-name').value,username:el('nfa-username').value,password:el('nfa-password').value});el('nfa-name').value='';el('nfa-username').value='';el('nfa-password').value='';await load();status('Acesso criado para '+data.username+'. Envie ao cliente o link de entrada, o usuário e a senha que você definiu.');}
    catch(error){status(error.message);}finally{button.disabled=false;}
  };
  try{await load();}catch(error){status(error.message);}
})();
