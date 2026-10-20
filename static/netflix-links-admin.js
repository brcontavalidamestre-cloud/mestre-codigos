'use strict';
(async () => {
  if (location.hostname !== 'consulta-codigos-jr7z.onrender.com') return;
  try {
    const me = await (await fetch('/api/auth/me', {cache:'no-store'})).json();
    if (!me.logged_in || me.role !== 'admin' || me.username !== 'admin') return;
  } catch { return; }
  const css = document.createElement('link'); css.rel = 'stylesheet'; css.href = '/static/netflix-links.css'; document.head.append(css);
  const section = document.createElement('section'); section.className = 'nfl-admin';
  section.innerHTML = `<h2>🔗 Links Netflix</h2><p>Um link individual por email, somente para códigos Netflix. Qualquer pessoa com o link poderá consultar esse email; compartilhe apenas com o cliente. Redefinir invalida o link antigo.</p><form id="nfl-create"><input id="nfl-add-email" type="email" maxlength="254" required placeholder="Email do cliente" aria-label="Email do cliente"><button type="submit">Adicionar e gerar link</button></form><label for="nfl-search">Pesquisar email</label><input id="nfl-search" type="search" placeholder="Digite parte do email…"><div id="nfl-admin-status" role="status" aria-live="polite"></div><div id="nfl-generated" hidden><label for="nfl-generated-url">Link gerado</label><input id="nfl-generated-url" readonly><button id="nfl-generated-copy" type="button">Copiar link</button></div><div class="nfl-scroll"><table><thead><tr><th>Email</th><th>Criado em</th><th>Última redefinição</th><th>Ações</th></tr></thead><tbody id="nfl-rows"></tbody></table></div><button id="nfl-refresh" type="button" class="nfl-secondary">Atualizar lista</button>`;
  const main = document.querySelector('.main'); if (!main) return;
  const launcher = document.createElement('button');
  launcher.type = 'button'; launcher.className = 'btn-ref';
  launcher.textContent = '🔗 Links Netflix — criar e gerenciar';
  launcher.style.cssText = 'display:block;width:100%;margin:16px 0;padding:20px;border-color:#e24b68;color:#ffc1cc;font-size:1.05rem';
  section.hidden = true;
  main.prepend(launcher, section);
  const el = id => section.querySelector('#' + id);
  const message = text => { el('nfl-admin-status').textContent = text; };
  let items = [];
  async function api(path = '', body) {
    const response = await fetch('/api/admin/netflix-links' + path, {method: body ? 'POST':'GET', cache:'no-store', headers:body ? {'Content-Type':'application/json'} : {}, body:body ? JSON.stringify(body):undefined});
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.message || 'Não foi possível concluir.');
    return data;
  }
  async function copy(url) {
    try { await navigator.clipboard.writeText(url); message('Link copiado.'); }
    catch { showLink(url); message('Selecione e copie o link no campo acima.'); }
  }
  function showLink(url) { el('nfl-generated').hidden = false; el('nfl-generated-url').value = url; }
  function render() {
    const query = el('nfl-search').value.trim().toLowerCase();
    const rows = el('nfl-rows'); rows.replaceChildren();
    const visible = items.filter(item => item.email.includes(query));
    if (!visible.length) {
      const tr = document.createElement('tr'); const td = document.createElement('td'); td.colSpan=4; td.textContent='Nenhum email encontrado.'; tr.append(td); rows.append(tr);
    }
    visible.forEach(item => {
      const tr = document.createElement('tr');
      [item.email, new Date(item.created_at * 1000).toLocaleString('pt-BR'), new Date(item.updated_at * 1000).toLocaleString('pt-BR')].forEach(text => {const td=document.createElement('td'); td.textContent=text; tr.append(td);});
      const actions = document.createElement('td');
      const copyButton = document.createElement('button'); copyButton.type='button'; copyButton.textContent='Copiar link'; copyButton.onclick=()=>copy(item.url);
      const reset = document.createElement('button'); reset.type='button'; reset.className='nfl-secondary'; reset.textContent='Redefinir link';
      reset.onclick=async()=>{
        if (!confirm('Redefinir o link de ' + item.email + '? O link anterior deixará de funcionar.')) return;
        reset.disabled=true;
        try { const data=await api('/reset',{email:item.email}); showLink(data.item.url); await load(); message('Link redefinido. Envie o novo link ao cliente.'); }
        catch(error){message(error.message);} finally{reset.disabled=false;}
      };
      actions.append(copyButton, reset); tr.append(actions); rows.append(tr);
    });
  }
  async function load() { const data=await api(); items=data.items; render(); }
  launcher.onclick = async()=>{ section.hidden=!section.hidden; if(!section.hidden){try{await load();}catch(error){message(error.message);}} };
  el('nfl-search').addEventListener('input',render);
  el('nfl-refresh').onclick=async()=>{try{await load();message('Lista atualizada.');}catch(error){message(error.message);}};
  el('nfl-generated-copy').onclick=()=>copy(el('nfl-generated-url').value);
  el('nfl-create').addEventListener('submit',async(event)=>{
    event.preventDefault(); const button=event.currentTarget.querySelector('button'); button.disabled=true;
    try {const data=await api('',{email:el('nfl-add-email').value}); showLink(data.item.url); el('nfl-add-email').value=''; await load(); message('Link criado. Copie e envie ao cliente.');}
    catch(error){message(error.message);} finally{button.disabled=false;}
  });
})();
