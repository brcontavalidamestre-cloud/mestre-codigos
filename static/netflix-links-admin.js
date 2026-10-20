'use strict';
(async () => {
  if (location.hostname !== 'consulta-codigos-jr7z.onrender.com') return;
  if (location.pathname === '/admin' && document.getElementById('nfl-nav-link')) return;
  const directPanel = location.pathname === '/admin/netflix-links';
  try {
    const me = await (await fetch('/api/auth/me', {cache:'no-store'})).json();
    if (!me.logged_in || me.role !== 'admin' || me.username !== 'admin') return;
  } catch { return; }
  const css = document.createElement('link'); css.rel = 'stylesheet'; css.href = '/static/netflix-links.css?v=3'; document.head.append(css);
  const section = document.createElement('section'); section.className = 'nfl-admin';
  section.innerHTML = `<h2>🔗 Links Netflix</h2><p>Um link exclusivo por email, somente para códigos Netflix. Apenas o administrador pode redefinir os links. Compartilhe cada endereço somente com o respectivo cliente.</p><form id="nfl-create"><label for="nfl-add-email">Adicionar vários emails de uma vez</label><textarea id="nfl-add-email" rows="6" maxlength="60000" required placeholder="cliente1@exemplo.com&#10;cliente2@exemplo.com&#10;cliente3@exemplo.com" aria-label="Emails dos clientes"></textarea><small>Até 200 emails por vez. Use um por linha ou separe por vírgula ou ponto e vírgula. Emails já cadastrados mantêm seu link atual.</small><button type="submit">Gerar links para os emails</button></form><label for="nfl-search">Pesquisar email</label><input id="nfl-search" type="search" placeholder="Digite parte do email…"><div id="nfl-admin-status" role="status" aria-live="polite"></div><div id="nfl-generated" hidden><label for="nfl-generated-url">Emails e links gerados</label><textarea id="nfl-generated-url" rows="8" readonly></textarea><button id="nfl-generated-copy" type="button">Copiar todos os links gerados</button></div><div class="nfl-scroll"><table><thead><tr><th>Email</th><th>Criado em</th><th>Última redefinição</th><th>Ações</th></tr></thead><tbody id="nfl-rows"></tbody></table></div><button id="nfl-refresh" type="button" class="nfl-secondary">Atualizar lista</button>`;
  const main = document.querySelector('.main'); if (!main) return;
  const launcher = document.createElement('button');
  launcher.type = 'button'; launcher.className = 'btn-ref';
  launcher.textContent = '🔗 Links Netflix — criar e gerenciar';
  launcher.style.cssText = 'display:block;width:100%;margin:16px 0;padding:20px;border-color:#e24b68;color:#ffc1cc;font-size:1.05rem';
  section.hidden = !directPanel;
  if (directPanel) main.append(section);
  else main.prepend(launcher, section);
  const el = id => section.querySelector('#' + id);
  const message = text => { el('nfl-admin-status').textContent = text; };
  let items = [];
  async function api(path = '', body) {
    const response = await fetch('/api/admin/netflix-links' + path, {method: body ? 'POST':'GET', cache:'no-store', headers:body ? {'Content-Type':'application/json'} : {}, body:body ? JSON.stringify(body):undefined});
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.message || 'Não foi possível concluir.');
    return data;
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); message('Copiado.'); }
    catch { el('nfl-generated').hidden=false; el('nfl-generated-url').value=text; el('nfl-generated-url').select(); message('Selecione e copie o texto no campo acima.'); }
  }
  function showLinks(generated) {
    el('nfl-generated').hidden = false;
    el('nfl-generated-url').value = generated.map(item => item.email + '\n' + item.url).join('\n\n');
  }
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
        try { const data=await api('/reset',{email:item.email}); showLinks([data.item]); await load(); message('Link redefinido. Envie o novo link ao cliente.'); }
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
    try {
      const data=await api('',{emails:el('nfl-add-email').value});
      showLinks(data.items); el('nfl-add-email').value=''; await load();
      const notes=[data.created+' link(s) novo(s)',data.existing+' já cadastrado(s) mantido(s)'];
      if(data.duplicates) notes.push(data.duplicates+' repetido(s) ignorado(s)');
      if(data.invalid_emails.length) notes.push('Inválidos não adicionados: '+data.invalid_emails.join(', '));
      message(notes.join(' · ')+'. Copie os links e envie cada um ao respectivo cliente.');
    }
    catch(error){message(error.message);} finally{button.disabled=false;}
  });
  if (directPanel) {
    try { await load(); } catch (error) { message(error.message); }
  }
})();
