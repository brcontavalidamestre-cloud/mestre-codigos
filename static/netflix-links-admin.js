'use strict';
(async () => {
  if (location.hostname !== 'consulta-codigos-jr7z.onrender.com') return;
  const directPanel = location.pathname === '/admin/netflix-links';
  // On /admin the server already injects one entry bar per service.
  if (!directPanel) return;

  const SERVICES = [
    { key: 'netflix', name: 'Netflix', icon: '🔗', color: '#e24b68', hint: 'somente para códigos Netflix' },
    { key: 'disney', name: 'Disney+', icon: '🏰', color: '#3b8ff0', hint: 'somente para códigos Disney+' }
  ];
  const byKey = Object.fromEntries(SERVICES.map(item => [item.key, item]));
  let currentService = new URLSearchParams(location.search).get('service');
  if (!byKey[currentService]) currentService = 'netflix';

  let identity;
  try {
    identity = await (await fetch('/api/netflix-admin/me', { cache: 'no-store' })).json();
    if (!identity.success) { location.replace('/netflix-admin/login'); return; }
  } catch { return; }

  const back = document.getElementById('nfl-back-link');
  if (back && !identity.principal) {
    back.href = '/netflix-admin/login';
    back.textContent = 'Acesso exclusivo — Links de Acesso';
  }

  const css = document.createElement('link');
  css.rel = 'stylesheet';
  css.href = '/static/netflix-links.css?v=8';
  document.head.append(css);

  const section = document.createElement('section');
  section.className = 'nfl-admin';
  section.innerHTML = `
    <h2>🔗 Links de Acesso</h2>
    <p>Um link exclusivo por email e por serviço. Apenas o administrador pode redefinir os links. Compartilhe cada endereço somente com o respectivo cliente.</p>
    <div class="nfl-tabs" role="tablist" aria-label="Escolha o serviço"></div>
    <form id="nfl-create">
      <label for="nfl-add-email" id="nfl-add-label">Adicionar vários emails de uma vez</label>
      <textarea id="nfl-add-email" rows="6" maxlength="60000" required placeholder="cliente1@exemplo.com&#10;cliente2@exemplo.com&#10;cliente3@exemplo.com" aria-label="Emails dos clientes"></textarea>
      <small id="nfl-add-help">Até 200 emails por vez. Use um por linha ou separe por vírgula ou ponto e vírgula. Emails já cadastrados mantêm seu link atual.</small>
      <button type="submit" id="nfl-create-button">Gerar links para os emails</button>
    </form>
    <label for="nfl-search">Pesquisar email</label>
    <input id="nfl-search" type="search" placeholder="Digite parte do email…">
    <div id="nfl-admin-status" role="status" aria-live="polite"></div>
    <div id="nfl-generated" hidden>
      <label for="nfl-generated-url">Emails e links gerados</label>
      <textarea id="nfl-generated-url" rows="8" readonly></textarea>
      <button id="nfl-generated-copy" type="button">Copiar todos os links gerados</button>
    </div>
    <div class="nfl-scroll">
      <table>
        <thead><tr><th>Email</th><th>Criado em</th><th>Última redefinição</th><th>Responsável</th><th>Ações</th></tr></thead>
        <tbody id="nfl-rows"></tbody>
      </table>
    </div>
    <button id="nfl-refresh" type="button" class="nfl-secondary">Atualizar lista</button>
    <div id="nfl-block-box">
      <h3>🚫 Bloquear recebimento de emails</h3>
      <p>Escolha o cliente, adicione o email abaixo e ele para de receber os códigos. A lista vale para todos os serviços e também para a consulta do painel principal. Para liberar, use "Liberar" na lista.</p>
      <form id="nfl-block-form">
        <textarea id="nfl-block-emails" rows="4" maxlength="60000" required placeholder="cliente1@exemplo.com&#10;cliente2@exemplo.com" aria-label="Emails que não podem receber códigos"></textarea>
        <small>Um email por linha (ou separados por vírgula). Bloquear o endereço base também bloqueia os apelidos com +tag.</small>
        <button type="submit" id="nfl-block-button">Bloquear recebimento</button>
      </form>
      <div class="nfl-scroll">
        <table>
          <thead><tr><th>Email bloqueado</th><th>Bloqueado em</th><th>Por</th><th>Ações</th></tr></thead>
          <tbody id="nfl-blocked-rows"></tbody>
        </table>
      </div>
    </div>`;

  const main = document.querySelector('.main');
  if (!main) return;
  main.append(section);

  const welcome = document.createElement('p');
  welcome.textContent = 'Acesso: ' + identity.username + (identity.principal ? ' — administrador principal' : ' — somente seus emails');
  section.prepend(welcome);
  if (!identity.principal) {
    const logout = document.createElement('button');
    logout.type = 'button'; logout.className = 'nfl-secondary'; logout.textContent = 'Sair deste acesso';
    logout.onclick = async () => { await fetch('/api/netflix-admin/logout', { method: 'POST' }); location.replace('/netflix-admin/login'); };
    section.prepend(logout);
  }

  const el = id => section.querySelector('#' + id);
  const message = text => { el('nfl-admin-status').textContent = text; };
  const tabBar = section.querySelector('.nfl-tabs');
  let items = [];
  let generatedItems = [];
  let blockedItems = [];

  const tabButtons = SERVICES.map(cfg => {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.service = cfg.key;
    button.textContent = cfg.icon + ' ' + cfg.name;
    button.onclick = () => { if (currentService !== cfg.key) switchService(cfg.key); };
    tabBar.append(button);
    return button;
  });

  function paintTabs() {
    tabButtons.forEach(button => {
      const active = button.dataset.service === currentService;
      button.classList.toggle('nfl-tab-active', active);
      button.setAttribute('aria-selected', String(active));
      const cfg = byKey[button.dataset.service];
      button.style.borderColor = active ? cfg.color : '';
      button.style.color = active ? cfg.color : '';
    });
    const cfg = byKey[currentService];
    el('nfl-create-button').textContent = 'Gerar links ' + cfg.name + ' para os emails';
    el('nfl-add-help').textContent = 'Até 200 emails por vez. Use um por linha ou separe por vírgula ou ponto e vírgula. Emails já cadastrados mantêm seu link atual. Os links gerados aqui são ' + cfg.hint + '.';
  }

  async function api(path = '', body) {
    const url = '/api/admin/netflix-links' + path + (body ? '' : '?service=' + encodeURIComponent(currentService));
    const response = await fetch(url, {
      method: body ? 'POST' : 'GET', cache: 'no-store',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(Object.assign({ service: currentService }, body)) : undefined
    });
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.message || 'Não foi possível concluir.');
    return data;
  }

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); message('Copiado.'); }
    catch {
      el('nfl-generated').hidden = false;
      el('nfl-generated-url').value = text;
      el('nfl-generated-url').select();
      message('Selecione e copie o texto no campo acima.');
    }
  }

  function showLinks(generated) {
    generatedItems = generated.slice();
    el('nfl-generated').hidden = generatedItems.length === 0;
    el('nfl-generated-url').value = generatedItems.map(item => item.email + '\n' + item.url).join('\n\n');
  }

  function isBlocked(email) {
    const target = String(email || '').trim().toLowerCase();
    if (!target) return false;
    const set = new Set(blockedItems.map(item => String(item.email || '').toLowerCase()));
    if (set.has(target)) return true;
    const at = target.indexOf('@');
    if (at < 0) return false;
    const local = target.slice(0, at);
    const domain = target.slice(at + 1);
    if (!local.includes('+')) return false;
    return set.has(local.split('+')[0] + '@' + domain);
  }

  async function blockEmails(text) {
    const data = await blockApi('', { emails: text });
    blockedItems = data.items || [];
    renderBlocked();
    render();
    const notes = [];
    if (data.added) notes.push(data.added + ' email(s) bloqueado(s)');
    if (data.already) notes.push(data.already + ' já estava(m) na lista');
    if (data.invalid_emails && data.invalid_emails.length) notes.push('Inválidos ignorados: ' + data.invalid_emails.join(', '));
    return (notes.join(' · ') || 'Nada alterado') + '. Esses emails não recebem mais códigos.';
  }

  function render() {
    const query = el('nfl-search').value.trim().toLowerCase();
    const rows = el('nfl-rows');
    rows.replaceChildren();
    const visible = items.filter(item => item.email.includes(query));
    if (!visible.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.textContent = 'Nenhum email encontrado.';
      tr.append(td);
      rows.append(tr);
    }
    visible.forEach(item => {
      const blocked = isBlocked(item.email);
      const tr = document.createElement('tr');
      if (blocked) tr.className = 'nfl-row-blocked';
      const emailCell = document.createElement('td');
      emailCell.textContent = item.email;
      if (blocked) {
        const tag = document.createElement('span');
        tag.className = 'nfl-blocked-tag';
        tag.textContent = '🚫 bloqueado';
        emailCell.append(' ', tag);
      }
      tr.append(emailCell);
      [new Date(item.created_at * 1000).toLocaleString('pt-BR'),
       new Date(item.updated_at * 1000).toLocaleString('pt-BR'),
       item.manager || identity.username].forEach(text => {
        const td = document.createElement('td');
        td.textContent = text;
        tr.append(td);
      });
      const actions = document.createElement('td');
      const copyButton = document.createElement('button');
      copyButton.type = 'button';
      copyButton.textContent = 'Copiar link';
      copyButton.onclick = () => copy(item.url);
      const reset = document.createElement('button');
      reset.type = 'button';
      reset.className = 'nfl-secondary';
      reset.textContent = 'Redefinir link';
      reset.onclick = async () => {
        if (!confirm('Redefinir o link de ' + item.email + '? O link anterior deixará de funcionar.')) return;
        reset.disabled = true;
        try {
          const data = await api('/reset', { email: item.email });
          showLinks([data.item]);
          await load();
          message('Link redefinido. Envie o novo link ao cliente.');
        } catch (error) { message(error.message); } finally { reset.disabled = false; }
      };
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'nfl-danger';
      remove.textContent = 'Excluir email e link';
      remove.onclick = async () => {
        if (!confirm('Excluir o email ' + item.email + ' e seu link? O acesso por esse link será bloqueado. Essa ação não apaga a caixa de email.')) return;
        remove.disabled = true; reset.disabled = true; copyButton.disabled = true;
        try {
          const data = await api('/delete', { email: item.email });
          items = items.filter(existing => existing.email !== item.email);
          showLinks(generatedItems.filter(existing => existing.email !== item.email));
          render();
          message(data.message);
        } catch (error) {
          message(error.message);
          remove.disabled = false; reset.disabled = false; copyButton.disabled = false;
        }
      };
      actions.append(copyButton, reset);
      if (identity.principal) {
        if (blocked) {
          const unblock = document.createElement('button');
          unblock.type = 'button';
          unblock.className = 'nfl-secondary';
          unblock.textContent = 'Liberar recebimento';
          unblock.onclick = async () => {
            unblock.disabled = true;
            try {
              const data = await blockApi('/remove', { email: item.email });
              blockedItems = data.items || [];
              renderBlocked();
              render();
              message(data.message);
            } catch (error) { message(error.message); unblock.disabled = false; }
          };
          actions.append(unblock);
        } else {
          const block = document.createElement('button');
          block.type = 'button';
          block.className = 'nfl-danger';
          block.textContent = 'Bloquear recebimento';
          block.onclick = async () => {
            if (!confirm('Bloquear o recebimento de emails de ' + item.email + '? Ele deixará de receber os códigos até você liberar.')) return;
            block.disabled = true;
            try { message(await blockEmails(item.email)); }
            catch (error) { message(error.message); block.disabled = false; }
          };
          actions.append(block);
        }
      }
      actions.append(remove);
      tr.append(actions);
      rows.append(tr);
    });
  }

  function renderBlocked() {
    const rows = el('nfl-blocked-rows');
    rows.replaceChildren();
    if (!blockedItems.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 4;
      td.textContent = 'Nenhum email bloqueado no momento.';
      tr.append(td);
      rows.append(tr);
      return;
    }
    blockedItems.forEach(item => {
      const tr = document.createElement('tr');
      [item.email,
       item.created_at ? new Date(item.created_at * 1000).toLocaleString('pt-BR') : '—',
       item.created_by || 'admin'].forEach(text => {
        const td = document.createElement('td');
        td.textContent = text;
        tr.append(td);
      });
      const actions = document.createElement('td');
      const unblock = document.createElement('button');
      unblock.type = 'button';
      unblock.className = 'nfl-secondary';
      unblock.textContent = 'Liberar';
      unblock.onclick = async () => {
        if (!confirm('Liberar ' + item.email + '? Ele voltará a receber os códigos.')) return;
        unblock.disabled = true;
        try {
          const data = await blockApi('/remove', { email: item.email });
          blockedItems = data.items || [];
          renderBlocked();
          message(data.message);
        } catch (error) { message(error.message); unblock.disabled = false; }
      };
      actions.append(unblock);
      tr.append(actions);
      rows.append(tr);
    });
  }

  async function loadBlocked() {
    const response = await fetch('/api/admin/netflix-links/blocked', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.message || 'Não foi possível carregar a lista de bloqueio.');
    blockedItems = data.items || [];
    renderBlocked();
  }

  async function blockApi(path = '', body) {
    const response = await fetch('/api/admin/netflix-links/blocked' + path, {
      method: body ? 'POST' : 'GET', cache: 'no-store',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined
    });
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.message || 'Não foi possível concluir.');
    return data;
  }

  async function load() {
    const data = await api();
    items = data.items;
    render();
  }

  async function switchService(service) {
    currentService = service;
    const params = new URLSearchParams(location.search);
    params.set('service', service);
    history.replaceState(null, '', location.pathname + '?' + params.toString());
    paintTabs();
    el('nfl-search').value = '';
    showLinks([]);
    message('Carregando ' + byKey[service].name + '…');
    try { await load(); message(''); } catch (error) { items = []; render(); message(error.message); }
  }

  el('nfl-search').addEventListener('input', render);
  el('nfl-refresh').onclick = async () => {
    try { await load(); message('Lista atualizada.'); } catch (error) { message(error.message); }
  };
  el('nfl-generated-copy').onclick = () => copy(el('nfl-generated-url').value);
  el('nfl-create').addEventListener('submit', async event => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button');
    button.disabled = true;
    const serviceName = byKey[currentService].name;
    try {
      const data = await api('', { emails: el('nfl-add-email').value });
      showLinks(data.items);
      el('nfl-add-email').value = '';
      await load();
      const notes = [data.created + ' link(s) ' + serviceName + ' novo(s)', data.existing + ' já cadastrado(s) mantido(s)'];
      if (data.duplicates) notes.push(data.duplicates + ' repetido(s) ignorado(s)');
      if (data.invalid_emails.length) notes.push('Inválidos não adicionados: ' + data.invalid_emails.join(', '));
      if (data.conflict_emails && data.conflict_emails.length) notes.push('Já pertencem a outro acesso e não foram adicionados: ' + data.conflict_emails.join(', '));
      message(notes.join(' · ') + '. Copie os links e envie cada um ao respectivo cliente.');
    } catch (error) { message(error.message); } finally { button.disabled = false; }
  });

  // Bloqueio de recebimento: exclusivo do administrador principal.
  const blockBox = el('nfl-block-box');
  if (!identity.principal) {
    if (blockBox) blockBox.hidden = true;
  } else if (blockBox) {
    el('nfl-block-form').addEventListener('submit', async event => {
      event.preventDefault();
      const button = el('nfl-block-button');
      button.disabled = true;
      try {
        const data = await blockApi('', { emails: el('nfl-block-emails').value });
        el('nfl-block-emails').value = '';
        blockedItems = data.items || [];
        renderBlocked();
        const notes = [];
        if (data.added) notes.push(data.added + ' email(s) bloqueado(s)');
        if (data.already) notes.push(data.already + ' já estava(m) na lista');
        if (data.invalid_emails && data.invalid_emails.length) notes.push('Inválidos ignorados: ' + data.invalid_emails.join(', '));
        message((notes.join(' · ') || 'Nada alterado') + '. Esses emails não recebem mais códigos.');
      } catch (error) { message(error.message); } finally { button.disabled = false; }
    });
  }

  paintTabs();
  try { await load(); } catch (error) { message(error.message); }
  if (identity.principal) {
    try { await loadBlocked(); } catch (error) { message(error.message); }
  }
})();
