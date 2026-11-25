'use strict';
(async () => {
  if (location.hostname !== 'jmp-codigos.onrender.com') return;
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

  // Presets de validade. 0 = nunca expira.
  const PRESETS = [
    { days: 0, label: 'Nunca expira' },
    { days: 1, label: '1 dia' },
    { days: 7, label: '7 dias' },
    { days: 15, label: '15 dias' },
    { days: 30, label: '30 dias' },
    { days: 60, label: '60 dias' },
    { days: 90, label: '90 dias' }
  ];
  const MAX_DAYS = 3650;

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
      <fieldset class="nfl-expiry">
        <legend>Validade do link</legend>
        <p class="nfl-expiry-note">Depois do prazo o link para de funcionar sozinho. Com "Nunca expira", ele só é revogado quando você redefinir ou excluir.</p>
        <div class="nfl-expiry-presets" id="nfl-expiry-presets"></div>
        <div class="nfl-expiry-custom">
          <label for="nfl-expiry-days">Outro prazo (em dias)</label>
          <input id="nfl-expiry-days" type="number" min="1" max="3650" step="1" inputmode="numeric" placeholder="ex.: 45" autocomplete="off">
        </div>
        <p class="nfl-expiry-summary" id="nfl-expiry-summary"></p>
      </fieldset>
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
        <thead><tr><th>Email</th><th>Validade</th><th>Criado em</th><th>Última redefinição</th><th>Responsável</th><th>Ações</th></tr></thead>
        <tbody id="nfl-rows"></tbody>
      </table>
    </div>
    <button id="nfl-refresh" type="button" class="nfl-secondary">Atualizar lista</button>`;

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
  let selectedDays = 0;

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

  // ── Validade: presets + prazo livre ──────────────────────────────────────
  const presetBox = el('nfl-expiry-presets');
  const presetButtons = PRESETS.map(preset => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'nfl-preset';
    button.dataset.days = String(preset.days);
    button.textContent = preset.label;
    button.onclick = () => selectDays(preset.days);
    presetBox.append(button);
    return button;
  });

  el('nfl-expiry-days').addEventListener('input', () => {
    const raw = el('nfl-expiry-days').value.trim();
    if (!raw) { selectDays(0); return; }
    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_DAYS) { paintExpiry(); return; }
    selectedDays = parsed;
    paintExpiry();
  });

  function selectDays(days) {
    selectedDays = days;
    if (days === 0) el('nfl-expiry-days').value = '';
    paintExpiry();
  }

  function expirySummary() {
    if (selectedDays > 0) {
      const until = new Date(Date.now() + selectedDays * 86400000);
      return 'O link vale por ' + selectedDays + ' dia(s), até ' + until.toLocaleDateString('pt-BR') + '.';
    }
    const custom = el('nfl-expiry-days').value.trim();
    if (customInvalid(custom)) return 'Informe um número inteiro entre 1 e ' + MAX_DAYS + '.';
    return 'O link nunca expira. Ele só é bloqueado quando você redefinir ou excluir.';
  }

  function customInvalid(custom) {
    if (!custom) return false;
    const parsed = Number(custom);
    return !Number.isInteger(parsed) || parsed < 1 || parsed > MAX_DAYS;
  }

  function paintExpiry() {
    presetButtons.forEach(button => {
      const active = selectedDays === Number(button.dataset.days);
      button.classList.toggle('nfl-preset-active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    el('nfl-expiry-summary').textContent = expirySummary();
    el('nfl-expiry-summary').classList.toggle('nfl-expiry-warn', customInvalid(el('nfl-expiry-days').value.trim()));
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
    el('nfl-generated-url').value = generatedItems.map(item => {
      const validade = item.expires_at ? 'vale até ' + new Date(item.expires_at * 1000).toLocaleDateString('pt-BR') : 'nunca expira';
      return item.email + '\n' + item.url + '\n(' + validade + ')';
    }).join('\n\n');
  }

  function expiryCell(item) {
    const td = document.createElement('td');
    const span = document.createElement('span');
    if (item.expired) {
      span.textContent = 'Expirado';
      span.className = 'nfl-expiry-badge nfl-expiry-expired';
    } else if (!item.expires_at) {
      span.textContent = 'Nunca expira';
      span.className = 'nfl-expiry-badge nfl-expiry-never';
    } else {
      const until = new Date(item.expires_at * 1000).toLocaleDateString('pt-BR');
      span.textContent = until + ' (' + item.expiry_label.replace('Expira em ', '').replace('Expira hoje', 'hoje') + ')';
      span.className = 'nfl-expiry-badge' + (item.expires_in_days !== null && item.expires_in_days <= 3 ? ' nfl-expiry-soon' : '');
    }
    span.title = item.expires_at ? new Date(item.expires_at * 1000).toLocaleString('pt-BR') : 'Sem prazo de validade';
    td.append(span);
    return td;
  }

  function render() {
    const query = el('nfl-search').value.trim().toLowerCase();
    const rows = el('nfl-rows');
    rows.replaceChildren();
    const visible = items.filter(item => item.email.includes(query));
    if (!visible.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.textContent = 'Nenhum email encontrado.';
      tr.append(td);
      rows.append(tr);
    }
    visible.forEach(item => {
      const tr = document.createElement('tr');
      const emailTd = document.createElement('td');
      emailTd.textContent = item.email;
      tr.append(emailTd, expiryCell(item));
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
        const prazo = selectedDays > 0 ? selectedDays + ' dia(s)' : 'nunca expirar';
        if (!confirm('Redefinir o link de ' + item.email + ' com validade: ' + prazo + '?\n\nO link anterior deixará de funcionar imediatamente.')) return;
        reset.disabled = true;
        try {
          const body = { email: item.email };
          if (selectedDays > 0) body.expires_days = selectedDays;
          const data = await api('/reset', body);
          showLinks([data.item]);
          await load();
          message('Link redefinido (' + data.item.expiry_label + '). Envie o novo link ao cliente.');
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
      actions.append(copyButton, reset, remove);
      tr.append(actions);
      rows.append(tr);
    });
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
    const custom = el('nfl-expiry-days').value.trim();
    if (customInvalid(custom)) { message('Informe um número inteiro entre 1 e ' + MAX_DAYS + ' dias, ou escolha nunca expirar.'); return; }
    const button = event.currentTarget.querySelector('button[type="submit"]');
    button.disabled = true;
    const serviceName = byKey[currentService].name;
    try {
      const body = { emails: el('nfl-add-email').value };
      if (selectedDays > 0) body.expires_days = selectedDays;
      const data = await api('', body);
      showLinks(data.items);
      el('nfl-add-email').value = '';
      await load();
      const prazo = selectedDays > 0 ? selectedDays + ' dia(s)' : 'nunca expira';
      const notes = [data.created + ' link(s) ' + serviceName + ' novo(s)', data.existing + ' já cadastrado(s) mantido(s)'];
      if (data.duplicates) notes.push(data.duplicates + ' repetido(s) ignorado(s)');
      if (data.invalid_emails.length) notes.push('Inválidos não adicionados: ' + data.invalid_emails.join(', '));
      if (data.conflict_emails && data.conflict_emails.length) notes.push('Já pertencem a outro acesso e não foram adicionados: ' + data.conflict_emails.join(', '));
      message(notes.join(' · ') + '. Validade: ' + prazo + '. Copie os links e envie cada um ao respectivo cliente.');
    } catch (error) { message(error.message); } finally { button.disabled = false; }
  });

  paintTabs();
  paintExpiry();
  try { await load(); } catch (error) { message(error.message); }
})();
