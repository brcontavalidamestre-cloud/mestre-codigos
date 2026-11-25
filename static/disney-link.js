'use strict';
(() => {
  const SERVICE = 'disney';
  const API = '/api/disney-link/';
  const PATH = '/disney';
  const ALLOWED_HOSTS = ['disneyplus.com', 'disney.com'];
  let token = location.hash.slice(1);
  const el = id => document.getElementById(id);
  const status = text => { el('nfl-status').textContent = text; };
  const url = () => location.origin + PATH + '#' + token;
  async function api(action, method = 'GET') {
    const requestedToken = token;
    const response = await fetch(API + action, { method, cache: 'no-store', credentials: 'omit', headers: { Authorization: 'Bearer ' + requestedToken } });
    const data = await response.json();
    if (token !== requestedToken) throw new Error('O link mudou. Atualize a consulta.');
    if (!response.ok || !data.success) throw new Error(data.message || 'Não foi possível concluir.');
    return data;
  }
  async function copy(text, message) {
    try { await navigator.clipboard.writeText(text); status(message || 'Copiado.'); }
    catch { status('Selecione o código ou o endereço exibido para copiar.'); }
  }
  function hostAllowed(hostname) {
    return ALLOWED_HOSTS.some(host => hostname === host || hostname.endsWith('.' + host));
  }
  function resultCard(item) {
    const card = document.createElement('article'); card.className = 'nfl-result-card';
    const heading = document.createElement('h2'); heading.textContent = item.label || 'Disney+'; card.append(heading);
    if (item.type === 'code') {
      const code = document.createElement('strong'); code.className = 'nfl-code'; code.textContent = item.value; card.append(code);
      const button = document.createElement('button'); button.textContent = 'Copiar código';
      button.onclick = () => copy(item.value, 'Código copiado.'); card.append(button);
    } else if (item.type === 'link') {
      let parsed;
      try { parsed = new URL(item.value); } catch { return null; }
      if (parsed.protocol !== 'https:' || !hostAllowed(parsed.hostname) || parsed.username || parsed.password) return null;
      const link = document.createElement('a'); link.href = item.value; link.target = '_blank'; link.rel = 'noopener noreferrer';
      link.className = 'nfl-action-link';
      link.textContent = item.platform === 'disney-residence' ? 'Abrir confirmação de residência Disney+' : 'Abrir acesso Disney+';
      card.append(link);
      const address = document.createElement('input'); address.readOnly = true; address.value = item.value;
      address.setAttribute('aria-label', 'Link: ' + (item.label || 'Disney+')); card.append(address);
      const button = document.createElement('button'); button.className = 'nfl-secondary'; button.textContent = 'Copiar link';
      button.onclick = () => copy(item.value, 'Link Disney+ copiado.'); card.append(button);
    } else return null;
    return card;
  }
  el('nfl-query').addEventListener('click', async () => {
    const button = el('nfl-query'); button.disabled = true;
    const result = el('nfl-result'); result.textContent = 'Consultando todos os filtros Disney+ deste email…'; status('');
    try {
      const data = await api('code', 'POST'); result.replaceChildren();
      let items = Array.isArray(data.results) ? data.results : [];
      if (!items.length && (data.code || data.link)) items = [{ type: data.code ? 'code' : 'link', value: data.code || data.link, platform: data.platform, label: 'Disney+' }];
      let shown = 0;
      items.forEach(item => { const card = resultCard(item); if (card) { result.append(card); shown++; } });
      if (!shown) result.textContent = data.message || 'Nenhum código ou link Disney+ recente encontrado.';
      else status(shown + ' resultado(s) encontrado(s). ' + (data.warning || ''));
    } catch (error) { result.textContent = error.message; }
    finally { button.disabled = false; }
  });
  el('nfl-copy').onclick = () => copy(url(), 'Link de consulta copiado.');
  async function validateLink() {
    token = location.hash.slice(1); el('nfl-controls').hidden = true; el('nfl-result').textContent = ''; status('Validando seu link…');
    try {
      const data = await api('access'); el('nfl-email').textContent = data.email;
      const filters = el('nfl-filter-list');
      if (filters && Array.isArray(data.filters)) filters.textContent = 'Filtros: ' + data.filters.map(item => item.label).join(' · ');
      const expiry = el('nfl-expiry');
      if (expiry) {
        if (data.expires_at) {
          const until = new Date(data.expires_at * 1000).toLocaleDateString('pt-BR');
          expiry.textContent = 'Este link vale até ' + until + '.';
        } else {
          expiry.textContent = 'Este link não tem prazo de validade.';
        }
      }
      el('nfl-controls').hidden = false; status('');
    } catch (error) { el('nfl-email').textContent = ''; status(error.message); }
  }
  window.addEventListener('hashchange', validateLink); validateLink();
})();
