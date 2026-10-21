'use strict';
(() => {
  let token = location.hash.slice(1);
  const el = id => document.getElementById(id);
  const status = text => { el('nfl-status').textContent = text; };
  const url = () => location.origin + '/netflix#' + token;
  const labels = {
    'netflix': 'Código de acesso',
    'netflix-login': 'Acesso início',
    'netflix-temp': 'Acesso temporário',
    'netflix-residence': 'Atualização de residência',
    'password-reset': 'Redefinir senha'
  };
  async function api(action, method = 'GET') {
    const requestedToken = token;
    const response = await fetch('/api/netflix-link/' + action, { method, cache: 'no-store', credentials: 'omit', headers: { Authorization: 'Bearer ' + requestedToken } });
    const data = await response.json();
    if (token !== requestedToken) throw new Error('O link mudou. Atualize a consulta.');
    if (!response.ok || !data.success) throw new Error(data.message || 'Não foi possível concluir.');
    return data;
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); status('Link copiado.'); }
    catch { status('Copie o link exibido na barra de endereço do navegador.'); }
  }
  function renderItems(data) {
    const result = el('nfl-result');
    result.replaceChildren();
    const items = Array.isArray(data.results) && data.results.length
      ? data.results
      : (data.code || data.link)
        ? [{ type: data.code ? 'code' : 'link', value: data.code || data.link, platform: data.platform, label: labels[data.platform] || data.platform || 'Netflix' }]
        : [];
    if (!items.length) {
      result.textContent = data.message || 'Nenhum código Netflix recente encontrado.';
      return;
    }
    const intro = document.createElement('p');
    intro.className = 'nfl-result-intro';
    intro.textContent = 'Filtros encontrados para este email: ' + items.length;
    result.append(intro);
    const list = document.createElement('div');
    list.className = 'nfl-results';
    items.forEach(item => {
      const card = document.createElement('article');
      card.className = 'nfl-result-card';
      const heading = document.createElement('strong');
      heading.className = 'nfl-result-label';
      heading.textContent = item.label || labels[item.platform] || item.platform || 'Netflix';
      card.append(heading);
      if (item.type === 'code') {
        const code = document.createElement('strong');
        code.className = 'nfl-code';
        code.textContent = item.value;
        card.append(code);
        const copyButton = document.createElement('button');
        copyButton.textContent = 'Copiar código';
        copyButton.onclick = async () => {
          try { await navigator.clipboard.writeText(item.value); status('Código copiado.'); }
          catch { status('Selecione o código acima para copiar.'); }
        };
        card.append(copyButton);
      } else if (item.type === 'link') {
        const link = document.createElement('a');
        link.textContent = 'Abrir confirmação Netflix';
        link.href = item.value;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        card.append(link);
      }
      list.append(card);
    });
    result.append(list);
  }
  el('nfl-query').addEventListener('click', async () => {
    const button = el('nfl-query');
    button.disabled = true;
    const result = el('nfl-result');
    result.textContent = 'Consultando todos os filtros do email…';
    try {
      const data = await api('code', 'POST');
      renderItems(data);
    } catch (error) { result.textContent = error.message; }
    finally { button.disabled = false; }
  });
  el('nfl-copy').onclick = () => copy(url());
  async function validateLink() {
    token = location.hash.slice(1);
    el('nfl-controls').hidden = true;
    el('nfl-result').textContent = '';
    status('Validando seu link…');
    try {
      const data = await api('access');
      el('nfl-email').textContent = data.email;
      el('nfl-controls').hidden = false;
      status('');
    } catch (error) { el('nfl-email').textContent = ''; status(error.message); }
  }
  window.addEventListener('hashchange', validateLink);
  validateLink();
})();
