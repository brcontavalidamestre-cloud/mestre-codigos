'use strict';
(() => {
  let token = location.hash.slice(1);
  const el = id => document.getElementById(id);
  const status = text => { el('nfl-status').textContent = text; };
  const url = () => location.origin + '/netflix#' + token;
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
  el('nfl-query').addEventListener('click', async () => {
    const button = el('nfl-query');
    button.disabled = true;
    const result = el('nfl-result');
    result.textContent = 'Consultando a caixa de email…';
    try {
      const data = await api('code', 'POST');
      result.replaceChildren();
      if (data.code) {
        const code = document.createElement('strong');
        code.className = 'nfl-code'; code.textContent = data.code;
        result.append(code);
        const copyButton = document.createElement('button');
        copyButton.textContent = 'Copiar código';
        copyButton.onclick = async () => {
          try { await navigator.clipboard.writeText(data.code); status('Código copiado.'); }
          catch { status('Selecione o código acima para copiar.'); }
        };
        result.append(copyButton);
      } else if (data.link) {
        const link = document.createElement('a');
        link.textContent = 'Abrir confirmação Netflix'; link.href = data.link;
        link.target = '_blank'; link.rel = 'noopener noreferrer';
        result.append(link);
      } else result.textContent = data.message;
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
