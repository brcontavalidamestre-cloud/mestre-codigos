'use strict';
const get = id => document.getElementById(id);
const login = get('login'), tray = get('tray'), status = get('status'), rows = get('rows');
let active = false, busy = false;
async function api(path, data) {
  const response = await fetch('/bandeja-extra/' + path, data ? {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)} : {cache:'no-store'});
  return response.json();
}
function show(enabled) {
  active = enabled; login.hidden = enabled; tray.hidden = !enabled;
  if (!enabled) { rows.replaceChildren(); get('address').textContent = ''; }
}
async function load() {
  if (!active || busy) return;
  busy = true;
  try {
    const j = await api('messages');
    if (!active) return;
    if (!j.success) { show(false); status.textContent = j.message; return; }
    get('address').textContent = j.email;
    rows.replaceChildren(...j.items.map(item => {
      const row = document.createElement('tr');
      for (const text of [item.platform, 'Mensagem recebida', new Date(item.date_ts * 1000).toLocaleString('pt-BR')]) {
        const cell = row.insertCell(); cell.textContent = text;
      }
      return row;
    }));
    status.textContent = j.partial ? 'Uma ou mais caixas não responderam. Tentaremos novamente.' : j.items.length ? 'Atualizado às ' + new Date().toLocaleTimeString('pt-BR') : 'Nenhuma mensagem dos filtros ativos nos últimos 15 minutos.';
  } catch { if (active) status.textContent = 'Não foi possível atualizar. Tentaremos novamente.'; }
  finally { busy = false; }
}
login.onsubmit = async event => {
  event.preventDefault();
  const button = login.querySelector('button'); button.disabled = true;
  try {
    const j = await api('login', Object.fromEntries(new FormData(login)));
    login.elements.password.value = '';
    if (!j.success) { status.textContent = j.message; return; }
    show(true); status.textContent = 'Consultando a bandeja…'; await load();
  } catch { status.textContent = 'Erro de conexão.'; }
  finally { button.disabled = false; }
};
get('refresh').onclick = load;
get('logout').onclick = async () => {
  try { await api('logout', {}); show(false); status.textContent = 'Sessão encerrada.'; }
  catch { status.textContent = 'Não foi possível sair. Tente novamente.'; }
};
setInterval(load, 12000);
api('messages?status=1').then(j => { if (j.success && !active) { show(true); load(); } }).catch(() => {});
