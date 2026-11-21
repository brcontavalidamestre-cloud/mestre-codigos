'use strict';
const el = id => document.getElementById(id);
let timer, generation = 0, live = false;
async function load(read) {
  clearTimeout(timer);
  const id = ++generation, select = el('email'), address = read ? select.value : '';
  el('refresh').disabled = true;
  el('status').textContent = address ? 'Consultando recebimentos…' : 'Carregando endereços…';
  try {
    const res = await fetch('/api/admin-extra/status' + (address ? '?email=' + encodeURIComponent(address) : ''), {cache:'no-store', signal:AbortSignal.timeout(25000)});
    if (id !== generation) return;
    const data = await res.json();
    if (id !== generation) return;
    if (!res.ok) {
      el('items').replaceChildren();
      if (res.status === 403 && !address) { location.assign('/login'); return; }
      el('status').textContent = data.message;
      if (address && res.status === 403) { select.replaceChildren(); timer = setTimeout(() => load(false), 12000); }
      return;
    }
    const choice = select.value;
    select.replaceChildren(...data.emails.map(email => new Option(email,email)));
    if (data.emails.includes(choice)) select.value = choice;
    el('items').replaceChildren(...data.items.map(item => {
      const li = document.createElement('li');
      li.textContent = `${item.platform} · ${new Date(item.date_ts * 1000).toLocaleString('pt-BR')}`;
      return li;
    }));
    el('status').textContent = !select.value ? 'Nenhum e-mail ativo vinculado a este perfil.' : !address ? 'Selecione o e-mail e consulte.' : data.partial ? 'Uma ou mais caixas não responderam.' : data.items.length ? 'Recebimentos recentes' : 'Nenhuma mensagem encontrada nos últimos 15 minutos.';
  } catch { if (id === generation) el('status').textContent = 'Não foi possível atualizar. Tente novamente.'; }
  finally {
    if (id === generation) {
      el('refresh').disabled = !select.value;
      if (live && select.value) timer = setTimeout(() => load(true), 12000);
    }
  }
}
function tab(inbox) {
  live = inbox;
  el('query').setAttribute('aria-pressed',!inbox);
  el('inbox').setAttribute('aria-pressed',inbox);
  el('title').textContent = inbox ? 'Caixa de Entrada' : 'Consultar recebimento';
  load(inbox && Boolean(el('email').value));
}
el('query').onclick = () => tab(false);
el('inbox').onclick = () => tab(true);
el('refresh').onclick = () => load(true);
el('email').onchange = () => load(true);
el('logout').onclick = async () => {
  try {
    const res = await fetch('/api/auth/logout', {method:'POST'});
    if (res.ok) location.assign('/login');
    else el('status').textContent = 'Não foi possível encerrar a sessão.';
  } catch { el('status').textContent = 'Não foi possível encerrar a sessão.'; }
};
load(false);
