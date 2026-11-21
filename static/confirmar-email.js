'use strict';
const token = location.hash.slice(1);
const button = document.getElementById('confirm');
const status = document.getElementById('status');
const login = document.getElementById('login');
if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
  button.disabled = true; status.textContent = 'Link de confirmação inválido.';
} else {
  login.href = '/login#confirmar-email=' + token;
  login.hidden = false;
  button.onclick = async () => {
    button.disabled = true;
    try {
      const response = await fetch('/api/confirmar-email', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token})});
      const data = await response.json();
      status.textContent = data.message || 'Não foi possível confirmar o vínculo.';
      if (data.success) { login.hidden = true; history.replaceState(null, '', '/confirmar-email'); return; }
    } catch { status.textContent = 'Não foi possível confirmar agora.'; }
    button.disabled = false;
  };
}
