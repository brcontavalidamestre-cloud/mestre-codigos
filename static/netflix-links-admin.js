'use strict';
(async () => {
  if (location.hostname !== 'consulta-codigos-jr7z.onrender.com') return;
  if (location.pathname === '/admin' && document.getElementById('nfl-nav-link')) return;
  const directPanel = location.pathname === '/admin/netflix-links';
  let identity;
  try {
    identity = await (await fetch('/api/netflix-admin/me', {cache:'no-store'})).json();
    if (!identity.success) { if (directPanel) location.replace('/netflix-admin/login'); return; }
  } catch { return; }
  const back = document.getElementById('nfl-back-link');
  if (back && !identity.principal && identity.kind !== 'panel') {
    back.href = '/netflix-admin/login';
    back.textContent = 'Acesso exclusivo — Links Netflix';
  }
  if (directPanel && !identity.principal && identity.kind !== 'panel') {
    const directory = document.getElementById('restricted-email-directory');
    if (directory) {
      const logout=document.createElement('button'); logout.type='button'; logout.className='nfl-secondary'; logout.textContent='Sair deste acesso';
      logout.onclick=async()=>{const response=await fetch('/api/netflix-admin/logout',{method:'POST'});if(response.ok)location.replace('/netflix-admin/login');};
      directory.prepend(logout);
    }
    return;
  }
})();
