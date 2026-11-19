'use strict';
(async () => {
  const box=document.querySelector('#restricted-email-directory');
  if (!box) return;
  const el=id=>box.querySelector('#red-'+id);
  const form=el('form'), owner=el('owner'), field=el('emails'), filter=el('filter'), list=el('list'), status=el('status');
  form.style.display='none';
  let items=[], principal=false, restricted=false;
  async function api(body) {
    const r=await fetch('/api/netflix-admin/email-directory', { cache:'no-store', method:body?'POST':'GET', headers:body?{'Content-Type':'application/json'}:{}, body:body?JSON.stringify(body):undefined });
    const d=await r.json();
    if (!r.ok||!d.success) throw new Error(d.message||'Não foi possível carregar a lista.');
    return d;
  }
  function render() {
    const q=filter.value.trim().toLowerCase();
    const rows=items.filter(row=>!q||row.email.includes(q)||(principal&&row.username.includes(q)));
    list.replaceChildren();
    if (!rows.length) { const li=document.createElement('li'); li.textContent='Nenhum email encontrado.'; list.append(li); }
    for (const row of rows) {
      const li=document.createElement('li');
      li.style.overflowWrap='anywhere';
      li.textContent=row.email+(principal?' — '+row.username:'');
      if (principal) {
        const button=document.createElement('button');
        button.type='button'; button.className='nfl-secondary'; button.textContent='Remover'; button.setAttribute('aria-label','Remover '+row.email);
        button.onclick=async()=>{
          if (!confirm('Remover '+row.email+' da lista de '+row.username+'?')) return;
          button.disabled=true;
          try { await api({action:'remove',username:row.username,emails:row.email}); await load(); status.textContent='Email removido da lista.'; }
          catch (e) { status.textContent=e.message; }
          finally { button.disabled=false; }
        };
        li.append(' ',button);
      }
      if (restricted) {
        const button=document.createElement('button'); button.type='button'; button.className='nfl-secondary'; button.textContent='Gerar link de status';
        button.onclick=async()=>{
          button.disabled=true;
          try {
            const r=await fetch('/api/netflix-admin/status-link',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:row.email})});
            const d=await r.json(); if(!r.ok||!d.success) throw new Error(d.message||'Não foi possível gerar o link.');
            const input=document.createElement('input');input.readOnly=true;input.value=d.url;input.setAttribute('aria-label','Link de status de '+row.email);
            li.querySelector('input')?.remove();li.append(input);input.select();status.textContent='Link gerado. Copie e compartilhe apenas com o destinatário. Validade: 7 dias.';
          } catch(e) {status.textContent=e.message;}
          finally {button.disabled=false;}
        };
        li.append(' ',button);
      }
      list.append(li);
    }
  }
  async function load() {
    const d=await api(); const current=owner.value;
    items=d.items; principal=d.principal===true;
    if(!principal){ const r=await fetch('/api/netflix-admin/me',{cache:'no-store'});const me=await r.json();restricted=me.success===true && me.kind!=='panel'; }
    owner.replaceChildren(new Option('Selecione um acesso restrito',''), ...d.accounts.map(name=>new Option(name,name)));
    if (d.accounts.includes(current)) owner.value=current;
    form.hidden=!principal; form.style.display=principal?'block':'none';
    render();
  }
  filter.addEventListener('input',render);
  form.addEventListener('submit', async event=>{
    event.preventDefault();
    const button=form.querySelector('button'); button.disabled=true;
    try { await api({action:'assign',username:owner.value,emails:field.value}); field.value=''; await load(); status.textContent='Lista atualizada.'; }
    catch (e) { status.textContent=e.message; }
    finally { button.disabled=false; }
  });
  try { await load(); } catch (e) { status.textContent=e.message; }
})();
