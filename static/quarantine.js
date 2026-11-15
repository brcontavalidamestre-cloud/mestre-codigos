'use strict';
(()=>{
  const el=id=>document.getElementById(id);let items=[];
  const message=text=>{el('q-status').textContent=text;};
  async function api(path='',body){const response=await fetch('/api/admin/quarantine'+path,{method:body?'POST':'GET',cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await response.json();if(!response.ok||!data.success)throw new Error(data.message||'Não foi possível concluir.');return data;}
  function render(){
    const query=el('q-search').value.trim().toLowerCase();const rows=el('q-rows');rows.replaceChildren();
    const shown=items.filter(item=>item.email.includes(query));el('q-total').textContent=items.length+' email(s) na quarentena';
    if(!shown.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=3;td.textContent='Nenhum email encontrado na quarentena.';tr.append(td);rows.append(tr);}
    shown.forEach(item=>{const tr=document.createElement('tr');[item.email,new Date(item.created_at*1000).toLocaleString('pt-BR')].forEach(text=>{const td=document.createElement('td');td.textContent=text;tr.append(td);});const actions=document.createElement('td');const button=document.createElement('button');button.type='button';button.className='nfl-secondary';button.textContent='Retirar da quarentena';button.onclick=async()=>{if(!confirm('Retirar '+item.email+' da quarentena? A consulta continuará sujeita às regras de vínculo.'))return;button.disabled=true;try{const data=await api('/remove',{email:item.email});await load();message(data.message);}catch(error){message(error.message);button.disabled=false;}};actions.append(button);tr.append(actions);rows.append(tr);});
  }
  let searchVersion=0;
  async function lookup(){
    const query=el('q-lookup').value.trim();const version=++searchVersion;
    const rows=el('q-lookup-rows');rows.replaceChildren();
    if(query.length<2){el('q-lookup-status').textContent='Digite pelo menos 2 caracteres para pesquisar.';return;}
    el('q-lookup-status').textContent='Pesquisando…';
    try{
      const data=await api('/search?q='+encodeURIComponent(query));if(version!==searchVersion)return;
      el('q-lookup-status').textContent=data.total+' registro(s) encontrado(s).'+(data.limited?' Mostrando os primeiros 200. Refine a pesquisa.':'');
      if(!data.items.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=4;td.textContent='Nenhum email encontrado nos clientes ou links.';tr.append(td);rows.append(tr);}
      data.items.forEach(item=>{
        const tr=document.createElement('tr');[item.email,item.client_name&&item.client_name!==item.client?item.client_name+' ('+item.client+')':item.client,item.source_label].forEach(text=>{const td=document.createElement('td');td.textContent=text;tr.append(td);});
        const td=document.createElement('td');const button=document.createElement('button');button.type='button';button.textContent=item.quarantined?'Concluir remoção':'Colocar em quarentena';
        button.onclick=async()=>{
          if(!confirm('Colocar '+item.email+' em quarentena? Todos os vínculos desse email serão removidos e seus links individuais excluídos. Esta ação não apaga o cliente. Retirar da quarentena não restaura os vínculos ou links.'))return;
          button.disabled=true;
          try{const result=await api('',{emails:item.email});await load();await lookup();message(result.message);}catch(error){message(error.message);button.disabled=false;}
        };td.append(button);tr.append(td);rows.append(tr);
      });
    }catch(error){if(version===searchVersion)el('q-lookup-status').textContent=error.message;}
  }
  el('q-lookup-form').onsubmit=event=>{event.preventDefault();lookup();};
  el('q-lookup').addEventListener('input',()=>{searchVersion++;el('q-lookup-rows').replaceChildren();el('q-lookup-status').textContent='';});
  async function load(){const data=await api();items=data.items;render();}
  el('q-form').onsubmit=async(event)=>{event.preventDefault();const button=event.currentTarget.querySelector('button');if(!confirm('Adicionar à quarentena e remover os vínculos e links desses emails? O cadastro dos clientes será preservado. Retirar da quarentena não restaura os vínculos ou links.'))return;button.disabled=true;try{const data=await api('',{emails:el('q-emails').value});el('q-emails').value='';await load();if(el('q-lookup').value.trim().length>=2)await lookup();message(data.message);}catch(error){message(error.message);}finally{button.disabled=false;}};
  el('q-search').addEventListener('input',render);el('q-refresh').onclick=()=>load().catch(error=>message(error.message));load().catch(error=>message(error.message));
})();
