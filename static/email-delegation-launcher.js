'use strict';
(async()=>{
 if(location.hostname!=='consulta-codigos-jr7z.onrender.com'||location.pathname!=='/admin')return;
 try{
  const identity=await(await fetch('/api/auth/me',{cache:'no-store'})).json();if(!identity.logged_in||identity.role!=='admin')return;
  const main=document.querySelector('.main');if(!main)return;
  if(identity.username==='admin'){
  const link=document.createElement('a');link.id='email-pool-launcher';link.href='/admin/emails-subadmins';link.className='btn-ref';link.style.cssText='display:block;text-align:center;margin:14px 0;padding:18px;border-color:#38bdf8;color:#a5e3ff;font-size:1rem';link.textContent='📋 Listas antigas de e-mails — administrar';main.prepend(link);
  }
  const form=document.getElementById('vinculos-form');if(form&&identity.username!=='admin'){const note=document.createElement('p');note.style.color='#a5e3ff';note.textContent='Cadastre e-mails para os clientes que você gerencia. Para um endereço novo, o titular confirma o vínculo pelo e-mail recebido. Não é necessária autorização prévia do admin principal.';form.prepend(note);}
 }catch{}
})();
