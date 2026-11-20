'use strict';
(async()=>{
 if(location.hostname!=='consulta-codigos-jr7z.onrender.com'||location.pathname!=='/admin')return;
 try{
  const identity=await(await fetch('/api/auth/me',{cache:'no-store'})).json();if(!identity.logged_in||identity.role!=='admin')return;
  const main=document.querySelector('.main');if(!main)return;
  const link=document.createElement('a');link.id='email-pool-launcher';link.href='/admin/emails-subadmins';link.className='btn-ref';link.style.cssText='display:block;text-align:center;margin:14px 0;padding:18px;border-color:#38bdf8;color:#a5e3ff;font-size:1rem';link.textContent=['admin','carlosadm'].includes(identity.username)?'📋 Emails permitidos por subadmin — definir listas':'📋 Minha lista de emails permitidos';main.prepend(link);
  const form=document.getElementById('vinculos-form');if(form&&!['admin','carlosadm'].includes(identity.username)){const note=document.createElement('p');note.style.color='#a5e3ff';note.textContent='Você só pode vincular ou remover vínculos dos emails da sua lista permitida. Remova o vínculo anterior antes de passar o email para outro cliente seu.';const open=document.createElement('a');open.href='/admin/emails-subadmins';open.textContent=' Abrir minha lista permitida';open.style.color='#a5e3ff';note.append(open);form.prepend(note);}
 }catch{}
})();
