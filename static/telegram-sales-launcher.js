'use strict';
(async()=>{
 if(location.hostname!=='lojamestre.onrender.com'||location.pathname!=='/admin')return;
 try{
  const user=await(await fetch('/api/auth/me',{cache:'no-store'})).json();
  if(!user.logged_in||user.role!=='admin'||user.username!=='admin')return;
  const main=document.querySelector('.main');if(!main)return;
  const link=document.createElement('a');link.href='/admin/telegram-vendas';link.className='btn-ref';link.id='telegram-sales-launcher';link.style.cssText='display:block;margin:14px 0;padding:18px;text-align:center;border-color:#38bdf8;color:#a5e3ff;font-size:1rem';link.textContent='📨 Vendas e avisos do Telegram';main.prepend(link);
 }catch{}
})();
