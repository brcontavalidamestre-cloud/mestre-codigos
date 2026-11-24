'use strict';
(()=>{
  const form=document.getElementById('nfa-login');const status=document.getElementById('nfa-login-status');
  form.addEventListener('submit',async(event)=>{
    event.preventDefault();const button=form.querySelector('button');button.disabled=true;status.textContent='Validando acesso…';
    try{
      const response=await fetch('/api/netflix-admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('nfa-user').value,password:document.getElementById('nfa-pass').value})});
      const data=await response.json();if(!response.ok||!data.success)throw new Error(data.message||'Não foi possível entrar.');
      document.getElementById('nfa-pass').value='';location.replace('/admin/netflix-links');
    }catch(error){status.textContent=error.message;}finally{button.disabled=false;}
  });
})();
