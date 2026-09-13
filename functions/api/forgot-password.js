import {json,tokenHash,randomToken,validEmail} from '../_auth.js';

export async function onRequestPost({request,env}){
  try{
    if(!env.DB)return json({error:'D1 binding DB не подключён'},500);
    const body=await request.json();
    const email=String(body.email||'').trim().toLowerCase();
    // Always return the same response for valid-looking emails to avoid account enumeration.
    if(!validEmail(email))return json({ok:true,message:'Если аккаунт с таким email существует, письмо уже отправляется.'});
    const u=await env.DB.prepare('SELECT id,username,email FROM users WHERE email=? COLLATE NOCASE').bind(email).first();
    if(!u)return json({ok:true,message:'Если аккаунт с таким email существует, письмо уже отправляется.'});

    await env.DB.prepare('DELETE FROM password_reset_tokens WHERE user_id=? OR expires_at<?').bind(u.id,Math.floor(Date.now()/1000)).run();
    const token=await randomToken();
    const hash=await tokenHash(token);
    const expires=Math.floor(Date.now()/1000)+30*60;
    await env.DB.prepare('INSERT INTO password_reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(hash,u.id,expires).run();

    if(!env.RESEND_API_KEY){
      await env.DB.prepare('DELETE FROM password_reset_tokens WHERE token_hash=?').bind(hash).run();
      return json({error:'Сервис восстановления email пока не настроен администратором'},503);
    }
    const base=String(env.APP_URL||new URL(request.url).origin).replace(/\/$/,'');
    const link=`${base}/#reset/${encodeURIComponent(token)}`;
    const from=String(env.RESEND_FROM_EMAIL||'onboarding@resend.dev');
    const html=`<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#132238"><h2>⚓ Штурман — восстановление пароля</h2><p>Для аккаунта <b>${escapeHtml(u.username)}</b> запрошен сброс пароля.</p><p><a href="${link}" style="display:inline-block;background:#3467ff;color:#fff;text-decoration:none;padding:12px 18px;border-radius:10px">Сбросить пароль</a></p><p style="color:#68778c;font-size:13px">Ссылка действует 30 минут и может быть использована один раз.</p><p style="color:#68778c;font-size:12px">Если ты не запрашивал восстановление, просто проигнорируй это письмо.</p></div>`;
    const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{'Authorization':`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from,to:[email],subject:'Штурман — восстановление пароля',html})});
    if(!r.ok){const txt=await r.text();await env.DB.prepare('DELETE FROM password_reset_tokens WHERE token_hash=?').bind(hash).run();return json({error:`Не удалось отправить письмо: ${txt.slice(0,240)}`},502)}
    return json({ok:true,message:'Если аккаунт с таким email существует, письмо уже отправляется.'});
  }catch(e){return json({error:`Ошибка восстановления: ${String(e?.message||e)}`},500)}
}
function escapeHtml(s){return String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
