import {hashPassword,createSession,json} from '../_auth.js';
export async function onRequestPost({request,env}){
  try{
    if(!env.DB)return json({error:'D1 binding DB не подключён. В Cloudflare: Settings → Bindings → Add → D1 database, Variable name: DB.'},500);
    const body=await request.json();const username=String(body.username||'').trim();const password=String(body.password||'');
    const u=await env.DB.prepare('SELECT id,username,password_hash,password_salt FROM users WHERE username=? COLLATE NOCASE').bind(username).first();
    if(!u)return json({error:'Неверный ник или пароль'},401);
    const h=await hashPassword(password,u.password_salt);if(h!==u.password_hash)return json({error:'Неверный ник или пароль'},401);
    const s=await createSession(env,u.id);
    return json({user:{username:u.username},ok:true},200,{headers:{'Set-Cookie':`shturman_session=${s.token}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax`}})
  }catch(e){return json({error:`Ошибка входа: ${String(e?.message||e)}`},500)}
}
