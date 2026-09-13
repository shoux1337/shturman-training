import {getUser,json,validEmail} from '../_auth.js';
export async function onRequestGet({request,env}){
  const u=await getUser(request,env); if(!u)return json({error:'Не авторизован'},401);
  const row=await env.DB.prepare('SELECT id,username,email,created_at,updated_at FROM users WHERE id=?').bind(u.id).first();
  return json({user:row});
}
export async function onRequestPost({request,env}){
  const u=await getUser(request,env); if(!u)return json({error:'Не авторизован'},401);
  try{
    const body=await request.json(); const email=String(body.email||'').trim().toLowerCase();
    if(!validEmail(email))return json({error:'Укажи корректный email'},400);
    const exists=await env.DB.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE AND id<>?').bind(email,u.id).first();
    if(exists)return json({error:'Этот email уже привязан к другому аккаунту'},409);
    await env.DB.prepare('UPDATE users SET email=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(email,u.id).run();
    return json({ok:true,email});
  }catch(e){return json({error:`Ошибка профиля: ${String(e?.message||e)}`},500)}
}
