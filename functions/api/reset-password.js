import {json,tokenHash,hashPassword,newSalt,createSession} from '../_auth.js';

export async function onRequestPost({request,env}){
  try{
    if(!env.DB)return json({error:'D1 binding DB не подключён'},500);
    const body=await request.json();
    const token=String(body.token||'');
    const password=String(body.password||'');
    if(token.length<20)return json({error:'Ссылка восстановления некорректна или устарела'},400);
    if(password.length<6||password.length>128)return json({error:'Пароль должен содержать от 6 до 128 символов'},400);
    const th=await tokenHash(token);
    const row=await env.DB.prepare('SELECT token_hash,user_id FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?').bind(th,Math.floor(Date.now()/1000)).first();
    if(!row)return json({error:'Ссылка восстановления недействительна или уже использована'},400);
    const salt=await newSalt(),hash=await hashPassword(password,salt);
    await env.DB.prepare('UPDATE users SET password_hash=?,password_salt=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(hash,salt,row.user_id).run();
    await env.DB.prepare('UPDATE password_reset_tokens SET used_at=? WHERE token_hash=?').bind(Math.floor(Date.now()/1000),th).run();
    await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(row.user_id).run();
    const s=await createSession(env,row.user_id);
    return json({ok:true},200,{headers:{'Set-Cookie':`shturman_session=${s.token}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax`}});
  }catch(e){return json({error:`Ошибка сброса пароля: ${String(e?.message||e)}`},500)}
}
