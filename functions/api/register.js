import {hashPassword,newSalt,createSession,json,validUsername} from '../_auth.js';
export async function onRequestPost({request,env}){
  try{
    if(!env.DB)return json({error:'D1 binding DB не подключён'},500);
    const body=await request.json();const username=String(body.username||'').trim();const password=String(body.password||'');const email=String(body.email||'').trim().toLowerCase();
    if(!validUsername(username))return json({error:'Ник: 3–24 символа, буквы, цифры, _ или -'},400);
    if(password.length<6||password.length>128)return json({error:'Пароль должен содержать от 6 до 128 символов'},400);
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)return json({error:'Укажи корректный email'},400);
    const exists=await env.DB.prepare('SELECT id FROM users WHERE username=? COLLATE NOCASE').bind(username).first();if(exists)return json({error:'Такой ник уже занят'},409);const emailExists=await env.DB.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE').bind(email).first();if(emailExists)return json({error:'Этот email уже используется'},409);
    const salt=await newSalt(),hash=await hashPassword(password,salt);const r=await env.DB.prepare('INSERT INTO users(username,email,password_hash,password_salt) VALUES(?,?,?,?,?)').bind(username,email,hash,salt).run();
    const s=await createSession(env,r.meta.last_row_id);return json({user:{username,role:'user'},ok:true},200,{headers:{'Set-Cookie':`shturman_session=${s.token}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax`}})
  }catch(e){return json({error:`Ошибка регистрации: ${String(e?.message||e)}`},500)}
}
