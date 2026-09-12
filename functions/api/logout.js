import {cookieToken,tokenHash,json} from '../_auth.js';
export async function onRequestPost({request,env}){
  try{const t=cookieToken(request);if(t&&env.DB){const h=await tokenHash(t);await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(h).run()}}
  catch(e){}
  return json({ok:true},200,{headers:{'Set-Cookie':'shturman_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax'}})
}
