import {cookieToken,tokenHash,json} from '../_auth.js';
export async function onRequestPost({request,env}){const t=cookieToken(request);if(t){const h=await tokenHash(t);await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(h).run()}return json({ok:true},{headers:{'Set-Cookie':'shturman_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax'}})}
