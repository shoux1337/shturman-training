import {getUser,json} from '../_auth.js';
export async function onRequestGet({request,env}){const u=await getUser(request,env);return u?json({user:{username:u.username,role:env.ADMIN_USERNAME&&u.username.toLowerCase()===String(env.ADMIN_USERNAME).trim().toLowerCase()?'admin':'user'}}):json({error:'Не авторизован'},401)}
