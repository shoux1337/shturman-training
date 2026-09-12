import {getUser,json} from '../_auth.js';
export async function onRequestGet({request,env}){const u=await getUser(request,env);return u?json({user:{username:u.username}}):json({error:'Не авторизован'},401)}
