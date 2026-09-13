const COOKIE='shturman_session';
const encoder=new TextEncoder();
function bytesToB64(bytes){let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}
function b64ToBytes(s){s=s.replaceAll('-','+').replaceAll('_','/');while(s.length%4)s+='=';const bin=atob(s);return Uint8Array.from(bin,c=>c.charCodeAt(0))}
async function digest(data){return crypto.subtle.digest('SHA-256',typeof data==='string'?encoder.encode(data):data)}
async function hashPassword(password,saltB64){const salt=b64ToBytes(saltB64);const key=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},key,256);return bytesToB64(new Uint8Array(bits))}
async function newSalt(){const b=new Uint8Array(16);crypto.getRandomValues(b);return bytesToB64(b)}
async function newToken(){const b=new Uint8Array(32);crypto.getRandomValues(b);return bytesToB64(b)}
async function tokenHash(token){return bytesToB64(new Uint8Array(await digest(token)))}
function cookieToken(request){const h=request.headers.get('Cookie')||'';const m=h.match(new RegExp('(?:^|;\\s*)'+COOKIE+'=([^;]+)'));return m?.[1]||null}
function cookieHeader(token,maxAge){return `${COOKIE}=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`}
async function createSession(env,userId){const token=await newToken(),th=await tokenHash(token),expires=Math.floor(Date.now()/1000)+60*60*24*30;await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(th,userId,expires).run();return {token,expires}}
async function getUser(request,env){const token=cookieToken(request);if(!token||!env.DB)return null;const th=await tokenHash(token);const row=await env.DB.prepare('SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(th,Math.floor(Date.now()/1000)).first();return row||null}
function json(data,status=200,headers={}){return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers}})}
function validUsername(u){return /^[\p{L}\p{N}_-]{3,24}$/u.test(u)}
function validEmail(e){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e||'').trim()) && String(e||'').trim().length<=254}
async function randomToken(){return newToken()}
export {hashPassword,newSalt,createSession,getUser,cookieToken,tokenHash,cookieHeader,json,validUsername,validEmail,randomToken};
