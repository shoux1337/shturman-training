import {json} from '../_auth.js';
export async function onRequestGet({env}) {
  try {
    if (!env.DB) return json({ok:false,error:'D1 binding DB не подключён'},500);
    const tables = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users','sessions') ORDER BY name").all();
    return json({ok:true, db:true, tables:(tables.results||[]).map(x=>x.name)});
  } catch (e) {
    return json({ok:false,error:String(e?.message||e)},500);
  }
}
