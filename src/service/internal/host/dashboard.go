package host

// dashboardHTML is the built-in vTPM2 management UI (single-page, no external deps).
const dashboardHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>vTPM2 — Software TPM 2.0</title>
<style>
* { box-sizing: border-box; }
body { font-family: Segoe UI, system-ui, -apple-system, sans-serif; margin: 0; background: #f3f4f6; color: #111827; }
header { background: #0f172a; color: #fff; padding: 12px 20px; display:flex; align-items:center; gap:12px; }
header h1 { font-size: 16px; margin: 0; }
header .dot { width: 10px; height: 10px; border-radius: 50%; background: #22c55e; }
main { max-width: 980px; margin: 24px auto; padding: 0 16px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
.card h2 { font-size: 14px; margin: 0 0 12px 0; color: #374151; text-transform: uppercase; letter-spacing: 0.04em; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #f1f5f9; }
th { color: #6b7280; font-size: 11px; text-transform: uppercase; }
tr:nth-child(even) td { background: #fafafa; }
.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; word-break: break-all; }
.row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
input, button, select { font: inherit; padding: 6px 10px; border: 1px solid #d1d5db; border-radius: 4px; background: #fff; }
button { cursor: pointer; background: #111827; color: #fff; border: none; }
button:hover { background: #1f2937; }
button.secondary { background: #e5e7eb; color: #111827; }
button.secondary:hover { background: #d1d5db; }
button.danger { background: #dc2626; }
button.danger:hover { background: #b91c1c; }
.ok { color: #15803d; } .err { color: #dc2626; } .muted { color: #6b7280; font-size: 12px; }
#statusChip { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }
.logs { background: #0b0c10; color: #0f0; border-radius: 6px; padding: 10px; font-family: ui-monospace, monospace; font-size: 12px; max-height: 300px; overflow: auto; }
.logs div { white-space: pre-wrap; border-bottom: 1px solid #1a1d26; padding: 2px 0; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 700px){ .grid-2 { grid-template-columns: 1fr; } }
</style></head>
<body>
<header>
  <span class="dot" id="dot"></span>
  <h1>vTPM2 — Software TPM 2.0</h1>
  <span class="muted" id="mode"></span>
</header>
<main>
  <div class="grid-2">
    <div class="card">
      <h2>Status</h2>
      <div id="status" class="muted">loading…</div>
      <div id="statusChip" class="muted">—</div>
      <p class="muted" id="stateDir"></p>
    </div>
    <div class="card">
      <h2>Capabilities (TPM2_GetCapability)</h2>
      <pre class="mono" id="capability">—</pre>
      <button class="secondary" onclick="load('capability')">Refresh</button>
    </div>
  </div>

  <div class="card">
    <h2>PCR Banks</h2>
    <div id="pcr" class="muted">loading…</div>
    <button class="secondary" onclick="load('pcr')">Refresh</button>
  </div>

  <div class="card">
    <h2>NV Storage</h2>
    <div id="nv" class="muted">loading…</div>
    <button class="secondary" onclick="load('nv')">Refresh</button>
  </div>

  <div class="card grid-2" style="grid-template-columns: 1fr;">
    <h2>Send TPM Command</h2>
    <div class="row">
      <input id="cmd" type="text" placeholder="TPM command hex (e.g. 80010c0000000144010000000000)" />
      <button onclick="sendCommand()">Execute</button>
    </div>
    <div id="cmdOut" class="muted" style="margin-top:8px;"></div>
    <pre class="mono" id="cmdResp" style="margin-top:8px;"></pre>
  </div>

  <div class="card grid-2" style="grid-template-columns: 1fr;">
    <h2>State Backup / Restore</h2>
    <p class="muted">Exports/imports the full persistent TPM state (PCR, hierarchies, NV, clock, objects). Software-stored; not hardware-protected.</p>
    <button onclick="backupState()">Download state backup</button>
    <input type="file" id="stateFile" accept=".json" />
    <button class="secondary" onclick="restoreState()">Restore uploaded state</button>
    <div id="stateMsg" class="muted" style="margin-top:8px;"></div>
  </div>

  <div class="card">
    <h2>Diagnostic Logs</h2>
    <div id="logs" class="logs">loading…</div>
    <button class="secondary" onclick="load('logs')">Refresh</button>
  </div>
</main>
<script>
let api = '';
async function load(kind){
  try{
    const r = await fetch('/api/'+kind);
    const j = await r.json();
    if(kind==='status'){
      document.getElementById('status').textContent = JSON.stringify(j, null, 2);
      const chip = document.getElementById('statusChip');
      chip.textContent = (j.running ? 'RUNNING' : 'STOPPED') + '  •  ' + j.os;
      chip.className = (j.running ? 'ok' : 'err');
      document.getElementById('stateDir').textContent = 'State dir: ' + (j.stateDir||'—');
      document.getElementById('mode').textContent = j.os;
    } else if(kind==='capability'){
      document.getElementById('capability').textContent = j.response || '—';
    } else if(kind==='pcr'){
      const el = document.getElementById('pcr'); el.innerHTML='';
      if(!j || Object.keys(j).length===0){ el.textContent='no PCR data'; return; }
      for(const [bank, entries] of Object.entries(j)){
        const t = document.createElement('table');
        const tr = document.createElement('tr');
        const th = document.createElement('th'); th.textContent = bank; tr.appendChild(th); t.appendChild(tr);
        const tr2 = document.createElement('tr'); const td = document.createElement('td');
        td.innerHTML = entries.map(e=>'PCR['+e.index+']: <span class="mono">'+e.digest+'</span>').join('<br>');
        tr2.appendChild(td); t.appendChild(tr2);
        el.appendChild(t);
      }
    } else if(kind==='nv'){
      const el = document.getElementById('nv'); el.innerHTML='';
      if(!j || j.length===0){ el.textContent='no NV indices defined'; return; }
      const t = document.createElement('table');
      const tr = document.createElement('tr');
      ['publicLen','dataLen','readLocked','writeLocked'].forEach(k=>{const th=document.createElement('th');th.textContent=k;tr.appendChild(th);}); t.appendChild(tr);
      j.forEach(i=>{const tr=document.createElement('tr');['publicLen','dataLen','readLocked','writeLocked'].forEach(k=>{const td=document.createElement('td');td.textContent=i[k];tr.appendChild(td);});t.appendChild(tr);});
      el.appendChild(t);
    } else if(kind==='logs'){
      const el = document.getElementById('logs'); el.innerHTML='';
      (j.logs||[]).forEach(l=>{const d=document.createElement('div');d.textContent=l;el.appendChild(d);});
      el.scrollTop = el.scrollHeight;
    }
  }catch(e){
    const el = document.getElementById(kind); if(el) el.textContent='error: '+e;
  }
}
async function sendCommand(){
  const hex = document.getElementById('cmd').value.trim();
  if(!hex){ alert('enter a hex command'); return; }
  try{
    const r = await fetch('/api/command', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({command:hex})});
    const j = await r.json();
    document.getElementById('cmdResp').textContent = j.response || ('error: '+r.status);
    document.getElementById('cmdOut').textContent = 'status '+r.status;
    document.getElementById('cmdOut').className = r.ok ? 'ok' : 'err';
  }catch(e){ document.getElementById('cmdResp').textContent='error: '+e; }
}
async function backupState(){
  try{
    const r = await fetch('/api/state/backup');
    if(!r.ok){ alert('backup failed '+r.status); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download='vtpm2-state.json'; a.click();
    URL.revokeObjectURL(url);
    document.getElementById('stateMsg').textContent='backup downloaded';
    document.getElementById('stateMsg').className='ok';
  }catch(e){ document.getElementById('stateMsg').textContent='error: '+e; document.getElementById('stateMsg').className='err'; }
}
async function restoreState(){
  const f = document.getElementById('stateFile').files[0]; if(!f){ alert('select a state file'); return; }
  const ab = await f.arrayBuffer();
  try{
    const r = await fetch('/api/state/restore', {method:'POST', body: ab});
    const j = await r.json();
    document.getElementById('stateMsg').textContent = j.status || ('status '+r.status);
    document.getElementById('stateMsg').className = r.ok ? 'ok' : 'err';
    if(r.ok){ load('pcr'); load('nv'); load('status'); }
  }catch(e){ document.getElementById('stateMsg').textContent='error: '+e; document.getElementById('stateMsg').className='err'; }
}
load('status'); load('capability'); load('pcr'); load('nv'); load('logs');
setInterval(()=>{ load('status'); load('logs'); }, 5000);
</script>
</body></html>`;
