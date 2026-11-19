(() => {
  'use strict';
  const root = document.getElementById('assessments');
  if (!root) return;
  const $ = id => root.querySelector('#asm-' + id);
  const config = window.CRISP_ASSESSMENTS || {};
  const demo = config.mode !== 'api';
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const key = 'crisp-assessments-demo-v2';
  let state, busy = false, editingStart = null;
  const seed = () => { const data = { schedules: [], assessments: [], assessmentAssets: [], researchResults: [],
    // Sample inventory assets
    assets: [
      {AssetID:1, AssetTypeID:1, AssetName:'Firewall-01', Version:'7.2.10', Status:'Active'},
      {AssetID:2, AssetTypeID:2, AssetName:'VPN-Endpoint-01', Version:'4.10.04049', Status:'Active'},
      {AssetID:3, AssetTypeID:3, AssetName:'Switch-01', Version:'17.3.3', Status:'Active'},
      {AssetID:4, AssetTypeID:4, AssetName:'AccessPoint-01', Version:'4.0.80.10875', Status:'Active'},
      {AssetID:5, AssetTypeID:5, AssetName:'SaaS-01', Version:null, Status:'Active'}],
    sources: [{SourceID:1, SourceName:'NVD', SourceType:'Database', Enabled:true},
      {SourceID:2, SourceName:'CISA', SourceType:'Government', Enabled:true},
      {SourceID:3, SourceName:'MITRE CVE', SourceType:'Database', Enabled:true}] };
    const anchor = new Date(); anchor.setDate(anchor.getDate()-7); anchor.setHours(6,0,0,0);
    data.schedules = [
      {ScheduleID:1,AssessmentName:'Daily enterprise assessment',Frequency:'Daily',AssetScope:'All active assets',Enabled:true,StartAt:anchor.toISOString()},
      {ScheduleID:2,AssessmentName:'Weekly deep analysis',Frequency:'Weekly',AssetScope:'Network infrastructure',Enabled:true,StartAt:new Date(anchor.getTime()+4*86400000).toISOString()},
      {ScheduleID:3,AssessmentName:'SaaS intelligence sweep',Frequency:'Custom',CustomIntervalHours:12,AssetScope:'SaaS platforms',Enabled:false,StartAt:anchor.toISOString()}
    ].map(s=>{const row={CustomIntervalDays:null,CustomIntervalHours:null,LastRun:null,TimeZone:zone,...s}; row.NextRun=nextRun(row); return row;});
    for(let i=1;i<=4;i++) {
      const start=new Date(); start.setDate(start.getDate()-(4-i)); start.setHours(6,0,0,0);
      const status=i===2?'Failed':'Completed';
      data.assessments.push({AssessmentID:i,AssessmentName:i===3?'Manual assessment':'Daily enterprise assessment',AssessmentStart:start.toISOString(),AssessmentEnd:new Date(start.getTime()+1114000).toISOString(),TriggerType:i===3?'Manual':'Scheduled',Status:status,AssetScope:'All active assets'});
      data.assessmentAssets.push(...data.assets.map(a=>({AssessmentID:i,AssetID:a.AssetID,AssetSnapshotVersion:a.Version,EvaluationStatus:status==='Failed'?'Failed':'Evaluated'})));
    }
    return data;
  };
  const escape = value => String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const time = value => value ? new Date(value).toLocaleString() : '—';
  const badge = value => `<span class="asm-badge asm-status-${escape(String(value).toLowerCase())}">${escape(value)}</span>`;
  const button = (action, id, title) => `<button type="button" data-action="${action}" data-id="${id}">${title}</button>`;
  const activeRun = () => state.assessments.some(a => ['Pending','Running'].includes(a.Status));
  const nextID = rows => Math.max(0,...rows.map(r => r.ScheduleID || r.AssessmentID || 0)) + 1;
  const interval = s => s.Frequency === 'Daily' ? 1 : s.Frequency === 'Weekly' ? 7 : s.CustomIntervalDays;
  // Calendar increments preserve browser-local wall time across DST changes.
  function nextRun(s, now = new Date()) {
    if (!s.Enabled) return null;
    if (s.TimeZone !== zone) throw new Error('Edit this schedule in its original time zone, or use the server scheduler.');
    const d = new Date(s.StartAt);
    if (s.Frequency === 'Custom' && s.CustomIntervalHours) {
      const ms=s.CustomIntervalHours*3600000, offset=Math.max(0,Math.floor((now-d)/ms)+1);
      return new Date(d.getTime()+offset*ms).toISOString();
    }
    while (d <= now) d.setDate(d.getDate() + interval(s));
    return d.toISOString();
  }
  async function request(path, method='GET', payload) {
    const headers = {'Accept':'application/json'};
    if (payload) headers['Content-Type'] = 'application/json';
    if (config.csrfToken) headers['X-CSRF-Token'] = config.csrfToken;
    const res = await fetch((config.baseUrl || '/api') + path, {
      method, credentials:'same-origin', headers, ...(payload ? {body:JSON.stringify(payload)} : {})
    });
    const body = res.status === 204 ? null : await res.json().catch(() => null);
    if (!res.ok) throw new Error(body?.message || `Request failed (${res.status}).`);
    return body;
  }
  async function load() {
    if (demo) {
      const saved = localStorage.getItem(key);
      state = saved ? JSON.parse(saved) : seed();
    } else state = await request('/assessments/snapshot');
    for (const name of ['schedules','assessments','assessmentAssets','researchResults','assets','sources']) {
      if (!Array.isArray(state[name])) throw new Error('Invalid assessment data: ' + name);
    }
    render();
  }
  const icon = name => {
    const paths={calendar:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18"/>',clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',server:'<rect x="3" y="3" width="18" height="7" rx="1"/><rect x="3" y="14" width="18" height="7" rx="1"/><path d="M7 6.5h.01M7 17.5h.01"/>',check:'<path d="m5 12 4 4L19 6"/>'};
    return `<svg viewBox="0 0 24 24" width="21" height="21" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name]}</svg>`;
  };
  const assessmentName = a => a.AssessmentName || (a.TriggerType==='Manual'?'Manual assessment':`Assessment #${a.AssessmentID}`);
  const duration = a => {
    if (!a.AssessmentStart || !a.AssessmentEnd || a.Status==='Failed') return '—';
    const seconds=Math.max(0,Math.floor((new Date(a.AssessmentEnd)-new Date(a.AssessmentStart))/1000));
    return `${Math.floor(seconds/60)}m ${String(seconds%60).padStart(2,'0')}s`;
  };
  const assetCount = a => state.assessmentAssets.filter(x=>x.AssessmentID===a.AssessmentID).length;
  function recurrence(s) {
    if (s.Frequency==='Custom') return `Every ${s.CustomIntervalHours || s.CustomIntervalDays} ${s.CustomIntervalHours ? 'hours' : 'days'}`;
    const start=new Date(s.StartAt), localTime=start.toLocaleTimeString([],{hour:'numeric',minute:'2-digit',timeZone:s.TimeZone});
    return s.Frequency==='Daily' ? `Every day at ${localTime}` : `Every ${start.toLocaleDateString([],{weekday:'long',timeZone:s.TimeZone})} at ${localTime}`;
  }
  function render() {
    const running = state.assessments.find(a => ['Pending','Running'].includes(a.Status));
    $('run').disabled = !!running || busy;
    const latest=running || [...state.assessments].sort((a,b)=>b.AssessmentID-a.AssessmentID)[0];
    $('latest').innerHTML=latest ? `<span class="asm-result-icon">${icon(latest.Status==='Completed'?'check':'clock')}</span><div class="asm-latest-title">${badge(latest.Status)}<h2>${escape(assessmentName(latest))}</h2><p>${latest.AssessmentEnd?'Finished '+escape(time(latest.AssessmentEnd)):'Started '+escape(time(latest.AssessmentStart))} · ${assetCount(latest)} assets · ${escape(duration(latest))}</p></div><div class="asm-result-metrics"><div><small>New findings</small><b>${escape(latest.Summary?.NewFindings)}</b></div><div><small>Further review</small><b>${escape(latest.Summary?.FurtherReview)}</b></div><div><small>Resolved</small><b>${escape(latest.Summary?.Resolved)}</b></div></div>${button('details',latest.AssessmentID,'View results')}` : `<span class="asm-result-icon">${icon('clock')}</span><div><h2>No assessments yet</h2><p>Run an assessment to start researching your active inventory.</p></div>`;
    $('schedules').innerHTML = state.schedules.map(s => `<article class="asm-schedule-card"><div class="asm-schedule-top"><span class="asm-calendar-icon">${icon('calendar')}</span><button class="asm-switch" role="switch" aria-checked="${!!s.Enabled}" aria-label="${s.Enabled?'Deactivate':'Activate'} ${escape(s.AssessmentName)}" type="button" data-action="toggle" data-id="${s.ScheduleID}"><span></span></button></div><h3>${escape(s.AssessmentName || 'Schedule #'+s.ScheduleID)}</h3><p class="asm-recurrence">${escape(recurrence(s))}</p><div class="asm-schedule-meta"><div>${icon('clock')}<div><small>Next run</small><b>${s.Enabled?escape(time(s.NextRun)):'Paused'}</b></div></div><div>${icon('server')}<div><small>Scope</small><b>${escape(s.AssetScope || 'All active assets')}</b></div></div></div><div class="asm-schedule-footer">${button('edit',s.ScheduleID,'Edit schedule')}<details class="asm-card-menu"><summary aria-label="More actions for ${escape(s.AssessmentName)}">···</summary><div>${button('delete',s.ScheduleID,'Delete schedule')}</div></details></div></article>`).join('') || '<div class="asm-card"><p>No schedules yet. Create a schedule to get started.</p></div>';
    const search = $('search').value.trim().toLowerCase(), filter = $('filter').value;
    $('history').innerHTML = historyRows().filter(a => (!filter || a.Status===filter) && `${assessmentName(a)} ${a.AssessmentID} ${a.TriggerType}`.toLowerCase().includes(search)).map(a => `<tr><td><button class="asm-history-name" type="button" data-action="details" data-id="${a.AssessmentID}">${escape(assessmentName(a))}</button></td><td>${escape(time(a.AssessmentStart))}</td><td>${escape(duration(a))}</td><td>${assetCount(a)} assets</td><td>${a.Summary?.NewFindings == null ? '—' : escape(a.Summary.NewFindings)+' new'}</td><td>${badge(a.Status)}</td></tr>`).join('') || '<tr><td colspan="6">No matching assessments.</td></tr>';
    $('sources').innerHTML = state.sources.map(s => `<li>${escape(s.SourceName)} · ${escape(s.SourceType)} ${badge(s.Enabled?'Enabled':'Disabled')}</li>`).join('') || '<li>No approved sources configured.</li>';
  }
  function historyRows() { return [...state.assessments].sort((a,b)=>b.AssessmentID-a.AssessmentID); }
  function exportHistory() {
    const safeCell=value=>{let text=String(value??''); if (/^[\s]*[=+@-]/.test(text)) text="'"+text; return '"'+text.replace(/"/g,'""')+'"';};
    const rows=[['Assessment ID','Assessment','Started (UTC)','Duration','Assets','New findings','Status'], ...historyRows().map(a=>[a.AssessmentID,assessmentName(a),a.AssessmentStart,duration(a),assetCount(a),a.Summary?.NewFindings,a.Status])];
    const csv='\uFEFF'+rows.map(row=>row.map(safeCell).join(',')).join('\r\n');
    const url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8;'}));
    const link=document.createElement('a'); link.href=url; link.download='crisp-assessment-history.csv'; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
    $('message').textContent='Assessment history exported as CSV.';
  }
  async function work(fn) {
    if (busy) return;
    busy = true;
    $('message').textContent = '';
    try { await fn(); }
    catch(e) { $('message').textContent = e.message; }
    finally { busy=false; if (state) render(); }
  }
  function configureFrequency() { const custom=$('frequency').value === 'Custom'; $('custom-label').hidden = !custom; $('interval').required = custom; $('interval').disabled = !custom; $('interval').max=$('unit').value==='Hours'?'8760':'365'; }
  function defaults() {
    $('form').reset(); $('schedule-id').value=''; editingStart=null;
    $('frequency').value='Daily'; $('scope').value='All active assets'; $('unit').value='Days'; $('interval').value='14'; $('enabled').checked=true;
    const d = new Date(Date.now()+3600000); d.setSeconds(0,0);
    const local = new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString();
    $('date').value = local.slice(0,10); $('time').value=local.slice(11,16);
    $('form-error').textContent=''; configureFrequency();
  }
  function openEditor(s) {
    defaults();
    $('editor-title').textContent = s ? 'Edit assessment schedule' : 'Create assessment schedule';
    $('save').textContent=s?'Save changes':'Create schedule';
    if (s) {
      if (s.TimeZone !== zone) throw new Error('Switch to the schedule’s original time zone before editing it.');
      $('schedule-id').value=s.ScheduleID; $('name').value=s.AssessmentName;
      $('frequency').value=s.Frequency; $('interval').value=s.CustomIntervalHours || s.CustomIntervalDays || 14; $('unit').value=s.CustomIntervalHours?'Hours':'Days'; $('scope').value=s.AssetScope || 'All active assets'; $('enabled').checked=s.Enabled;
      const d=new Date(s.StartAt), local=new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString();
      $('date').value=local.slice(0,10); $('time').value=local.slice(11,16); editingStart=s.StartAt;
    }
    configureFrequency(); $('editor').showModal();
  }
  function confirmAction(title, text, callback) {
    $('confirm-title').textContent=title; $('confirm-text').textContent=text;
    $('confirm-yes').onclick=() => { $('confirm').close(); work(callback); };
    $('confirm').showModal();
  }
  async function saveSchedule(event) {
    event.preventDefault();
    await work(async () => {
      try {
        const name=$('name').value.trim(), id=Number($('schedule-id').value);
        const start=new Date($('date').value+'T'+$('time').value);
        if (!name) throw new Error('Enter an assessment name.');
        if (!Number.isFinite(start.getTime())) throw new Error('Enter a valid date and time.');
        // Reject nonexistent local times during a spring-forward transition.
        const expected=$('date').value+'T'+$('time').value;
        const actual=new Date(start.getTime()-start.getTimezoneOffset()*60000).toISOString().slice(0,16);
        if (actual !== expected) throw new Error('That local time does not exist because of a clock change. Choose another time.');
        if ((!id || start.toISOString() !== editingStart) && start <= new Date()) throw new Error('Choose a future start date and time.');
        const frequency=$('frequency').value, days=Number($('interval').value), hourly=$('unit').value==='Hours';
        if (frequency==='Custom' && (!Number.isInteger(days)||days<1||days>(hourly?8760:365))) throw new Error('Custom interval must be 1–365 days or 1–8760 hours.');
        const s={AssessmentName:name, Frequency:frequency, CustomIntervalDays:frequency==='Custom'&&!hourly?days:null, CustomIntervalHours:frequency==='Custom'&&hourly?days:null, AssetScope:$('scope').value, StartAt:start.toISOString(), TimeZone:zone, Enabled:$('enabled').checked};
        if(demo) {
          const old=state.schedules.find(s => s.ScheduleID===id);
          const row={...old,...s,ScheduleID:id||nextID(state.schedules),LastRun:old?.LastRun||null};
          row.NextRun=nextRun(row);
          const copy=structuredClone(state); copy.schedules=copy.schedules.filter(s => s.ScheduleID!==id); copy.schedules.push(row);
          localStorage.setItem(key,JSON.stringify(copy)); state=copy;
        } else { await request(id?'/assessment-schedules/'+id:'/assessment-schedules',id?'PUT':'POST',s); await load(); }
        $('editor').close(); $('message').textContent='Schedule saved.';
      } catch(e) { $('form-error').textContent=e.message; }
    });
  }
  async function run() {
    if (activeRun()) throw new Error('An assessment is already pending or running.');
    if (!state.assets.some(a => a.Status==='Active')) throw new Error('Add at least one active inventory asset first.');
    if (!state.sources.some(s => s.Enabled)) throw new Error('Enable an approved intelligence source first.');
    if (demo) {
      const id=nextID(state.assessments), copy=structuredClone(state);
      copy.assessments.push({AssessmentID:id,AssessmentName:'Manual assessment',AssetScope:'All active assets',AssessmentStart:new Date().toISOString(),AssessmentEnd:null,TriggerType:'Manual',Status:'Running'});
      copy.assessmentAssets.push(...state.assets.filter(a=>a.Status==='Active').map(a=>({AssessmentID:id,AssetID:a.AssetID,AssetSnapshotVersion:a.Version,EvaluationStatus:'Pending'})));
      localStorage.setItem(key,JSON.stringify(copy)); state=copy;
      $('message').textContent='Demo assessment created. Open its details to simulate completion or failure. No research has been performed.';
    } else { await request('/assessments','POST',{TriggerType:'Manual'}); await load(); $('message').textContent='Assessment accepted by the server.'; }
  }
  function details(id) {
    const a=state.assessments.find(a => a.AssessmentID===id);
    const rows=state.assessmentAssets.filter(x => x.AssessmentID===id);
    const research=state.researchResults.filter(x=>x.AssessmentID===id);
    $('detail-content').innerHTML=`<p>Assessment #${id} · ${escape(a.TriggerType)} · ${badge(a.Status)}</p><p>Started: ${escape(time(a.AssessmentStart))}<br>Finished: ${escape(time(a.AssessmentEnd))}</p><h3>Included assets</h3><div class="asm-table-wrap"><table><thead><tr><th>Asset</th><th>Version snapshot</th><th>Evaluation status</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${escape(state.assets.find(a=>a.AssetID===x.AssetID)?.AssetName || 'Asset #'+x.AssetID)}</td><td>${escape(x.AssetSnapshotVersion)}</td><td>${escape(x.EvaluationStatus)}</td></tr>`).join('')||'<tr><td colspan="3">No asset records.</td></tr>'}</tbody></table></div><h3>Research results</h3><p>Research records are source evidence; they are not verified findings.</p>${research.map(r=>`<details><summary>${escape(state.sources.find(s=>s.SourceID===r.SourceID)?.SourceName || r.SourceID)} · ${escape(r.Status)}</summary><pre>${escape(JSON.stringify(r,null,2))}</pre></details>`).join('')||'<p>No research results recorded.</p>'}${demo && ['Pending','Running'].includes(a.Status) ? button('complete',id,'Simulate completed')+button('fail',id,'Simulate failed'):''}`;
    $('detail').showModal();
  }
  root.addEventListener('click', e => {
    const b=e.target.closest('[data-action]'); if(!b) return;
    const id=Number(b.dataset.id), action=b.dataset.action;
    if(action==='details') { details(id); return; }
    if(action==='edit') { work(async()=>openEditor(state.schedules.find(s=>s.ScheduleID===id))); return; }
    if(action==='delete') {
      confirmAction('Delete schedule?', 'Future runs for this schedule will stop. Assessment history is preserved.', async()=>{
        if(demo) { const copy=structuredClone(state); copy.schedules=copy.schedules.filter(s=>s.ScheduleID!==id); localStorage.setItem(key,JSON.stringify(copy)); state=copy; }
        else { await request('/assessment-schedules/'+id,'DELETE'); await load(); }
        $('message').textContent='Schedule deleted.';
      }); return;
    }
    work(async()=>{
      if(action==='toggle') {
        const s=state.schedules.find(s=>s.ScheduleID===id);
        if(demo) { const copy=structuredClone(state), row=copy.schedules.find(s=>s.ScheduleID===id); row.Enabled=!row.Enabled; row.NextRun=nextRun(row); localStorage.setItem(key,JSON.stringify(copy)); state=copy; }
        else { await request('/assessment-schedules/'+id,'PATCH',{Enabled:!s.Enabled}); await load(); }
        $('message').textContent='Schedule status updated.';
      }
      if(demo && ['complete','fail'].includes(action)) {
        const copy=structuredClone(state), a=copy.assessments.find(a=>a.AssessmentID===id); a.Status=action==='complete'?'Completed':'Failed'; a.AssessmentEnd=new Date().toISOString();
        copy.assessmentAssets.filter(x=>x.AssessmentID===id).forEach(x=>x.EvaluationStatus=action==='complete'?'Evaluated':'Failed');
        localStorage.setItem(key,JSON.stringify(copy)); state=copy; $('detail').close(); $('message').textContent='Demo status updated. No vulnerability research or findings were generated.';
      }
    });
  });
  $('mode').textContent=demo ? 'Demo preview · Sample schedules and history. No research is performed and schedules do not run automatically. A dash means finding counts are unavailable.' : 'Connected mode · The server stores schedules and executes assessments. Displayed times use your browser’s time zone.';
  $('timezone').textContent='Time zone: '+zone;
  $('new').onclick=()=>work(async()=>openEditor()); $('refresh').onclick=()=>work(load);
  $('run').onclick=()=>confirmAction('Run assessment?', 'Research known vulnerabilities for all active inventory assets using enabled intelligence sources.',run);
  $('form').onsubmit=saveSchedule; $('frequency').onchange=configureFrequency; $('unit').onchange=configureFrequency;
  $('export').onclick=exportHistory; $('editor-close').onclick=()=>$('editor').close();
  $('reset').onclick=()=>{const id=$('schedule-id').value; defaults(); $('schedule-id').value=id;};
  $('cancel').onclick=()=>$('editor').close(); $('confirm-cancel').onclick=()=>$('confirm').close(); $('close-detail').onclick=()=>$('detail').close();
  $('search').oninput=render; $('filter').onchange=render;

  if (!demo) setInterval(()=>{if(!document.hidden) work(load);},15000);
  work(load);
})();
