let selected = null, workflows = [], records = [], fileText = '', openFile = '';
let fileHTML = '', renderedFileKey = '', detailSignature = '';
function showReport() {
  const key = `${selected}/${openFile}/${fileText}`;
  const container = $('file-content');
  if (!container || renderedFileKey === key) return;
  container.className = fileHTML ? 'markdown-report' : 'raw-report';
  container.innerHTML = fileHTML || `<pre>${escape(fileText)}</pre>`;
  container.querySelectorAll('a').forEach(a => { a.target = '_blank'; a.rel = 'noopener noreferrer'; });
  renderedFileKey = key;
}
const $ = id => document.getElementById(id);
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path, options) { const r = await fetch(path, {cache:'no-store', ...options}); if (!r.ok) { const e = await r.json().catch(() => ({})); throw Error(e.detail || r.statusText); } return r.json(); }
function notice(text) { $('notice').textContent = text; $('notice').style.display = text ? 'block' : 'none'; }
let graphPreview = false;
let modelsReady = false, modelConfig = {};
function updateStartButton() {
  if (typeof updateLaunchOptions === 'function') { updateLaunchOptions(); return; }
  const needsModel = workflows.find(p => p.id === $('pipeline').value)?.model;
  $('start').disabled = records.some(r => ['queued','running'].includes(r.status)) || (needsModel && !modelsReady);
}
async function loadModels() {
  const previous = [$('model').value, $('judge-model').value];
  modelsReady = false;
  $('refresh-models').disabled = true;
  for (const id of ['model', 'judge-model']) {
    $(id).disabled = true;
    $(id).replaceChildren(new Option('Loading models…', ''));
  }
  updateStartButton();
  try {
    const models = await api('/api/models');
    if (!models.length) throw Error('The proxy returned no available models.');
    ['model', 'judge-model'].forEach((id, index) => {
      const select = $(id);
      const choices = models;
      if(!choices.length) throw Error(`No models passed the ${index?'judge':'analyst'} capability check.`);
      select.replaceChildren(...choices.map(m => new Option(m.name, m.id)));
      const preferred = previous[index] || (index ? modelConfig.judge_model : modelConfig.analyst_model);
      select.value = choices.some(m => m.id === preferred) ? preferred : choices[0].id;
      select.disabled = false;
    });
    modelsReady = true;
    notice('');
  } catch (e) {
    for (const id of ['model', 'judge-model']) $(id).replaceChildren(new Option('Models unavailable', ''));
    notice(e.message);
  } finally {
    $('refresh-models').disabled = false;
    updateStartButton();
  }
}
async function previewDAG() {
  const pipeline = $('pipeline').value;
  try {
    const p = await api(`/api/pipelines/${pipeline}/workflow`);
    if (!graphPreview || pipeline !== $('pipeline').value) return;
    renderDAG(p.steps, {}, '', p.name, true);
    $('dag').scrollTop = 0; $('dag').scrollLeft = 0;
  } catch (e) { $('dag').innerHTML = `<p class="error">${escape(e.message)}</p>`; }
}
function workflowChanged() { const p = workflows.find(p => p.id === $('pipeline').value); $('pipeline-description').textContent = p.description; $('model-field').style.display = p.model ? 'flex' : 'none'; $('judge-field').style.display = p.model ? 'flex' : 'none'; if($('scenario-rubric'))$('scenario-rubric').href=`/api/pipelines/${p.id}/rubric`; updateStartButton(); graphPreview = true; previewDAG(); }
function renderRuns() {
  $('total').textContent = records.length;
  $('active').textContent = records.filter(r => ['queued','running'].includes(r.status)).length;
  $('complete').textContent = records.filter(r => r.status === 'completed').length;
  $('failed').textContent = records.filter(r => ['failed','interrupted'].includes(r.status)).length;
  updateStartButton();
  if (!records.length) { $('runs').innerHTML='<p class="empty">No runs yet. Start a scenario from the Run scenario tab.</p>'; return; }
  $('runs').innerHTML = records.map(r => `<div class="run ${selected === r.id ? 'selected' : ''}" data-id="${r.id}" tabindex="0" role="button"><span class="badge ${escape(r.status)}">${escape(r.status)}</span><strong>${escape(r.pipeline.toUpperCase())}</strong><p>${escape(r.name)}</p><small>${new Date(r.created_at).toLocaleString()} · ${r.id.slice(0,8)}</small></div>`).join('');
  document.querySelectorAll('.run').forEach(el => { const select = () => { selected = el.dataset.id; graphPreview = false; fileText = ''; openFile = ''; renderRuns(); refreshDetail(); }; el.onclick = select; el.onkeydown = e => { if (e.key === 'Enter') select(); }; });
}
async function refreshDetail() {
  if (!selected) return;
  const r = await api(`/api/runs/${selected}`);
  if (r.id !== selected) return;
  const signature = JSON.stringify([r.id,r.status,r.steps,r.message,r.error,r.export_error,r.results,r.files,openFile]);
  if (signature === detailSignature) {
    const activity = document.querySelector('.activity');
    if (activity && r.heartbeat_at) activity.textContent = `Worker online · last heartbeat ${Math.max(0,Math.floor((Date.now()-Date.parse(r.heartbeat_at))/1000))}s ago. Model steps can take several minutes.`;
    return;
  }
  detailSignature = signature;
  const previousInputs = $('agent-inputs');
  const previousViewer = $('file-content');
  const viewerScroll = previousViewer?.scrollTop || 0;
  const previousViewerKey = previousViewer?.dataset.fileKey;
  const pageScroll = window.scrollY;
  if (!graphPreview && (typeof activeTab === 'undefined' || activeTab === 'history')) renderDAG(r.workflow || [], r.steps, r.status, r.name);
  const steps = Object.entries(r.steps || {}).sort((a,b) => a[1].number-b[1].number);
  const done = steps.filter(([,s]) => s.status === 'completed').length;
  const percent = r.total_steps ? Math.round(done/r.total_steps*100) : 0;
  const scores = (r.results || []).flatMap(result => Object.entries(result.scores || {}));
  const activeSteps = steps.filter(([,s]) => s.status === 'running');
  const elapsed = activeSteps.map(([id,s]) => `${id}: ${s.started_at ? Math.max(0,Math.floor((Date.now()-Date.parse(s.started_at))/1000))+'s elapsed' : 'in progress'}`).join(' · ');
  const heartbeatAge = r.heartbeat_at && Number.isFinite(Date.parse(r.heartbeat_at)) ? Math.max(0,Math.floor((Date.now()-Date.parse(r.heartbeat_at))/1000)) : null;
  const activity = ['running','queued'].includes(r.status) ? `<p class="activity">${escape(elapsed || 'Preparing run')}<br>${heartbeatAge === null ? 'Waiting for next AEF step event.' : heartbeatAge < 15 ? '● Worker online · heartbeat '+heartbeatAge+'s ago. Model steps can take several minutes.' : 'Worker heartbeat delayed ('+heartbeatAge+'s); inspect execution log.'}</p>` : '';
  $('detail').innerHTML = `<div class="run-head"><h2>${escape(r.name)}</h2><span class="badge ${escape(r.status)}">${escape(r.status)}</span></div><div class="mono">${escape(r.id)}${r.model ? ' · '+escape(r.model) : ''}</div><div class="progress"><div style="width:${percent}%"></div></div><p>${done} / ${r.total_steps || '—'} steps completed · ${percent}%</p><p>${escape(r.message)}</p>${r.error ? `<pre class="error">${escape(r.error)}</pre>`:''}${r.export_error ? `<pre class="error">Export failed: ${escape(r.export_error)}</pre>`:''}<div class="section-label">WORKFLOW PROGRESS</div>${steps.map(([id,s])=>`<div class="step ${s.status}"><span class="dot">${s.status==='completed'?'✓':'◌'}</span>${escape(id)}<span>${escape(s.detail)}</span></div>`).join('') || '<p>Preparing the environment…</p>'}${scores.length ? `<div class="section-label">VERIFIER SCORES</div><div class="checks">${scores.map(([id,score])=>`<div class="score"><b>${Number(score).toFixed(2)}</b><small>${escape(id)}</small></div>`).join('')}</div>`:''}<div class="files"><div class="section-label">RESULTS & REPORTS</div><div class="file-list">${(r.files||[]).filter(f=>f.endsWith('.md')&&!f.includes('/')).map(f=>`<button class="secondary" data-file="${escape(f)}">${escape(f)}</button>`).join('')}${r.verifications.length ? '<button class="secondary" id="checks">Verification details</button>':''}</div>${openFile ? `<p>${escape(openFile)}</p><pre id="file-content">${escape(fileText)}</pre>`:''}</div><details ${['running','queued'].includes(r.status)?'open':''}><summary class="section-label">LIVE EXECUTION LOG</summary><pre id="log">${escape(r.log || 'Waiting for worker output…')}</pre></details>`;
  const resultsSection = document.querySelector('#detail .files');
  if (previousInputs?.dataset.runId === selected) resultsSection.before(previousInputs);
  else {
    const inputs = document.createElement('section');
    inputs.id = 'agent-inputs'; inputs.dataset.runId = selected;
    inputs.innerHTML = '<div class="section-label">INPUTS</div><p>View prompts, available scenario records and recorded tool responses.</p><button class="secondary" type="button">View agent inputs</button><div class="input-items"></div>';
    resultsSection.before(inputs);
    inputs.querySelector('button').onclick = async () => {
      const button = inputs.querySelector('button'); button.disabled = true;
      try {
        const payload = await api(`/api/runs/${inputs.dataset.runId}/inputs`);
        inputs.querySelector('.input-items').innerHTML = `<p>${escape(payload.source)}</p>` + payload.items.map(item => `<details><summary>${escape(item.phase)} · ${escape(item.name)}</summary><pre>${escape(item.content)}</pre></details>`).join('');
        button.textContent = 'Refresh inputs';
      } catch (e) { notice(e.message); }
      finally { button.disabled = false; }
    };
  }
  const viewerKey = `${selected}/${openFile}`;
  if ($('file-content')) {
    if (previousViewer && previousViewerKey === viewerKey) { $('file-content').replaceWith(previousViewer); previousViewer.scrollTop=viewerScroll; }
    else {
      const viewer = document.createElement('article'); viewer.id='file-content'; viewer.dataset.fileKey=viewerKey;
      $('file-content').replaceWith(viewer); renderedFileKey='';
    }
    showReport();
  }
  window.scrollTo(window.scrollX,pageScroll);
  document.querySelectorAll('[data-file]').forEach(el => el.onclick = async () => {
    const id = selected, filename=el.dataset.file;
    try {
      const [text,rendered] = await Promise.all([
        fetch(`/api/runs/${id}/files/${encodeURIComponent(filename)}`).then(r=>{if(!r.ok)throw Error('Could not load report');return r.text();}),
        api(`/api/runs/${id}/render/${encodeURIComponent(filename)}`)
      ]);
      if(id===selected){openFile=filename;fileText=text;fileHTML=rendered.html;detailSignature='';await refreshDetail();}
    } catch(e) {notice(e.message);}
  });
  const criticalFailures = [...new Set((r.results || []).flatMap(result => Object.values(result.grading || {}).flatMap(grade => grade.failures || [])))];
  if (criticalFailures.length) $('detail').insertAdjacentHTML('afterbegin', `<p class="error"><strong>CRITICAL FAILURE · Mission score 0.00</strong><br>${criticalFailures.map(escape).join('<br>')}</p>`);
  $('detail').insertAdjacentHTML('afterbegin', activity);
  if ($('checks')) $('checks').onclick = () => { openFile = 'Verification details'; fileHTML=''; fileText = JSON.stringify(r.verifications,null,2); refreshDetail(); };
}
async function refresh() { try { records = await api('/api/runs'); if (!selected && records.length) { selected=records[0].id; if(typeof activeTab==='undefined'||activeTab==='history')graphPreview=false; } renderRuns(); await refreshDetail(); } catch(e){notice(e.message);} }
$('pipeline').onchange=workflowChanged;
$('refresh-models').onclick=loadModels;
$('dag-preview').onclick = () => { graphPreview = true; previewDAG(); };
(async()=>{workflows=await api('/api/pipelines');$('pipeline').innerHTML=workflows.map(p=>`<option value="${p.id}">${escape(p.name)}</option>`).join('');$('pipeline').value='smoke';workflowChanged();modelConfig=await api('/api/models/config');$('connection').textContent=modelConfig.ready?`LiteLLM · ${modelConfig.endpoint} · key configured`:'LiteLLM not configured: export LITELLM_BASE_URL and LITELLM_API_KEY. Model-free scenarios are available.';await Promise.all([loadModels(),refresh()]);setInterval(refresh,2000);})().catch(e=>notice(e.message));
