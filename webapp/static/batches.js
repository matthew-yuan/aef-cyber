/* One launch form; repetitions are an optional extension of the selected scenario. */
var launchBusy = false, batchActive = false;
var activeTab = 'launch';
var historyBatches = [];
const additionalScenarios = () => [...document.querySelectorAll('#additional-scenarios input:checked')].map(el=>el.value);
const launchScenarios = () => [...new Set([$('pipeline').value, ...additionalScenarios()])].filter(Boolean);
function showTab(tab) {
  activeTab = tab;
  $('launch-page').hidden = tab !== 'launch';
  $('history-page').hidden = tab !== 'history';
  document.querySelectorAll('[data-page]').forEach(button => {
    button.classList.toggle('active', button.dataset.page === tab);
    button.setAttribute('aria-selected', String(button.dataset.page === tab));
  });
  if (tab === 'launch') { graphPreview = true; if (workflows.length) previewDAG(); }
  else { graphPreview = false; detailSignature = ''; refreshDetail().catch(e=>notice(e.message)); }
}
document.querySelectorAll('[data-page]').forEach(button=>{
  button.onclick=()=>showTab(button.dataset.page);
  button.onkeydown=event=>{
    if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
    event.preventDefault();
    const tab=event.key==='Home'?'launch':event.key==='End'?'history':activeTab==='launch'?'history':'launch';
    showTab(tab);document.querySelector(`[data-page="${tab}"]`).focus();
  };
});
function updateLaunchOptions() {
  if (!$('repeat-enabled')) return;
  const enabled = $('repeat-enabled').checked;
  $('trial-settings').hidden = !enabled;
  $('trial-k').disabled = !enabled;
  $('trial-threshold').disabled = !enabled;
  const chosen = launchScenarios();
  const needsModel = workflows.some(p=>chosen.includes(p.id) && p.model);
  $('model-field').style.display = needsModel ? 'flex' : 'none';
  $('judge-field').style.display = needsModel ? 'flex' : 'none';
  const k = enabled ? Number($('trial-k').value) : 1;
  const count = k * chosen.length;
  $('trial-summary').textContent = enabled || chosen.length > 1 ? `${count} trials across ${chosen.length} scenario${chosen.length===1?'':'s'}.` : '';
  $('start').textContent = launchBusy ? 'Starting…' : enabled || chosen.length > 1 ? `Start ${count} trials` : '▶  Start run';
  $('start').disabled = launchBusy || batchActive || records.some(r=>['queued','running'].includes(r.status)) ||
    (needsModel && !modelsReady) || !Number.isInteger(k) || k<1 || k>20 || count>40;
  if(typeof uploadedRubric!=='undefined' && uploadedRubric &&
     (chosen.length!==1 || chosen[0]!==uploadedRubric.scenario || k>3))$('start').disabled=true;
  if(typeof rubricUploading!=='undefined' && rubricUploading)$('start').disabled=true;
  if(typeof rubricInvalid!=='undefined' && rubricInvalid)$('start').disabled=true;
}
$('repeat-enabled').onchange=updateLaunchOptions;
$('run-options').oninput=updateLaunchOptions;
$('pipeline').addEventListener('change',()=>{
  document.querySelectorAll('#additional-scenarios label').forEach(label=>{
    const checkbox = label.querySelector('input');
    label.hidden = checkbox.value === $('pipeline').value;
    if (label.hidden) checkbox.checked = false;
  });
  updateLaunchOptions();
});
$('launch-form').onsubmit = async event => {
  event.preventDefault();
  if ($('start').disabled) return;
  launchBusy = true; updateLaunchOptions(); notice('');
  try {
    const pipelines = launchScenarios(), repeated = $('repeat-enabled').checked;
    const custom = typeof uploadedRubric!=='undefined' && uploadedRubric;
    const batch = repeated || pipelines.length > 1 || custom;
    const body = {model:$('model').value, judge_model:$('judge-model').value};
    if (batch) Object.assign(body,{pipelines,k:repeated?Number($('trial-k').value):1,
      success_threshold:repeated?Number($('trial-threshold').value):.8});
    else body.pipeline=pipelines[0];
    if(custom)body.rubric_id=custom.id;
    const result = await api(batch?'/api/batches':'/api/runs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    selected = batch?result.run_ids[0]:result.id;
    detailSignature=''; openFile=''; fileText=''; fileHTML='';
    showTab('history'); await refresh(); await refreshBatches();
  } catch(error) { notice(error.message); }
  finally { launchBusy=false; updateLaunchOptions(); }
};
async function refreshBatches() {
  try {
    const batches = await api('/api/batches');
    historyBatches = batches;
    batchActive = batches.some(b=>['queued','running'].includes(b.status));
    renderBatchHistory();
    updateLaunchOptions();
  } catch(error){$('batch-error').textContent=error.message;}
}
function renderBatchHistory() {
    const filters = typeof historyFilters === 'function' ? historyFilters() : {};
    const batches = typeof filterHistory === 'function' ? filterHistory(historyBatches,filters,true) : historyBatches;
    const opened = new Set([...document.querySelectorAll('.batch-summary[open]')].map(el=>el.dataset.batchId));
    $('batch-error').textContent='';
    $('batch-summaries').innerHTML = batches.length ? batches.map(batch=>`<details class="batch-summary" data-batch-id="${escape(batch.id)}" ${opened.has(batch.id)?'open':''}>
      <summary>Trial group ${escape(batch.id.slice(0,8))} · ${escape(batch.status)} · ${batch.k} per scenario · ${Math.round(batch.elapsed_seconds)}s</summary>
      ${batch.error?`<p class="error">${escape(batch.error)}</p>`:''}
      <p>Success threshold: ${batch.success_threshold}. Execution completion and evaluation success are separate.</p>
      <div class="batch-table"><table><thead><tr><th>Scenario</th><th>Finished</th><th>Successful</th><th>Success rate</th><th>All trials passed</th></tr></thead><tbody>
      ${batch.scenarios.filter(s=>!filters.scenario||s.pipeline===filters.scenario).map(s=>`<tr><td>${escape(workflows.find(p=>p.id===s.pipeline)?.name||s.pipeline)}</td><td>${s.completed}/${s.total}</td><td>${s.successes}${s.failed?` (${s.failed} errors)`:''}</td><td>${s.success_rate===null?'—':`${Math.round(s.success_rate*100)}%`}${s.confidence_interval_95?`<small>95% interval ${Math.round(s.confidence_interval_95[0]*100)}–${Math.round(s.confidence_interval_95[1]*100)}%</small>`:''}</td><td>${s.all_trials_passed===null?'Pending':s.all_trials_passed?'Yes':'No'}</td></tr>`).join('')}
      </tbody></table></div><button class="secondary" type="button" data-group="${escape(batch.id)}">View these runs</button></details>`).join('') : `<p>${historyBatches.length?'No trial groups match these filters.':'No trial groups yet.'}</p>`;
    document.querySelectorAll('[data-group]').forEach(button=>button.onclick=()=>{
      const batch=batches.find(b=>b.id===button.dataset.group);
      const match=filterHistory(records,filters).find(r=>batch.run_ids.includes(r.id));
      if(match){selected=match.id;detailSignature='';openFile='';fileText='';fileHTML='';renderRuns();refreshDetail().catch(e=>notice(e.message));}
    });
}
(async()=>{
  const scenarios=await api('/api/pipelines');
  if(typeof populateHistoryScenarios==='function')populateHistoryScenarios(scenarios);
  $('additional-scenarios').innerHTML=scenarios.map(p=>`<label><input type="checkbox" value="${escape(p.id)}">${escape(p.name)}</label>`).join('');
  $('additional-scenarios').onchange=updateLaunchOptions;
  document.querySelectorAll('#additional-scenarios label').forEach(label=>{
    label.hidden=label.querySelector('input').value===$('pipeline').value;
  });
  updateLaunchOptions();
  await refreshBatches();setInterval(refreshBatches,2500);
})().catch(e=>notice(e.message));
