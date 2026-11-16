/* Batch launch is independent of single-run polling and preserves form edits. */
const batchPanel = document.createElement('section');
batchPanel.className = 'panel batch-panel';
batchPanel.innerHTML = `<h2>Batch evaluations & reliability</h2>
  <p>Select scenarios and repeat each one k times. Trials use fresh environments with a bounded number running together.</p>
  <form id="batch-form"><fieldset><legend>Scenarios</legend><div id="batch-scenarios"></div></fieldset>
  <div class="batch-options"><label>Trials per scenario (k)<input id="batch-k" type="number" min="1" max="20" value="1" required></label>
  <label>Parallel trials<input id="batch-concurrency" type="number" min="1" max="4" value="2" required></label>
  <label>Success threshold<input id="batch-threshold" type="number" min="0" max="1" step="0.01" value="0.8" required></label>
  <button id="batch-start" type="submit" disabled>Start batch</button></div></form>
  <p id="batch-estimate"></p><p>Uses the analyst and judge models selected above. Completion means execution finished; success also requires the threshold, no critical failure and no refused execution.</p>
  <div id="batch-error" role="status"></div><div id="batch-summaries" aria-live="polite"></div>`;
document.querySelector('.launch').after(batchPanel);
let batchBusy = false, batchActive = false;
let batchScenarioModels = [];
const chosenScenarios = () => [...document.querySelectorAll('#batch-scenarios input:checked')].map(el => el.value);
function batchFormChanged() {
  const chosen = chosenScenarios();
  const needsModels = batchScenarioModels.some(p => chosen.includes(p.id) && p.model);
  if (needsModels) { $('model-field').style.display = 'flex'; $('judge-field').style.display = 'flex'; }
  const trials = chosen.length * Number($('batch-k').value);
  $('batch-estimate').textContent = `${trials} planned trial${trials === 1 ? '' : 's'} · maximum 40 per batch. Parallel trials share local Docker and proxy capacity.`;
  $('batch-start').disabled = batchBusy || batchActive || !chosen.length || trials > 40 || (needsModels && !modelsReady);
}
$('batch-form').onchange = batchFormChanged;
$('batch-form').oninput = batchFormChanged;
$('pipeline').addEventListener('change', batchFormChanged);
$('batch-form').onsubmit = async event => {
  event.preventDefault();
  if ($('batch-start').disabled) return;
  batchBusy = true; batchFormChanged(); $('batch-error').textContent = '';
  try {
    const batch = await api('/api/batches', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({
      pipelines:chosenScenarios(), k:Number($('batch-k').value), concurrency:Number($('batch-concurrency').value),
      success_threshold:Number($('batch-threshold').value), model:$('model').value, judge_model:$('judge-model').value
    })});
    selected = batch.run_ids[0]; graphPreview = false; detailSignature = '';
    await refresh(); await refreshBatches();
  } catch (error) { $('batch-error').textContent = error.message; }
  finally { batchBusy = false; batchFormChanged(); }
};
async function refreshBatches() {
  try {
    const batches = await api('/api/batches');
    batchActive = batches.some(b => ['queued','running'].includes(b.status)) || records.some(r => ['queued','running'].includes(r.status));
    $('batch-summaries').innerHTML = batches.slice(0, 8).map(batch => `<article class="batch-summary">
      <h3>Batch ${escape(batch.id.slice(0,8))} <span class="badge ${escape(batch.status)}">${escape(batch.status)}</span></h3>
      <p>${batch.k} trials/scenario · concurrency ${batch.concurrency} · threshold ${batch.success_threshold} · ${Math.round(batch.elapsed_seconds)}s elapsed</p>
      ${batch.input_sha256 ? `<p>Frozen inputs: <code>${escape(batch.input_sha256.slice(0,16))}</code></p>` : ''}
      ${batch.error ? `<p class="error">${escape(batch.error)}</p>` : ''}
      <table><thead><tr><th>Scenario</th><th>Finished</th><th>Successes</th><th>Observed success rate</th><th>All k successful</th></tr></thead><tbody>
      ${batch.scenarios.map(s => `<tr><td>${escape(workflows.find(p=>p.id===s.pipeline)?.name || s.pipeline)}</td><td>${s.completed}/${s.total}${s.failed ? ` (${s.failed} execution errors)` : ''}</td><td>${s.successes}</td><td>${s.success_rate === null ? '—' : `${Math.round(100*s.success_rate)}%`}${s.confidence_interval_95 ? `<small>95% interval: ${Math.round(100*s.confidence_interval_95[0])}–${Math.round(100*s.confidence_interval_95[1])}%</small>` : ''}</td><td>${s.all_trials_passed === null ? 'Pending' : s.all_trials_passed ? 'Yes' : 'No'}</td></tr>`).join('')}
      </tbody></table><p>Observed outcomes for this batch, not a population pass@k estimate.</p></article>`).join('');
    batchFormChanged();
  } catch (error) { $('batch-error').textContent = error.message; }
}
(async () => {
  const scenarios = await api('/api/pipelines');
  batchScenarioModels = scenarios;
  $('batch-scenarios').innerHTML = scenarios.map(p=>`<label><input type="checkbox" value="${escape(p.id)}">${escape(p.name)}</label>`).join('');
  batchFormChanged(); await refreshBatches();
  setInterval(refreshBatches, 2500);
})().catch(error => { $('batch-error').textContent = error.message; });
