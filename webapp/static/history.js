/* Shared run/group filtering. Dates are interpreted in the browser's local zone. */
(function(root) {
  function filterHistory(items, filters = {}, groups = false) {
    const start = filters.from ? Date.parse(filters.from) : null;
    const end = filters.to ? Date.parse(filters.to) : null;
    if ((filters.from && !Number.isFinite(start)) || (filters.to && !Number.isFinite(end)) ||
        (start !== null && end !== null && start > end)) return [];
    const query = (filters.search || '').trim().toLowerCase();
    return items.filter(item => {
      const scenarios = groups ? item.pipelines || [] : [item.pipeline];
      if (filters.scenario && !scenarios.includes(filters.scenario)) return false;
      if (filters.status && item.status !== filters.status) return false;
      const stamp = Date.parse(item.started_at || item.created_at);
      if ((start !== null || end !== null) && !Number.isFinite(stamp)) return false;
      if (start !== null && stamp < start || end !== null && stamp > end) return false;
      if (filters.kind === 'single' && (groups || item.batch_id)) return false;
      if (filters.kind === 'group' && !groups && !item.batch_id) return false;
      if (query && ![item.id,item.name,item.model,item.judge_model,item.batch_id,...scenarios]
        .filter(Boolean).join(' ').toLowerCase().includes(query)) return false;
      return true;
    }).sort((a,b)=> {
      const time = item => Date.parse(item.started_at || item.created_at) || 0;
      return filters.sort === 'oldest' ? time(a)-time(b) : time(b)-time(a);
    });
  }
  root.filterHistory = filterHistory;
  if (typeof module !== 'undefined') module.exports = {filterHistory};
})(globalThis);

if (typeof document !== 'undefined') {
  const historyKeys = ['scenario','status','from','to','search','kind','sort'];
  const getHistoryFilters = () => Object.fromEntries(historyKeys.map(key=>[key,document.getElementById('filter-'+key).value]));
  globalThis.historyFilters = getHistoryFilters;
  globalThis.populateHistoryScenarios = function(scenarios) {
    const select = document.getElementById('filter-scenario'), previous = select.value;
    select.replaceChildren(new Option('All scenarios',''),...scenarios.map(p=>new Option(p.name,p.id)));
    select.value = previous;
  };
  function applyFilters() {
    const filters = getHistoryFilters();
    const invalid = filters.from && filters.to && Date.parse(filters.from) > Date.parse(filters.to);
    document.getElementById('history-filter-error').textContent = invalid ? 'Start time must be before end time.' : '';
    try { sessionStorage.setItem('cyber-history-filters',JSON.stringify(filters)); } catch {}
    renderRuns();
    if (typeof renderBatchHistory === 'function') renderBatchHistory();
  }
  try {
    const saved = JSON.parse(sessionStorage.getItem('cyber-history-filters') || '{}');
    for (const key of historyKeys) if (typeof saved[key] === 'string' && key !== 'scenario')
      document.getElementById('filter-'+key).value = saved[key];
    // Scenario options arrive asynchronously; restore once populated.
    const populate = globalThis.populateHistoryScenarios;
    globalThis.populateHistoryScenarios = scenarios => {
      populate(scenarios);
      if(scenarios.some(p=>p.id===saved.scenario))document.getElementById('filter-scenario').value=saved.scenario;
      applyFilters();
    };
  } catch {}
  document.getElementById('history-filters').addEventListener('input',applyFilters);
  document.getElementById('history-filters').addEventListener('change',applyFilters);
  document.getElementById('clear-history-filters').onclick=()=>{
    for(const key of historyKeys)document.getElementById('filter-'+key).value=key==='sort'?'newest':'';
    applyFilters();
  };
}
