/* Layered dependency graph: edges come from AEF task JSON, never from step order alone. */
let focusedStep = null;
let dagMode = 'overview', lastGraph = null;
const phaseLabels = {
  setup: ['Prepare environment', 'Deploy containers, load data and connect the analyst'],
  triage: ['Triage alerts', 'Separate malicious activity from authorized operations'],
  report: ['Write incident report', 'Document scope, evidence and response actions'],
  evidence: ['Analyze evidence', 'Review forensic artifacts and extract indicators'],
  artifacts: ['Build detection tools', 'Create and test rules, hunt scripts and IOC extractors'],
  baseline: ['Grade initial work', 'Check facts, judge reports and execute detection tests'],
  update: ['Receive incident update', 'Inject new telemetry without resetting the incident'],
  revision: ['Revise incident report', 'Integrate new findings while preserving valid conclusions'],
  review: ['Grade revision', 'Measure adaptation, regressions and report quality'],
  score: ['Final evaluation score', 'Combine verifier scores and save results'],
  check: ['Verify environment', 'Run model-free tool and submission checks'],
};
function phaseOf(step) {
  const id = step.id;
  if (id.endsWith('-check') || id.endsWith('-exec-tests')) return 'check';
  if (id.startsWith('soc-') || id.startsWith('lab-') || id.startsWith('scorebox-')) return 'setup';
  if (id === 'score') return 'score';
  if (id === 'issue-update') return 'update';
  if (['revision-checks','judge-revision'].includes(id)) return 'review';
  if (['revision','snap-revised'].includes(id)) return 'revision';
  if (['triage','snap-triage'].includes(id)) return 'triage';
  if (['report','snap-report'].includes(id)) return 'report';
  if (['evidence','snap-evidence'].includes(id)) return 'evidence';
  if (['artifacts','snap-final','snap-lab','submit'].includes(id)) return 'artifacts';
  if (id.startsWith('judge-') || ['facts','artifact-checks','exec-tests','handoff','baseline-score'].includes(id)) return 'baseline';
  if (id === 'check') return 'check';
  return 'setup';
}
function renderOverview(definitions, statuses, runStatus) {
  const groups = new Map();
  for (const step of definitions) {
    const phase = phaseOf(step);
    if (!groups.has(phase)) groups.set(phase, []);
    groups.get(phase).push(step);
  }
  const order = ['setup','triage','report','evidence','artifacts','baseline','update','revision','review','check','score'];
  $('dag').innerHTML = '<div class="phase-list">' + order.filter(id=>groups.has(id)).map((id,index)=>{
    const members = groups.get(id), done = members.filter(s=>statuses[s.id]?.status==='completed').length;
    const active = members.some(s=>statuses[s.id]?.status==='running');
    const status = done===members.length ? 'completed' : active ? (['failed','interrupted'].includes(runStatus)?'failed':'running') : 'pending';
    const [label,description] = phaseLabels[id];
    return `<button class="phase-card ${status}" data-phase="${id}" aria-label="${escape(label)}: ${status}"><span class="phase-number">${status==='completed'?'✓':index+1}</span><span><strong>${escape(label)}</strong><small>${escape(description)}</small><em>${done}/${members.length} steps · ${status}</em></span></button>`;
  }).join('') + '</div>';
  document.querySelectorAll('[data-phase]').forEach(el=>el.onclick=()=>{
    const members=groups.get(el.dataset.phase);
    $('dag-inspector').textContent=phaseLabels[el.dataset.phase][0]+'\n'+members.map(s=>`${statuses[s.id]?.status==='completed'?'✓':'○'} ${s.id}`).join('\n');
    document.querySelectorAll('.phase-card').forEach(card=>card.classList.toggle('focused',card===el));
  });
}
function renderDAG(definitions, statuses = {}, runStatus = '', title = 'Workflow', preview = false) {
  lastGraph = [definitions,statuses,runStatus,title,preview];
  const signature = JSON.stringify([definitions,statuses,runStatus,title,preview,dagMode]);
  if (typeof graphSignature !== 'undefined' && signature === graphSignature) return;
  if (typeof graphSignature !== 'undefined') graphSignature=signature;
  $('dag-title').textContent = title;
  $('dag-caption').textContent = `${preview ? 'Preview' : 'Selected run'} · ${definitions.length} steps · ${dagMode==='overview'?'evaluation phases':'exact dependencies'}`;
  document.querySelectorAll('[data-dag-mode]').forEach(el=>{el.classList.toggle('active',el.dataset.dagMode===dagMode);el.setAttribute('aria-pressed',String(el.dataset.dagMode===dagMode));});
  if (dagMode === 'overview' && definitions.length) {renderOverview(definitions,statuses,runStatus);return;}
  const depths = new Map(), nodes = new Map(), levels = [];
  for (const step of definitions) {
    const depth = Math.max(-1, ...step.depends_on.map(id => depths.get(id) ?? -1)) + 1;
    depths.set(step.id, depth);
    (levels[depth] ||= []).push(step);
  }
  const columns = Math.max(1, ...levels.map(level => level.length));
  const width = Math.max(300, columns * 112 + 16), height = levels.length * 76 + 16;
  for (const [depth, level] of levels.entries()) {
    level.forEach((step, i) => {
      let status = statuses[step.id]?.status || 'pending';
      if (status === 'running' && ['failed','interrupted'].includes(runStatus)) status = 'failed';
      nodes.set(step.id, {...step, status, x: (i + .5) * width / level.length - 50, y: depth * 76 + 8});
    });
  }
  const edges = [...nodes.values()].flatMap(node => node.depends_on.map(id => {
    const parent = nodes.get(id); if (!parent) return '';
    const x1 = parent.x + 50, y1 = parent.y + 43, x2 = node.x + 50, y2 = node.y;
    return `<path class="dag-edge ${parent.status === 'completed' ? 'done' : ''}" d="M ${x1} ${y1} C ${x1} ${y1+18}, ${x2} ${y2-18}, ${x2} ${y2}" marker-end="url(#dag-arrow)"/>`;
  })).join('');
  const cards = [...nodes.values()].map(node => {
    const label = node.id.replaceAll('-', ' '), short = label.length > 15 ? label.slice(0,14) + '…' : label;
    const icon = {completed:'✓',running:'◌',failed:'!'}[node.status] || '○';
    return `<g class="dag-node ${node.status} ${focusedStep === node.id ? 'focused' : ''}" transform="translate(${node.x},${node.y})" data-step="${escape(node.id)}" tabindex="0" role="button" aria-label="${escape(node.id)}: ${node.status}"><title>${escape(node.id)} · ${escape(node.type)} · ${node.status}</title><rect width="100" height="43" rx="7"/><text x="8" y="16" class="dag-icon">${icon}</text><text x="23" y="16">${escape(short)}</text><text x="8" y="32" class="dag-kind">${escape(node.type.replaceAll('_',' ').slice(0,19))}</text></g>`;
  }).join('');
  const viewportWidth = Math.max(width, $('dag').clientWidth - 2);
  const scale = 1;
  $('dag').innerHTML = definitions.length ? `<svg viewBox="0 0 ${width} ${height}" width="${viewportWidth}" height="${height * scale}" aria-label="${escape(title)} dependency graph"><defs><marker id="dag-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#526c81"/></marker></defs>${edges}${cards}</svg>` : '<p class="empty">No workflow steps available. Select a scenario and retry Preview.</p>';
  if (typeof applyGraphZoom === 'function') applyGraphZoom();
  function inspect(id) {
    focusedStep = id;
    const node = nodes.get(id);
    $('dag-inspector').textContent = `${id} · ${node.status}\n${node.type}\nRequires: ${node.depends_on.join(', ') || 'No dependencies'}${statuses[id]?.detail ? '\n' + statuses[id].detail : ''}`;
    document.querySelectorAll('.dag-node').forEach(el => el.classList.toggle('focused', el.dataset.step === id));
  }
  document.querySelectorAll('.dag-node').forEach(el => {
    el.onclick = () => inspect(el.dataset.step);
    el.onkeydown = e => { if (['Enter',' '].includes(e.key)) { e.preventDefault(); inspect(el.dataset.step); } };
  });
  if (focusedStep && nodes.has(focusedStep)) inspect(focusedStep);
  else {focusedStep = null; $('dag-inspector').textContent = 'Select a step to inspect its dependencies.';}
}
