/* Expand the same live graph into a large dialog; keep its viewport across status refreshes. */
let graphZoom = 1, graphSize = null, graphSignature = '';
const graphDialog = document.createElement('dialog');
graphDialog.id = 'graph-dialog';
graphDialog.innerHTML = '<header><div><h2>Evaluation workflow</h2><p>Scroll to pan · Ctrl/⌘ + wheel to zoom · select a node for dependencies</p></div><div class="graph-toolbar"><button id="zoom-out" aria-label="Zoom out">−</button><output id="zoom-level">100%</output><button id="zoom-in" aria-label="Zoom in">+</button><button id="zoom-fit">Fit graph</button><button id="zoom-reset">100%</button><button id="graph-close" aria-label="Close expanded graph">Close ✕</button></div></header><div id="expanded-graph-slot"></div>';
document.body.append(graphDialog);
const graphPanel = document.querySelector('.dag-panel');
const graphHome = document.createComment('graph home');
graphPanel.before(graphHome);
const expandButton = document.createElement('button');
expandButton.id = 'graph-expand'; expandButton.textContent = '⛶ Expand graph'; expandButton.title = 'Open the complete graph with zoom controls';
document.querySelector('.dag-heading').append(expandButton);
function applyGraphZoom() {
  const svg = $('dag').querySelector('svg');
  if (!svg) return;
  const box = svg.viewBox.baseVal;
  svg.setAttribute('width', box.width * graphZoom);
  svg.setAttribute('height', box.height * graphZoom);
  $('zoom-level').textContent = Math.round(graphZoom * 100) + '%';
}
function changeGraphZoom(value) { graphZoom = Math.max(.15,Math.min(4,value)); applyGraphZoom(); }
function fitGraph() {
  const svg = $('dag').querySelector('svg'); if (!svg) return;
  changeGraphZoom(Math.min(($('dag').clientWidth-30)/svg.viewBox.baseVal.width,($('dag').clientHeight-30)/svg.viewBox.baseVal.height));
  $('dag').scrollTop=0; $('dag').scrollLeft=0;
}
expandButton.onclick = () => {
  dagMode='details'; $('expanded-graph-slot').append(graphPanel); graphDialog.showModal();
  graphSignature=''; if(lastGraph)renderDAG(...lastGraph); fitGraph();
};
$('graph-close').onclick=()=>graphDialog.close();
graphDialog.addEventListener('close',()=>{
  graphHome.after(graphPanel); graphZoom=1; graphSignature=''; if(lastGraph)renderDAG(...lastGraph); expandButton.focus();
});
$('zoom-in').onclick=()=>changeGraphZoom(graphZoom*1.25);
$('zoom-out').onclick=()=>changeGraphZoom(graphZoom/1.25);
$('zoom-reset').onclick=()=>changeGraphZoom(1);
$('zoom-fit').onclick=fitGraph;
$('dag').addEventListener('wheel',e=>{if(graphDialog.open&&(e.ctrlKey||e.metaKey)){e.preventDefault();changeGraphZoom(graphZoom*(e.deltaY<0?1.1:1/1.1));}},{passive:false});
$('dag').addEventListener('dblclick',e=>{if(!graphDialog.open&&!e.target.closest('[data-step],[data-phase]'))expandButton.click();});
