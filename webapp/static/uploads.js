/* Uploaded rubric data never becomes an agent prompt or judge instruction. */
let uploadedRubric = null;
let rubricUploading = false;
let rubricInvalid = false;
const uploadPanel=document.createElement('details');
uploadPanel.className='rubric-upload';
uploadPanel.innerHTML=`<summary>Upload a rubric (JSON)</summary><p>Choose approved observable checks for the existing triage or report scenario. New worlds, code, free-form prompts and infrastructure requests are not supported. Trusted grading stays enabled.</p><button id="rubric-template" type="button" class="secondary">Download template</button> <a href="/api/rubrics/catalog" target="_blank" rel="noopener">Approved checks</a><label>Rubric file (max 16 KB)<input id="rubric-file" type="file" accept=".json,application/json"></label><p id="rubric-upload-status" role="status"></p><button id="rubric-remove" class="secondary" type="button" hidden>Remove rubric</button>`;
document.querySelector('.launch').append(uploadPanel);
$('rubric-template').onclick=async()=>{
 try{
  const catalog=await api('/api/rubrics/catalog');
  const scenario=['triage','report'].includes($('pipeline').value)?$('pipeline').value:'triage';
  const template={version:1,scenario,title:'Cyber investigation rubric',checks:catalog[scenario].slice(0,4).map(c=>({id:c.id,weight:1}))};
  const blob=new Blob([JSON.stringify(template,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob);
  const link=document.createElement('a');link.href=url;link.download=`${scenario}-rubric.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 }catch(e){$('rubric-upload-status').textContent=e.message;}
};
$('rubric-file').onchange=async()=>{
 uploadedRubric=null;
 rubricInvalid=false;
 $('rubric-remove').hidden=true;
 updateLaunchOptions();
 const file=$('rubric-file').files[0];if(!file)return;
 if(file.size>16384){rubricInvalid=true;$('rubric-remove').hidden=false;$('rubric-upload-status').textContent='File exceeds 16 KB. Remove or replace it to run.';updateLaunchOptions();return;}
 rubricUploading=true;updateLaunchOptions();
 try{
  const result=await api('/api/rubrics',{method:'POST',headers:{'Content-Type':'application/json'},body:await file.text()});
  uploadedRubric=result;$('pipeline').value=result.scenario;$('pipeline').dispatchEvent(new Event('change'));
  $('rubric-upload-status').textContent=`Validated: ${result.title} · ${result.checks} checks · matching scenario only · maximum 3 trials.`;
  $('rubric-remove').hidden=false;
 }catch(e){rubricInvalid=true;$('rubric-upload-status').textContent=e.message+' Remove or replace it to run.';$('rubric-remove').hidden=false;}
 rubricUploading=false;updateLaunchOptions();
};
$('rubric-remove').onclick=()=>{uploadedRubric=null;rubricInvalid=false;$('rubric-file').value='';$('rubric-upload-status').textContent='';$('rubric-remove').hidden=true;updateLaunchOptions();};
