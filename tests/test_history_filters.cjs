const assert = require('node:assert/strict');
const {filterHistory} = require('../webapp/static/history.js');
const runs = [
  {id:'alpha',pipeline:'triage',status:'completed',model:'GPT-5',created_at:'2026-11-10T10:00:00Z'},
  {id:'beta',pipeline:'report',status:'failed',judge_model:'GPT-6-Sol',created_at:'2026-11-11T10:00:00Z',batch_id:'group'},
  {id:'gamma',pipeline:'triage',status:'running',created_at:'2026-11-12T10:00:00Z',started_at:'2026-11-12T11:00:00Z'},
  {id:'invalid',pipeline:'rules',status:'queued',created_at:'unknown'}
];
const ids = (filters,items=runs,groups=false)=>filterHistory(items,filters,groups).map(r=>r.id);
assert.deepEqual(ids({scenario:'triage',status:'completed'}),['alpha']);
assert.deepEqual(ids({search:'gpt-6-sol'}),['beta']);
assert.deepEqual(ids({search:' ALPHA '}),['alpha']);
assert.deepEqual(ids({kind:'single'}),['gamma','alpha','invalid']);
assert.deepEqual(ids({kind:'group'}),['beta']);
assert.deepEqual(ids({from:'2026-11-11T10:00:00Z',to:'2026-11-12T11:00:00Z'}),['gamma','beta']);
assert.deepEqual(ids({from:'2026-11-12T10:30:00Z'}),['gamma']);
assert.deepEqual(ids({from:'2026-11-12',to:'2026-11-10'}),[]);
assert.deepEqual(ids({from:'bad'}),[]);
assert.deepEqual(ids({sort:'oldest'}),['invalid','alpha','beta','gamma']);
assert.deepEqual(ids({scenario:'missing'}),[]);
assert.deepEqual(ids({scenario:'report'},[{id:'g',pipelines:['triage','report'],status:'completed',created_at:'2026-11-11'}],true),['g']);
assert.deepEqual(ids({kind:'single'},[{id:'g',pipelines:['triage'],created_at:'2026-11-11'}],true),[]);
assert.deepEqual(runs.map(r=>r.id),['alpha','beta','gamma','invalid']);
console.log('History filter tests passed (scenario, status, model/ID, time bounds, groups, sort, invalid dates, nonmutation).');
