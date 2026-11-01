// Synthetic, isolated Chromium coverage. No real mail, Google, or model calls.
// Run with Node 22+: node tests/questions-ui-smoke.mjs
import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';

const repo = fileURLToPath(new URL('../', import.meta.url));
const staticRoot = path.join(repo, 'mailsec/static');
const bundle = {};
for (const [group, file] of [['primary','questions.json'],['actions','action_questions.json'],['authority','authority_questions.json']]) bundle[group] = JSON.parse(await fs.readFile(path.join(repo,'mailsec',file),'utf8'));
const now = new Date().toISOString();
const revision = (id, label, bundles = bundle) => ({id,label,bundles:structuredClone(bundles),sha256:id.repeat(64).slice(0,64),created_at:now,source:'custom'});
const baseline = revision('a','Shipped baseline'); baseline.source = 'shipped';
const prior = revision('b','Older <img src=x onerror=alert(1)> version');
const fixture = {active:baseline,revisions:[baseline,prior],tests:[],requests:[],writable:true,provider:'jev',failSave:false,failActivation:false,nextTestError:false,polls:0};
const provider = () => ({provider:fixture.provider,model:'synthetic-model',fingerprint:(fixture.provider==='jev'?'1':'2').repeat(64),data_flow:'Synthetic fixture. No evidence leaves this local test server.',privacy:{provider:fixture.provider,title:fixture.provider==='jev'?'Jev sends email data to TypeSafe':'Authorize this model endpoint',summary:'Selected mail evidence and identifiers go to this provider; this synthetic test sends nothing outside its local fixture.',destination:fixture.provider==='jev'?'https://api.typesafe.ai/v1/systemone':'http://model.example.invalid',disclosure_version:'email-sharing-v1',disclosure_sha256:'3'.repeat(64),accepted:fixture.sharingAccepted!==false,analysis_allowed:fixture.sharingAccepted!==false,sections:[{title:'Evidence scope',body:'Recipient addresses, subject/body, complete URLs, extracted attachment/OCR/QR text, authentication and organization context, and custom question wording may be shared.'}]}});
const questions = () => ({active:fixture.active,defaults:{sha256:baseline.sha256,bundles:bundle},history:fixture.revisions.map(({bundles,...meta})=>({...meta,is_active:meta.id===fixture.active.id})),provider:provider(),writable:fixture.writable});
const server = http.createServer(async (req,res) => {
  const url = new URL(req.url,'http://localhost');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
  const json = (data,status=200) => {res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(data));};
  if (url.pathname.startsWith('/api/') && req.headers.authorization !== 'Bearer question-fixture-token') return json({detail:'Access token required'},401);
  let raw=''; for await (const part of req) raw += part;
  const body = raw ? JSON.parse(raw) : null;
  fixture.requests.push({method:req.method,path:url.pathname,body});
  if (url.pathname==='/api/status') return json({key_configured:true,model:'fixture',counts:{clean:0,spam:0,suspicious:0,phishing:0},decision:{configured:true},worker:{}});
  if (url.pathname==='/api/messages') return json({messages:[{id:'c'.repeat(32),subject:'Synthetic analyzed message',from_address:'test@example.invalid',status:'complete',run_count:1}],total:1});
  if (/^\/api\/messages\/[c]{32}$/.test(url.pathname)) return json({message:{id:'c'.repeat(32),subject:'Synthetic analyzed message'},runs:[],actions:[],feedback:[]});
  if (url.pathname==='/api/overview') return json({total_messages:1,analyzed_messages:1,verdict_counts:{clean:1,spam:0,suspicious:0,phishing:0},recent_risks:[]});
  if (url.pathname==='/api/accounts') return json({accounts:[]});
  if (url.pathname==='/api/actions') return json({actions:[]});
  if (url.pathname==='/api/protection') return json({mode:'passive',services:{},accounts:[],blockers:[]});
  if (url.pathname==='/api/workspaces') return json({workspaces:[{name:'Synthetic workspace',path:'/'}]});
  if (url.pathname==='/api/questions') {if(fixture.failQuestionFetch){fixture.failQuestionFetch--;return json({detail:'Synthetic metadata refresh unavailable'},503);}const data=questions();data.history_total=data.history.length;const offset=Number(url.searchParams.get('offset')||0);data.history=data.history.slice(offset,offset+(fixture.paginated?2:100));return json(data);}
  if (url.pathname==='/api/questions/tests') return json({tests:fixture.tests});
  if (url.pathname.startsWith('/api/questions/revisions/')) return json(fixture.revisions.find(rev=>rev.id===url.pathname.split('/').at(-1)));
  if (url.pathname==='/api/questions/drafts') {
    if (fixture.failSave) return json({detail:'Synthetic draft validation failed'},422);
    const created = revision(String.fromCharCode(100+fixture.revisions.length),body.label,body.bundles); fixture.revisions.unshift(created);if(fixture.failAfterSave){fixture.failQuestionFetch=1;fixture.failAfterSave=false;}return json(created,201);
  }
  if (url.pathname==='/api/questions/validate') {
    if(fixture.failValidation||Object.keys(body.bundles||{}).sort().join(',')!=='actions,authority,primary')return json({detail:'Question schema is incompatible. Use primary, actions, and authority without extra keys.'},400);
    return json({ok:true,bundles:body.bundles,sha256:'9'.repeat(64)});
  }
  if (url.pathname==='/api/questions/test') {
    if(body.expected_provider_fingerprint!==provider().fingerprint)return json({detail:'The decision provider changed. Review the current evidence destination before testing.'},409);
    const chosen=fixture.revisions.find(rev=>rev.id===body.revision_id);
    const test={id:'t'+fixture.tests.length,status:'running',revision_id:chosen.id,active_revision_id:fixture.active.id,candidate_sha256:chosen.sha256,provider_fingerprint:provider().fingerprint,provider:provider(),created_at:now,results:{},note:'Synthetic comparison; not a detection accuracy claim.'};
    fixture.tests.unshift(test);fixture.polls=0;return json(test,202);
  }
  if (url.pathname.startsWith('/api/questions/tests/')) {
    const test=fixture.tests.find(item=>item.id===url.pathname.split('/').at(-1));
    if (test.status==='running' && ++fixture.polls>=2) {
      const output={primary:{answers:{verdict:{choice:'clean',confidence:.7},deceptive_identity:{noul:.2}},comment:'<img src=https://unexpected.invalid/x onerror=alert(1)>'},action_review:{stages:{facts:{status:'complete',response:{answers:{payment_requested:{noul:.1}}}},authority:{status:'complete',response:{answers:{authority_relationship:{choice:'coherent',confidence:.8}}}}}},policy:{review_only:true}};
      test.results={active:output,candidate:structuredClone(output)};
      test.results.candidate.primary.answers.deceptive_identity.noul=.65;
      test.status=fixture.nextTestError?'error':'complete';
      if (fixture.nextTestError) {test.error='Synthetic authority stage failed';delete test.results.candidate.action_review;fixture.nextTestError=false;}
    }
    return json(test);
  }
  if (url.pathname==='/api/questions/activate') {
    if (fixture.failActivation) return json({detail:'Active version changed. Refresh and compare again.'},409);
    fixture.active=fixture.revisions.find(rev=>rev.id===body.revision_id);return json({active:fixture.active});
  }
  if (url.pathname==='/api/questions/restore-defaults') {const restored=revision('z','Restored shipped defaults');restored.source='restore_defaults';fixture.revisions.unshift(restored);fixture.active=restored;return json({active:restored});}
  if (url.pathname.startsWith('/api/')) return json({detail:'Not found'},404);
  const name=url.pathname==='/'?'index.html':url.pathname.replace(/^\/static\//,'');
  if (!['index.html','app.js','onboarding.js','question-editor.js','style.css'].includes(name)) return json({},404);
  try {const data=await fs.readFile(path.join(staticRoot,name));res.writeHead(200,{'Content-Type':name.endsWith('.js')?'application/javascript':name.endsWith('.css')?'text/css':'text/html'});res.end(data);} catch {json({},404);}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`http://127.0.0.1:${server.address().port}`;
const profile=await fs.mkdtemp(path.join(os.tmpdir(),'mailsec-question-ui-'));
const child=spawn(process.env.CHROMIUM_PATH||'/usr/bin/chromium-browser',['--headless','--no-sandbox','--disable-gpu','--disable-background-networking','--no-first-run','--no-default-browser-check',`--user-data-dir=${profile}`,'--remote-debugging-port=0',origin],{stdio:['ignore','ignore','pipe']});
let ws,current='Browser startup';const checks=[];
try {
  const endpoint=await new Promise((resolve,reject)=>{let output='';const timer=setTimeout(()=>reject(Error('Browser startup timeout')),12000);child.stderr.on('data',part=>{output+=part;const match=output.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(match){clearTimeout(timer);resolve(match[1]);}});child.on('exit',()=>reject(Error('Browser exited')));});
  const endpointURL=new URL(endpoint);const pages=await(await fetch(`http://${endpointURL.host}/json/list`)).json();ws=new WebSocket(pages.find(page=>page.type==='page').webSocketDebuggerUrl);await new Promise(resolve=>ws.addEventListener('open',resolve,{once:true}));
  let id=0;const pending=new Map(),errors=[],externalRequests=[];
  ws.addEventListener('message',event=>{const message=JSON.parse(event.data);if(message.id){const entry=pending.get(message.id);if(entry){clearTimeout(entry.timer);pending.delete(message.id);message.error?entry.reject(Error('Protocol error')):entry.resolve(message.result);}}if(message.method==='Runtime.exceptionThrown')errors.push('JavaScript exception');if(message.method==='Page.javascriptDialogOpening')errors.push('Unexpected script dialog');if(message.method==='Network.requestWillBeSent'){const url=message.params.request.url;if(/^https?:/.test(url)&&new URL(url).origin!==origin)externalRequests.push(url);}});
  const send=(method,params={})=>new Promise((resolve,reject)=>{const n=++id;const timer=setTimeout(()=>reject(Error('Protocol timeout')),10000);pending.set(n,{resolve,reject,timer});ws.send(JSON.stringify({id:n,method,params}));});
  const evaluate=async expression=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(r.exceptionDetails.exception?.description||r.exceptionDetails.text);return r.result.value;};
  const wait=async expression=>{for(let i=0;i<180;i++){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,50));}throw Error('Condition timeout');};
  const check=async(name,expression)=>{current=name;if(!await evaluate(expression))throw Error(name);checks.push(name);};
  const click=async selector=>evaluate(`document.querySelector(${JSON.stringify(selector)})?.click()`);
  const input=async(selector,value)=>evaluate(`document.querySelector(${JSON.stringify(selector)}).value=${JSON.stringify(value)};document.querySelector(${JSON.stringify(selector)}).dispatchEvent(new Event('input',{bubbles:true}))`);
  await send('Runtime.enable');await send('Network.enable');await send('Page.enable');
  await wait(`document.querySelector('#auth-dialog')?.open`);
  await evaluate(`document.querySelector('#access-token').value='question-fixture-token';document.querySelector('#auth-form').requestSubmit()`);
  await wait(`state.status&&state.detail&&!state.busy`);
  await click('#nav-questions');await wait(`document.querySelector('#question-save')`);
  await check('Advanced navigation opens editor with correct accessible heading',`state.view==='questions'&&document.querySelector('#nav-questions').getAttribute('aria-current')==='page'&&!document.querySelector('#questions-view').hidden`);
  await check('All three groups and fixed question schemas are visible',`document.querySelectorAll('.question-group').length===3&&document.querySelector('.question-schema').textContent.includes('fixed keys:')&&document.querySelector('.question-schema').textContent.includes('verdict')`);
  await check('Active baseline cannot be activated again',`document.querySelector('#question-activate').disabled&&document.querySelector('#question-edit-status').textContent==='Active version'`);
  await check('Hosted provider comparison clearly describes costs and data flow',`document.querySelector('.question-comparison').textContent.includes('six billable model calls')&&document.querySelector('.question-comparison').textContent.includes('hosted Jev')&&document.querySelector('.question-comparison').textContent.includes('does not change classifications')`);
  await check('History labels are rendered as inert text',`document.querySelector('.question-history').textContent.includes('<img src=x onerror=alert(1)>')&&!document.querySelector('#questions-view img,#questions-view script,#questions-view iframe')`);
  await evaluate(`[...document.querySelectorAll('button')].find(button=>button.textContent==='Copy questions').click()`);
  const copied=await evaluate(`document.querySelector('#question-transfer-text').value`);
  if(Object.keys(JSON.parse(copied)).sort().join(',')!=='actions,authority,primary')throw Error('Copy included extra data');checks.push('Copy contains all three question groups without metadata, secrets or email evidence');
  await check('Copy provides selectable plain text without a file workflow',`document.querySelector('#question-transfer-dialog').open&&document.querySelector('#question-transfer-text').readOnly&&!document.querySelector('#question-transfer-dialog input[type=file],#question-transfer-dialog a[download]')`);
  await evaluate(`document.querySelector('#question-transfer-dialog .modal-footer button:last-child').click()`);await wait(`document.querySelector('#question-transfer-result').textContent`);
  await check('Clipboard copy has a visible manual-copy fallback',`/copied|Copy command/.test(document.querySelector('#question-transfer-result').textContent)`);
  await evaluate(`document.querySelector('#question-transfer-dialog .modal-footer button:first-child').click()`);
  await evaluate(`[...document.querySelectorAll('button')].find(button=>button.textContent==='Paste questions').click()`);
  await input('#question-transfer-text','not JSON');await evaluate(`document.querySelector('#question-transfer-dialog .modal-footer button:last-child').click()`);
  await check('Invalid pasted text leaves editor and saved versions unchanged',`document.querySelector('#question-transfer-result').textContent.includes('not valid JSON')&&document.querySelector('#question-edit-status').textContent==='Active version'`);
  fixture.failValidation=true;await input('#question-transfer-text',copied);await evaluate(`document.querySelector('#question-transfer-dialog .modal-footer button:last-child').click()`);await wait(`document.querySelector('#question-transfer-result').textContent.includes('schema is incompatible')`);
  await check('Server schema failure preserves editor and keeps pasted text available',`document.querySelector('#question-transfer-text').value.length>0&&document.querySelector('#question-edit-status').textContent==='Active version'`);
  fixture.failValidation=false;await evaluate(`document.querySelector('#question-transfer-dialog .modal-footer button:last-child').click()`);await wait(`!document.querySelector('#question-transfer-dialog')`);
  await check('Valid pasted questions load only an unsaved draft',`document.querySelector('#question-edit-status').textContent==='Unsaved edits'&&!document.querySelector('#question-save').disabled&&document.querySelector('#question-activate').disabled`);
  if(fixture.revisions.length!==2||fixture.tests.length)throw Error('Paste wrote saved state');checks.push('Pasting does not save, test, activate or mutate mail');
  await click('#question-discard');await click('#confirm-accept');await wait(`document.querySelector('#question-edit-status').textContent==='Active version'`);
  await evaluate(`document.querySelector('.question-item').open=true`);
  const selector='textarea[data-question="verdict"][data-part="instructions"]';
  await input(selector,'Synthetic changed instructions <img src=x onerror=alert(1)>');
  await check('Editing enables save and discard but disables comparisons and activation',`!document.querySelector('#question-save').disabled&&!document.querySelector('#question-discard').disabled&&document.querySelector('#question-compare').disabled&&document.querySelector('#question-activate').disabled&&document.querySelector('#question-edit-status').textContent==='Unsaved edits'`);
  await evaluate(`refresh({force:true})`);
  await check('Background console refresh preserves unsaved question text',`document.querySelector(${JSON.stringify(selector)}).value.startsWith('Synthetic changed instructions')`);
  await click('#nav-overview');
  await check('Leaving unsaved edits requires a visible confirmation',`document.querySelector('#confirm-dialog').open&&state.view==='questions'&&document.querySelector('#confirm-title').textContent.includes('Discard unsaved')`);
  await click('#confirm-cancel');await check('Cancel navigation preserves editor and draft',`state.view==='questions'&&document.querySelector(${JSON.stringify(selector)}).value.startsWith('Synthetic changed instructions')`);
  await click('#nav-overview');await click('#confirm-accept');await wait(`state.view==='overview'`);await click('#nav-questions');await wait(`document.querySelector('#question-save')&&!document.querySelector('#questions-view').getAttribute('aria-busy').includes('true')`);
  await check('Confirmed discard restores the saved version when reopening',`!document.querySelector(${JSON.stringify(selector)}).value.startsWith('Synthetic changed instructions')&&document.querySelector('#question-save').disabled`);
  await input(selector,'Synthetic changed instructions <img src=x onerror=alert(1)>');
  await input('#question-version-note','Clarify request <img src=x onerror=alert(1)>');
  fixture.failSave=true;await click('#question-save');await wait(`document.querySelector('#question-notice').textContent.includes('Synthetic draft validation failed')`);
  await check('Failed save preserves edits and displays actionable error',`document.querySelector(${JSON.stringify(selector)}).value.startsWith('Synthetic changed instructions')&&!document.querySelector('#question-save').disabled&&document.querySelector('#question-notice').getAttribute('role')==='alert'`);
  fixture.failSave=false;fixture.failAfterSave=true;await click('#question-save');await wait(`document.querySelector('#question-notice').textContent.includes('Draft saved')`);
  if(fixture.active.id!=='a')throw Error('Draft changed active questions');checks.push('Saving appends immutable draft without changing active version');
  await check('Confirmed save followed by refresh failure is reported as saved',`document.querySelector('#question-notice').textContent.includes('Current version status could not be refreshed')&&document.querySelector('#question-save').disabled&&document.querySelector('#question-compare').disabled`);
  await evaluate(`document.querySelector('.question-heading button').click()`);await wait(`document.querySelector('.question-history-row button')`);await evaluate(`document.querySelector('.question-history-row button').click()`);await wait(`document.querySelector('.question-editor h3').textContent.startsWith('Clarify request')`);
  if(fixture.revisions.length!==3)throw Error('Metadata recovery duplicated draft');checks.push('Refresh recovers saved draft without duplicating a version');
  await check('Saved draft has inactive status and safely escaped note',`document.querySelector('#question-edit-status').textContent==='Saved version'&&document.querySelector('.question-editor h3').textContent.includes('<img src=x')&&!document.querySelector('#questions-view img')`);
  await input('#question-test-text','Subject: Synthetic notice\nA benign message.');await click('#question-compare');
  await wait(`document.querySelector('.question-test-result')`);
  await check('Pending comparison blocks activation and duplicate submissions',`document.querySelector('#question-activate').disabled&&document.querySelector('#question-compare').disabled&&document.querySelector('.question-test-result').textContent.includes('Activation is unavailable')`);
  await click('#nav-overview');await check('Background test permits leaving view without canceling work',`state.view==='overview'`);
  await click('#nav-questions');await wait(`!document.querySelector('#question-activate').disabled`);
  await check('Completed comparison shows both versions and Jev confidence',`document.querySelectorAll('.question-result-card').length===2&&document.querySelectorAll('.question-result-card .badge.clean').length===2&&document.querySelector('.question-test-result').textContent.includes('Jev confidence: 70%')`);
  await check('Readable comparison covers every question group and highlights changed judgments',`document.querySelectorAll('.question-judgment-table').length===3&&document.querySelector('.question-judgments').textContent.includes('Probability of yes: 65%')&&document.querySelector('.question-judgment-table tr.changed').textContent.includes('Deceptive Identity')&&document.querySelector('.question-judgments').textContent.includes('Authority Relationship')`);
  await evaluate(`document.querySelectorAll('.question-result-card details').forEach(node=>node.open=true)`);
  await check('Model output remains inert and never fetches referenced URLs',`document.querySelector('.question-test-result').textContent.includes('https://unexpected.invalid/x')&&!document.querySelector('.question-test-result img,.question-test-result iframe,.question-test-result script')`);
  const testRequest=fixture.requests.find(request=>request.path==='/api/questions/test'&&request.method==='POST');
  if(Object.keys(testRequest.body).sort().join(',')!=='expected_provider_fingerprint,revision_id,text')throw Error('Unexpected comparison input fields');checks.push('Pasted comparison submits provider fingerprint and no expected answer or classification');
  await click('#question-activate');await check('Activation requires explicit confirmation',`document.querySelector('#confirm-dialog').open&&document.querySelector('#confirm-description').textContent.includes('future analyses')`);
  await click('#confirm-cancel');if(fixture.active.id!=='a')throw Error('Canceled activation wrote');checks.push('Canceled activation makes no write');
  fixture.failActivation=true;await click('#question-activate');await click('#confirm-accept');await wait(`document.querySelector('#question-notice').textContent.includes('Active version changed')`);
  await check('Activation conflict invalidates test authorization',`document.querySelector('#question-activate').disabled&&document.querySelector('#question-notice').getAttribute('role')==='alert'`);
  fixture.failActivation=false;await click('#question-compare');await wait(`!document.querySelector('#question-activate').disabled`);
  await click('#question-activate');await click('#confirm-accept');await wait(`document.querySelector('#question-notice').textContent.includes('Version activated')`);
  if(fixture.active.id==='a')throw Error('Activation not applied');checks.push('Tested draft activates with expected active id and comparison id');
  await check('Active history entry updates without deleting baseline',`document.querySelectorAll('.question-history-row').length===3&&document.querySelector('#question-edit-status').textContent==='Active version'`);
  await evaluate(`document.querySelectorAll('.question-history-row')[2].querySelector('button').click()`);await wait(`document.querySelector('.question-editor h3').textContent.startsWith('Older')`);
  await check('Older revision loads read-only schema and requires a fresh comparison',`document.querySelector('#question-activate').disabled&&document.querySelector('#question-edit-status').textContent==='Saved version'`);
  fixture.nextTestError=true;await click('#question-compare');await wait(`document.querySelector('.question-test-result')?.textContent.includes('Synthetic authority stage failed')`);
  await check('Partial failed comparison preserves outputs and refuses activation',`document.querySelector('#question-activate').disabled&&document.querySelector('.question-test-result').textContent.includes('partial output cannot authorize activation')&&document.querySelectorAll('.question-result-card').length===2`);
  await evaluate(`document.querySelector('#question-test-mode').value='message';document.querySelector('#question-test-mode').dispatchEvent(new Event('change'))`);await wait(`document.querySelector('#question-test-message')?.options.length===2`);
  await evaluate(`document.querySelector('#question-test-message').value='${'c'.repeat(32)}';document.querySelector('#question-test-message').dispatchEvent(new Event('change'))`);
  await click('#question-compare');await wait(`!document.querySelector('#question-activate').disabled`);
  const messageRequest=fixture.requests.filter(request=>request.path==='/api/questions/test'&&request.method==='POST').at(-1);
  if(Object.keys(messageRequest.body).sort().join(',')!=='expected_provider_fingerprint,message_id,revision_id')throw Error('Existing message comparison leaked labels');checks.push('Existing message comparison submits stable message id and provider fingerprint');
  for(const width of [1360,390,320]){await send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<690});await check(`Editor at ${width}px has no horizontal overflow`,`document.documentElement.scrollWidth<=window.innerWidth`);}
  await send('Emulation.setDeviceMetricsOverride',{width:1360,height:1100,deviceScaleFactor:1,mobile:false});
  const screenshot=await send('Page.captureScreenshot',{format:'png'});await fs.writeFile('/tmp/mailsec-question-editor.png',Buffer.from(screenshot.data,'base64'));
  await click('#question-restore');await check('Restore explains history retention and default activation',`document.querySelector('#confirm-dialog').open&&document.querySelector('#confirm-description').textContent.includes('saved versions, and test history are retained')`);
  await click('#confirm-cancel');if(fixture.active.id==='z')throw Error('Canceled restore wrote');checks.push('Canceled restore preserves active questions');
  await click('#question-restore');await click('#confirm-accept');await wait(`document.querySelector('#question-notice').textContent.includes('Shipped defaults restored')`);
  if(fixture.revisions.length!==4||fixture.active.id!=='z')throw Error('Restore lost history');checks.push('Restore defaults creates a new active revision and retains history');
  const priorTests=fixture.tests.length;fixture.provider='ollama';
  await click('#question-compare');await wait(`document.querySelector('#question-notice').textContent.includes('decision provider changed')`);
  if(fixture.tests.length!==priorTests)throw Error('Stale provider started comparison');checks.push('Stale provider fingerprint refuses undisclosed evidence destination before testing');
  await check('Rejected provider change refreshes the disclosed endpoint flow',`document.querySelector('.question-comparison').textContent.includes('server’s resources')`);
  await click('#question-compare');await wait(`document.querySelector('.question-test-result')?.textContent.includes('Estimated score: 70%')`);
  await check('Local comparison labels model estimates without Jev attribution',`document.querySelector('.question-test-result').textContent.includes('Uncalibrated estimate')&&!document.querySelector('.question-test-result').textContent.includes('Jev confidence')`);
  fixture.paginated=true;fixture.writable=false;
  await evaluate(`document.querySelector('.question-heading button').click()`);await wait(`document.querySelector('.question-comparison')?.textContent.includes('server’s resources')`);
  await evaluate(`[...document.querySelectorAll('button')].find(button=>button.textContent==='Load older versions').click()`);await wait(`document.querySelectorAll('.question-history-row').length===4`);
  await check('Older version pagination retains all saved versions',`document.querySelectorAll('.question-history-row').length===4&&!document.querySelector('.question-history').textContent.includes('Showing 2 of')`);
  await check('Configured provider data flow and automatic-quarantine restriction stay explicit',`!document.querySelector('.question-comparison').textContent.includes('six billable')&&document.querySelector('#questions-view').textContent.includes('Custom model scores alone still cannot trigger automatic quarantine')`);
  await check('Read-only settings disable editing, tests, activation and defaults',`[...document.querySelectorAll('#questions-view textarea[data-question]')].every(input=>input.disabled)&&document.querySelector('#question-save').disabled&&document.querySelector('#question-compare').disabled&&document.querySelector('#question-activate').disabled&&document.querySelector('#question-restore').disabled`);
  fixture.writable=true;fixture.sharingAccepted=false;await evaluate(`document.querySelector('.question-heading button').click()`);await wait(`document.querySelector('.question-comparison')?.textContent.includes('Question comparisons are paused')`);
  await check('Question comparison cannot send email evidence without enabled owner approval',`document.querySelector('#question-compare').disabled&&document.querySelector('#question-activate').disabled&&document.querySelector('.question-sharing-details').open&&document.querySelector('.question-sharing-details').textContent.includes('Recipient addresses')&&[...document.querySelectorAll('button')].some(button=>button.textContent==='Review and allow email sharing')`);
  if(fixture.requests.some(request=>request.method!=='GET'&&!request.path.startsWith('/api/questions/')))throw Error('Comparison unexpectedly mutated mail');checks.push('All writes stay inside detection question endpoints');
  if(externalRequests.length)throw Error('Unexpected external request');checks.push('Question text and model output cause no external requests');
  if(errors.length)throw Error(errors.join(', '));checks.push('No browser runtime exceptions or script dialogs');
  process.stdout.write(JSON.stringify({ok:true,checks:checks.length,passed:checks,screenshot:'/tmp/mailsec-question-editor.png'},null,2)+'\n');
} catch(error) {process.stderr.write(JSON.stringify({ok:false,current,error:error.message,checks},null,2)+'\n');process.exitCode=1;}
finally {ws?.close();child.kill('SIGTERM');server.close();await fs.rm(profile,{recursive:true,force:true,maxRetries:5,retryDelay:100}).catch(()=>{});}
