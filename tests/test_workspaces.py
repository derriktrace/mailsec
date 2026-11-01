import asyncio
import json
from dataclasses import replace

import httpx
import pytest
from sqlalchemy import select

from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.corpus import blind_evidence, samples
from mailsec.import_corpus import import_corpus
from mailsec.pipeline import Pipeline
from mailsec.runtime_controls import refresh_controls, update_controls

RAW = b'From: Example <sender@example.com>\nTo: phishing@pot\nSubject: A message\n\nHello phishing@pot\n'


def test_evaluation_cannot_use_mailbox_credentials_or_enable_actions(tmp_path):
    s = Settings(database_url=f'sqlite:///{tmp_path}/evaluation.db', evaluation_mode=True,
        enforcement_mode='auto_quarantine', notifications_enabled=True, mailboxes=['owner@example.com'],
        authorized_mailboxes=['owner@example.com'], google_oauth_client_file='/secret',
        google_service_account_file='/secret',token_encryption_key='secret',organization={'domains':['owned.com']})
    p = Pipeline(s)
    assert s.organization == {}
    assert not s.mailboxes and not s.authorized_mailboxes
    assert not s.google_oauth_client_file and not s.google_service_account_file and not s.token_encryption_key
    s.enforcement_mode='auto_quarantine'
    assert refresh_controls(s,p.store)=={'mode':'passive','notifications_enabled':False}
    with pytest.raises(ValueError):
        update_controls(s,p.store,{'mode':'auto_quarantine'})
    with pytest.raises(ValueError):
        p.ingest(RAW,provider='gmail')


def test_separate_databases_and_proxy_routes(tmp_path,monkeypatch):
    async def check():
        base = Settings(database_url=f'sqlite:///{tmp_path}/live.db',app_token='test-token',
            workspace_switching=True,evaluation_proxy_url='http://localhost:8025')
        live = Pipeline(base)
        evaluated = Pipeline(replace(base,database_url=f'sqlite:///{tmp_path}/evaluation.db',
            evaluation_mode=True,evaluation_proxy_url=''))
        live_id = live.ingest(RAW)['id']
        eval_id = evaluated.ingest(RAW.replace(b'A message',b'Another message'))['id']
        app=create_app(base,live)
        eval_app=create_app(evaluated.settings,evaluated)
        original = httpx.AsyncClient
        frontend=original(transport=httpx.ASGITransport(app=app),base_url='http://localhost')
        def upstream(**kwargs):
            kwargs['transport']=httpx.ASGITransport(app=eval_app)
            return original(**kwargs)
        monkeypatch.setattr(httpx,'AsyncClient',upstream)
        async with frontend as client:
            for prefix in ('','/evaluation'):
                assert (await client.get(prefix+'/api/messages')).status_code==401
            client.headers['authorization']='Bearer test-token'
            for prefix,own,other in [('',live_id,eval_id),('/evaluation',eval_id,live_id)]:
                r=await client.get(prefix+'/api/messages')
                assert r.status_code==200
                assert [m['id'] for m in r.json()['messages']]==[own]
                assert (await client.get(prefix+'/api/messages/'+other)).status_code==404
                assert (await client.post(prefix+'/api/messages/'+other+'/replay')).status_code==404
                assert (await client.get(prefix+'/api/overview')).json()['total_messages']==1
            assert (await client.get('/evaluation/api/workspaces')).json()['evaluation'] is True
            assert (await client.patch('/evaluation/api/protection',json={'mode':'auto_quarantine'})).status_code==403
            assert (await client.post('/evaluation/api/accounts/connect',json={'mailbox':'owner@example.com'})).status_code==403
            assert (await client.post('/evaluation/api/messages/'+eval_id+'/release')).status_code==403
            assert (await client.post('/evaluation/api/messages/'+eval_id+'/replay',headers={'origin':'https://evil.invalid'})).status_code==403
            assert (await client.get('/evaluation/api/accounts')).json()['accounts']==[]
            assert (await client.get('/evaluation/api/actions')).json()['actions']==[]
            assert (await client.get('/evaluation/')).status_code==200
            assert (await client.get('/api/corpus')).status_code==404
    asyncio.run(check())


def test_corpus_provenance_is_separate_and_import_is_idempotent(tmp_path):
    root=tmp_path/'corpus'
    root.mkdir()
    (root/'PHISHING.eml').write_bytes(RAW)
    (root/'duplicate.eml').write_bytes(RAW)
    (root/'empty.eml').touch()
    outside=tmp_path/'outside.eml'
    outside.write_bytes(RAW)
    (root/'symlink.eml').symlink_to(outside)
    p=Pipeline(Settings(database_url=f'sqlite:///{tmp_path}/evaluation.db',evaluation_mode=True))
    r=import_corpus(root,'revision123',p)
    assert r['imported']==1 and r['exact_duplicate_files']==1 and len(r['skipped'])==2
    assert r['accuracy'] is None
    assert r['reference_labels']=={'unreviewed':1}
    assert import_corpus(root,'revision123',p)['newly_imported']==0
    with p.store.engine.connect() as c:
        sample=c.execute(select(samples)).mappings().one()
    stored=p.store.get_message(sample['message_id'])
    assert stored['raw']==RAW
    assert stored['provider']=='eml' and stored['mailbox']==''
    assert 'PHISHING.eml' not in json.dumps(stored['parsed'])
    evidence={'body':'Hello phishing@pot. Suspicious phishing request? abcPHISHING@pot123',
              'links':[{'raw_url':'https://example.com/?email=phishing%40pot_suffix'}]}
    neutral=blind_evidence(evidence)
    assert 'phishing@pot' not in json.dumps(neutral) and 'phishing%40pot' not in json.dumps(neutral)
    assert 'Suspicious phishing request?' in neutral['body']
    assert 'abcPHISHING@pot123' not in neutral['body']
    assert 'abcrecipient@example.invalid123' in neutral['body']
    assert 'phishing@pot' in evidence['body']
    assert p.store.status()['counts']['pending']==1


def test_evaluation_pipeline_blinds_decoded_state_and_does_not_infer_history(tmp_path, monkeypatch):
    class Jev:
        state = None

        def evaluate(self, state, questions=None):
            self.state = state
            return {'model':'test','answers':{'verdict':{'choice':'clean','confidence':1,
                'probabilities':{'clean':1,'spam':0,'suspicious':0,'phishing':0}}}}

    class Inspector:
        def inspect(self, raw):
            assert raw == RAW
            return {'status':'complete','antivirus':{'status':'clean'},'findings':[],
                    'urls':[], 'attachments':[{'text':'Dear phishing@pot'}]}

    jev = Jev()
    p=Pipeline(Settings(database_url=f'sqlite:///{tmp_path}/evaluation.db',evaluation_mode=True),
               jev=jev,inspector=Inspector())
    # Isolate corpus projection with an explicitly permitted synthetic gate.
    # Actual provider authorization is exercised by test_provider_consent;
    # evaluation workspaces deliberately cannot grant owner consent in the UI.
    monkeypatch.setattr('mailsec.pipeline.require_consent', lambda *_: None)
    def forbidden_history(*args):
        raise AssertionError('A corpus cannot supply mailbox history')
    monkeypatch.setattr(p.store,'sender_history',forbidden_history)
    item=p.ingest(RAW)
    result=p.process_one()
    assert result['status']=='complete'
    state=json.dumps(jev.state)
    assert 'phishing@pot' not in state
    assert 'recipient@example.invalid' in state
    assert jev.state['identity']['history_status']=='not_available'
    run=p.store.detail(item['id'])['runs'][0]
    assert 'phishing@pot' in run['evidence']['body']
    assert run['policy']['eligible_action']=='none'
    assert run['versions']['evaluation_input']=='neutral-corpus-v2'


def test_invalid_transport_header_bytes_do_not_abort_evidence_hashing():
    import hashlib

    from mailsec.security_cache import digest
    valid={'subject':'Café — message','count':2}
    previous=hashlib.sha256(json.dumps(valid,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    assert digest(valid)==previous
    assert digest({'header':'bad\udcff'})==digest({'header':'bad\udcff'})
    assert digest({'header':'bad\udcff'})!=digest({'header':r'bad\udcff'})
