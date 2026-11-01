import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .accounts import account_health, connected_mailboxes, register_account_routes
from .config import Settings
from .http_security import ConsoleSecurityMiddleware
from .mailbox_actions import abandon_notification, enqueue_action, list_actions, reconcile_notification
from .manual_actions import enqueue_manual_action, enqueue_manual_undo, require_manual_access
from .pipeline import Pipeline
from .runtime_controls import refresh_controls, update_controls


class Review(BaseModel):
    verdict: Literal["clean", "spam", "suspicious", "phishing"]
    reason: str = Field(default="", max_length=4000)
    reviewer: str = Field(default="local analyst", min_length=1, max_length=120)
    run_id: str | None = Field(default=None, max_length=32)
    apply_verdict: bool = False


class ProtectionControls(BaseModel):
    mode: Literal['passive','flag_only','auto_quarantine'] | None = None
    notifications_enabled: bool | None = None


class ManualLabel(BaseModel):
    verdict: Literal['clean', 'spam', 'suspicious', 'phishing']
    move_to_label: bool = False
    idempotency_key: str = Field(min_length=8, max_length=80, pattern=r'^[A-Za-z0-9_-]+$')


def create_app(settings=None, pipeline=None):
    os.umask(0o077)
    settings = settings or Settings.load()
    pipeline = pipeline or Pipeline(settings)

    @asynccontextmanager
    async def lifespan(_):
        stop, thread = threading.Event(), None
        if settings.embedded_worker:
            from .worker import run_worker
            thread = threading.Thread(target=run_worker, args=(settings, stop), daemon=True)
            thread.start()
        yield
        stop.set()
        if thread:
            thread.join(timeout=2)

    app = FastAPI(title="Mailsec", version="0.4.0-alpha.8", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.pipeline = pipeline
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    app.add_middleware(ConsoleSecurityMiddleware, settings=settings)
    from .question_settings import register_question_routes
    register_question_routes(app, settings, pipeline.store)
    from .provider_consent import register_privacy_routes
    register_privacy_routes(app, settings, pipeline.store)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, exc: RequestValidationError):
        # Pydantic's default error response includes rejected input values. Setup
        # forms contain OAuth secrets and API keys, even when fields use repr=False.
        return JSONResponse({"detail": "Invalid request data", "errors": [
            {"location": list(error["loc"]), "type": error["type"]}
            for error in exc.errors()[:20]
        ]}, status_code=422)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get('/api/workspaces')
    def workspaces():
        return {'current':'evaluation' if settings.evaluation_mode else 'organization',
                'name':settings.workspace_name, 'evaluation':settings.evaluation_mode,
                'workspaces': ([{'id':'organization','name':settings.workspace_name,'path':'/'},
                                {'id':'evaluation','name':'Phishing Pot','path':'/evaluation/'}]
                               if settings.workspace_switching else
                               [{'id':'organization','name':settings.workspace_name,'path':'/'}])}

    @app.get('/api/corpus')
    def corpus_summary():
        if not settings.evaluation_mode:
            raise HTTPException(404,'No evaluation corpus in this workspace')
        from .corpus import corpus_status
        return corpus_status(pipeline.store)

    if settings.evaluation_proxy_url:
        @app.get('/evaluation', include_in_schema=False)
        def evaluation_redirect():
            return RedirectResponse('/evaluation/')

        @app.api_route('/evaluation/{path:path}', methods=['GET','POST','PATCH','HEAD'], include_in_schema=False)
        async def evaluation_proxy(path: str, request: Request):
            # Fixed internal upstream, no caller-controlled host or redirects.
            if path and (not path.startswith('api/') or '..' in path or '\\' in path):
                raise HTTPException(404,'Evaluation route not found')
            if not path and request.method not in {'GET', 'HEAD'}:
                raise HTTPException(405, 'Use an authenticated evaluation API route')
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > settings.max_message_bytes + 65536:
                    raise HTTPException(413,'Upload exceeds 25 MiB')
            url = httpx.URL(settings.evaluation_proxy_url).copy_with(
                path='/' + path, query=request.url.query.encode())
            headers = {key:request.headers[key] for key in ('authorization','content-type') if key in request.headers}
            try:
                async with httpx.AsyncClient(timeout=130,trust_env=False,follow_redirects=False) as client:
                    async with client.stream(request.method,url,content=bytes(body),headers=headers) as result:
                        content = bytearray()
                        async for chunk in result.aiter_bytes():
                            content.extend(chunk)
                            if len(content)>32*1024*1024:
                                raise HTTPException(502,'Evaluation response exceeds console limit')
                        return Response(bytes(content),status_code=result.status_code,
                                        headers={'content-type':result.headers.get('content-type','application/json')})
            except httpx.HTTPError:
                raise HTTPException(503,'Evaluation workspace is unavailable; your mail workspace is unaffected.') from None

    @app.get("/api/status")
    def status():
        from .model_setup import model_status
        refresh_controls(settings,pipeline.store)
        model = model_status(settings, pipeline.store)
        connections = connected_mailboxes(settings,pipeline.store)
        return {"mode": settings.enforcement_mode, "model": model['model'], "key_configured": model['configured'],
                "decision": model,
                "google_configured": bool(connections),
                "mailboxes": [pipeline.store.mailbox_state(m) for m in connections],
                "versions": settings.versions(), **pipeline.store.status()}

    @app.get('/api/protection')
    def protection_status():
        from .model_setup import model_status
        refresh_controls(settings,pipeline.store)
        model = model_status(settings, pipeline.store)
        accounts = account_health(settings,pipeline.store)
        inspection = {'configured':bool(settings.inspection_url),'reachable':False,'status':'not_configured'}
        if settings.inspection_url:
            try:
                r=httpx.get(settings.inspection_url.rstrip('/')+'/health',timeout=2,follow_redirects=False,trust_env=False)
                data = r.json() if r.status_code in (200,503) else {}
                inspection.update(reachable=bool(data), status=data.get('status','unavailable'), antivirus=data.get('antivirus',{}))
            except (httpx.HTTPError, ValueError):
                inspection['status']='unavailable'
        reputation_health = pipeline.cache.get('provider_health', 'web_risk')
        reputation_health = reputation_health['value'] if reputation_health else {'status':'not_checked'}
        retry_health = pipeline.store.status()['scan_retries']
        blockers=[]
        if retry_health['pending']:
            blockers.append(f"{retry_health['pending']} messages are waiting for scanner recovery; {retry_health['needs_attention']} have failed at least three attempts and need operator attention. Automatic retries continue.")
        if not settings.evaluation_mode and not accounts['oauth_configured']:
            blockers.append('Create a Google Cloud OAuth web client, enable Gmail API, configure the client file and matching callback URL, and authorize each mailbox.')
        if not settings.evaluation_mode and not any(a['connected'] for a in accounts['accounts']):
            blockers.append('No mailboxes are connected; no Gmail scanning or quarantine is running.')
        readonly = sum(a['connected'] and not a['can_modify'] for a in accounts['accounts'])
        if readonly and (settings.enforcement_mode != 'passive' or settings.notifications_enabled):
            blockers.append(f'{readonly} connected mailbox(es) permit monitoring only. Reconnect those accounts with Manage protection access before Gmail labels, quarantine, release, or notifications can work for them.')
        if settings.web_risk_api_key and reputation_health['status'] == 'unavailable':
            blockers.append('Google Web Risk lookups are failing: ' + str(reputation_health.get('reason') or 'check provider configuration') + ' Check billing, API restrictions, and connectivity.')
        if not inspection['reachable']:
            blockers.append('The attachment inspection service is not reachable; malware/document/QR coverage is unavailable.')
        elif inspection.get('antivirus',{}).get('status') != 'ready':
            blockers.append('Antivirus is starting, unavailable, or has stale signatures; messages wait for automatic scan retries.')
        if not model['configured']:
            blockers.append('Choose and test a decision provider in the setup walkthrough.')
        if model['analysis_paused']:
            blockers.append('Analysis is paused. Accept the current email-sharing disclosure, then save the selected provider and masking setting in Setup; queued mail is preserved.')
        return {'mode':settings.enforcement_mode,'notifications_enabled':settings.notifications_enabled,
                'thresholds':{'quarantine_phishing':settings.quarantine_threshold,'corroboration':settings.corroboration_threshold,'sensitive_fraud':.95,'protective_action':.98},
                'services':{'jev':model, 'decision':model,
                            'inspection':inspection,'url_reputation':{'configured':bool(settings.web_risk_api_key),'monthly_limit':settings.url_lookup_monthly_limit, **reputation_health},
                            'google_oauth':{'configured':accounts['oauth_configured'],'redirect_uri':settings.google_oauth_redirect_uri}},
                'accounts':accounts['accounts'],'cache':pipeline.cache.status(),'blockers':blockers,
                'limitations':['Gmail quarantine removes Inbox and adds a label; the email remains accessible in All Mail.',
                               'Mail is inspected after delivery. There is no browser sandbox, click-time link rewriting, or pre-delivery blocking.',
                               'No-match reputation and antivirus results do not prove an email is safe.']}

    @app.patch('/api/protection')
    def protection_update(body: ProtectionControls):
        changes=body.model_dump(exclude_none=True)
        if not changes:
            raise HTTPException(400,'Provide a mode or notification setting')
        update_controls(settings,pipeline.store,changes)
        return protection_status()

    @app.get('/api/actions')
    def action_list(message_id: str | None = Query(None,max_length=32),limit:int=Query(100,ge=1,le=500)):
        return {'actions':list_actions(pipeline.store,message_id=message_id,limit=limit)}

    @app.post('/api/messages/{mid}/release',status_code=202)
    def release(mid: str):
        msg=pipeline.store.get_message(mid)
        if not msg or msg['provider']!='gmail':
            raise HTTPException(404,'Connected Gmail message not found')
        try:
            require_manual_access(settings, pipeline.store, msg)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        applied=next((a for a in list_actions(pipeline.store,message_id=mid,limit=500)
                      if a['action']=='quarantine' and (a['status']=='applied' or a.get('attempts',0)>0)),None)
        if not applied:
            raise HTTPException(409,'No applied or attempted quarantine to reconcile and release')
        aid=enqueue_action(pipeline.store,msg['mailbox'],msg['provider_message_id'],'release',applied['analysis_run_id'],message_id=mid)
        return {'action_id':aid,'status':'queued'}

    @app.post('/api/messages/{mid}/gmail-label', status_code=202)
    def manual_label(mid: str, body: ManualLabel):
        try:
            return enqueue_manual_action(settings, pipeline.store, mid, body.verdict,
                                         body.move_to_label, body.idempotency_key)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post('/api/actions/{aid}/undo', status_code=202)
    def manual_undo(aid: str):
        try:
            return enqueue_manual_undo(settings, pipeline.store, aid)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post('/api/notifications/{nid}/reconcile')
    def notification_reconcile(nid:str):
        try:
            return reconcile_notification(settings,pipeline.store,nid)
        except (ValueError,KeyError):
            raise HTTPException(404,'Notification not found') from None

    @app.post('/api/notifications/{nid}/abandon')
    def notification_abandon(nid: str):
        try:
            return abandon_notification(pipeline.store, nid)
        except (ValueError, KeyError):
            raise HTTPException(409, 'Notification cannot be resumed from this state') from None

    if not settings.evaluation_mode:
        register_account_routes(app,settings,pipeline.store)
        from .model_setup import register_model_setup_routes
        register_model_setup_routes(app, settings, pipeline.store)
    else:
        @app.get('/api/accounts')
        def evaluation_accounts():
            return {'accounts':[], 'oauth_configured':False, 'setup_blockers':[], 'evaluation':True}

    @app.get("/api/messages")
    def message_list(q: str = Query("", max_length=300), verdict: str = "",
                     limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0)):
        return pipeline.store.list_messages(q, verdict, limit, offset)

    @app.get("/api/messages/{mid}")
    def detail(mid: str):
        result = pipeline.store.detail(mid)
        if not result:
            raise HTTPException(404, "Message not found")
        result['actions']=list_actions(pipeline.store,message_id=mid,limit=100)
        return result

    @app.post("/api/import", status_code=202)
    async def import_email(file: UploadFile = File(...), mailbox: str = Form("")):
        raw = await file.read(settings.max_message_bytes + 1)
        await file.close()
        try:
            return pipeline.ingest(raw, mailbox=mailbox[:320], provider="eml")
        except RecursionError:
            raise HTTPException(400, "Email MIME nesting exceeds parsing limits") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.post("/api/messages/{mid}/replay", status_code=202)
    def replay(mid: str):
        try:
            return {"job_id": pipeline.store.enqueue(mid)}
        except KeyError:
            raise HTTPException(404, "Message not found") from None

    @app.post("/api/messages/{mid}/feedback", status_code=201)
    def review(mid: str, body: Review):
        try:
            item=pipeline.store.add_feedback(mid, body.verdict, body.reason, body.reviewer, body.run_id,
                                             apply_verdict=body.apply_verdict)
            pipeline.cache.invalidate()
            return {**item, 'applied_to_console': body.apply_verdict}
        except KeyError:
            raise HTTPException(404, "Message not found") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.get("/api/evaluation")
    def evaluation():
        return pipeline.store.evaluation()

    @app.get("/api/overview")
    def overview():
        return pipeline.store.overview()

    @app.post("/api/demo", status_code=202)
    def demo():
        from .demo import samples
        return {"messages": [pipeline.ingest(raw, mailbox="analyst@example.org", provider="demo")
                             for _, raw in samples()]}

    static = Path(__file__).with_name("static")
    static.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    return app
