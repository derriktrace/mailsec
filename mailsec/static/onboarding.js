"use strict";

// No secrets in URL parameters or browser storage. Credentials are submitted to
// authenticated same-origin setup routes; API responses contain only status.
window.mailsecSetup = (() => {
  const titles = ["Welcome", "Decision model", "Connect Gmail", "Protection", "Ready to monitor"];
  const setup = {step: 0, model: null, google: null, loading: false, initialized: false};
  const field = (title, input, note) => {
    const wrapper = el("label", "setup-field", title); wrapper.append(input);
    if (note) wrapper.append(el("small", "", note));
    return wrapper;
  };
  const input = (id, value = "", type = "text") => {
    const node = el("input", ""); node.id = id; node.type = type; node.value = value;
    node.autocomplete = "off"; return node;
  };
  const button = (title, action, primary = false) => {
    const node = el("button", `button${primary ? " primary" : ""}`, title);
    node.type = "button"; node.addEventListener("click", action); return node;
  };
  const link = (title, url) => {
    const node = el("a", "setup-link", title); node.href = url;
    node.target = "_blank"; node.rel = "noopener noreferrer"; return node;
  };
  async function load() {
    const [model, google] = await Promise.all([api("/api/setup/model"), api("/api/setup/google")]);
    setup.model = model; setup.google = google;
  }
  async function open(step = 0) {
    showView("setup"); setup.step = step;
    $("#setup-view").replaceChildren(el("p", "loading-label", "Loading your setup…"));
    try { await load(); render(); }
    catch(error) { $("#setup-view").replaceChildren(el("p", "error-text", error.message), button("Try again", () => open(step))); }
  }
  function go(step) {
    setup.step = step; sessionStorage.setItem("mailsec-setup-step", String(step)); render();
    $("#setup-view").scrollIntoView({block:"start", behavior:"smooth"});
  }
  function render() {
    const root = $("#setup-view"); root.replaceChildren();
    const layout = el("div", "setup-layout");
    const rail = el("nav", "setup-rail"); rail.setAttribute("aria-label", "Setup steps");
    append(rail, el("div", "eyebrow", "MAKE IT YOURS"), el("h2", "", "A little setup.\nA clearer inbox."));
    titles.forEach((title, index) => {
      const step = button(`${index + 1}  ${title}`, () => go(index));
      step.className = `setup-step${index === setup.step ? " current" : ""}`;
      if (index === setup.step) step.setAttribute("aria-current", "step"); rail.append(step);
    });
    rail.append(el("p", "", "Gmail and Google Workspace. Keep your address and the email apps you already use."));
    const content = el("section", "setup-content");
    append(content, el("div", "eyebrow", `STEP ${setup.step + 1} OF ${titles.length}`), el("h2", "", titles[setup.step]));
    [welcome, modelStep, googleStep, protectionStep, readyStep][setup.step](content);
    append(layout, rail, content); root.append(layout);
  }
  function welcome(content) {
    content.append(el("p", "setup-lead", "Personal email security, with the evidence behind every decision."));
    const cards = el("div", "setup-benefits");
    for (const [title, description] of [
      ["Choose where analysis happens", "Use hosted Jev or your own Ollama / compatible model server. We make the data flow clear before you connect."],
      ["Keep control of your mail", "Start with read-only monitoring. Labels and reversible quarantine require your separate choice."],
      ["See what needs attention", "Review messages, inspect evidence, and check the health of your scanner and mailbox connections."],
    ]) append(cards, append(el("article", ""), el("h3", "", title), el("p", "", description)));
    append(content, cards, el("p", "control-caveat", "This release has one console owner. Connect only mailboxes whose owners have consented. Everyone with this console token can see imported mail. Separate family helper permissions are not included."), button("Set up my model →", () => go(1), true));
  }
  function modelStep(content) {
    content.append(el("p", "setup-lead", "Choose where email evidence is analyzed, then explicitly approve that destination."));
    const form = el("form", "setup-form");
    const provider = el("select", ""); provider.id = "setup-provider";
    for (const [value, title] of [["jev","Jev · TypeSafe hosted decision model"],["ollama","Ollama · configured model server"],["openai_compatible","OpenAI-compatible · local or hosted server"]]) provider.append(new Option(title,value));
    provider.value = setup.model.provider;
    const model = input("setup-model", setup.model.model);
    const base = input("setup-endpoint", setup.model.base_url);
    base.placeholder = "http://host.docker.internal:11434";
    const key = input("setup-key", "", "password"); key.placeholder = setup.model.key_configured ? "Stored securely · leave blank to keep" : "API key, if required";
    const timeout = input("setup-timeout", setup.model.timeout_seconds || 120, "number"); timeout.min = "10"; timeout.max = "300";
    const masking = input("setup-recipient-masking", "", "checkbox"); masking.checked = setup.model.recipient_address_masking === true;
    const maskingField = field("Mask recipient email addresses before model analysis", masking, "Replaces known To/Cc/Bcc addresses and the connected mailbox address where those known addresses occur in model input. Can reduce accuracy. This does not anonymize email: names, signatures and other identifying details may remain. Email content still goes to the selected provider. This choice takes effect only when you save and allow analysis.");
    const maskingState = el("small", ""); maskingState.id = "setup-recipient-masking-state"; maskingField.append(maskingState);
    function updateMaskingState() {
      const saved = setup.model.recipient_address_masking === true;
      maskingState.textContent = `Saved setting for the configured provider: ${saved ? "On" : "Off"}.${masking.checked !== saved ? ` Unsaved choice: ${masking.checked ? "On" : "Off"}. Current email analysis continues to use the saved setting until you save.` : ""}`;
    }
    masking.addEventListener("change", updateMaskingState); updateMaskingState();
    const baseField = field("Server base URL", base, "From a container, localhost is the container itself. Docker: host.docker.internal. Podman: host.containers.internal. A remote model server receives your email evidence; Ollama and compatible protocols do not by themselves mean local hosting.");
    const description = el("p", "control-caveat");
    const providerGuide = link("", ""); providerGuide.id = "setup-provider-guide";
    const privacyArea = el("div", "setup-sharing-area"); privacyArea.id = "setup-sharing-disclosure";
    const ack = input("setup-sharing-ack", "", "checkbox"); ack.checked = false; ack.required = true;
    const ackText = el("span", "");
    const ackLabel = append(el("label", "sharing-ack"), ack, ackText); ackLabel.hidden = true;
    const consentResult = el("p", "setup-result"); consentResult.id = "setup-sharing-result"; consentResult.setAttribute("role", "status");
    const receipt = el("p", "control-note"); receipt.id = "setup-sharing-receipt";
    const acceptanceNote = el("p", "sharing-resume-note"); acceptanceNote.id = "setup-sharing-resume-note";
    const result = el("p", "setup-result"); result.setAttribute("role", "status"); result.id = "setup-model-result";
    let privacy = null, privacyEpoch = 0, previewTimer, busy = false;
    const accept = button("Accept this evidence destination", acceptSharing, true); accept.id = "setup-sharing-accept";
    const revoke = button("Stop future sharing with this provider", revokeSharing); revoke.id = "setup-sharing-revoke"; revoke.hidden = true;
    const testButton = button("Test connection", () => submit(false)); testButton.id = "setup-model-test";
    const saveButton = button("Test, save & allow email analysis →", () => submit(true), true); saveButton.id = "setup-model-save";
    const payload = () => ({provider:provider.value,model:model.value,base_url:base.value,
      api_key:key.value || null,timeout_seconds:Number(timeout.value),recipient_address_masking:masking.checked});
    const destinationPayload = () => ({provider:provider.value,base_url:provider.value === "jev" ? "" : base.value});
    function updateActions() {
      const approved = privacy?.accepted === true && ack.checked;
      testButton.disabled = busy || !approved || !privacy?.writable;
      saveButton.disabled = busy || !approved || !privacy?.writable || !setup.model.setup_writable;
      accept.disabled = busy || !privacy || !ack.checked || privacy.accepted || !privacy.writable;
      const current = privacy?.destination_sha256 && privacy.destination_sha256 === setup.model.privacy?.destination_sha256;
      revoke.hidden = !(current && privacy?.accepted);
      revoke.disabled = busy || !privacy?.writable;
      ack.disabled = busy || !privacy || !privacy.writable;
    }
    function setBusy(value) {
      busy = value;
      for (const control of form.querySelectorAll("input,select,button")) control.disabled = value;
      updateActions();
    }
    function renderPrivacy() {
      privacyArea.replaceChildren(providerSharingDisclosure(privacy, "setup-disclosure"));
      ackText.textContent = privacy.acknowledgment;
      ackLabel.hidden = false;
      accept.textContent = privacy.provider === "jev" ? "Accept the Jev email-sharing disclosure" : "Accept this email-sharing disclosure";
      receipt.textContent = privacy.accepted ? `This disclosure was explicitly accepted${privacy.accepted_at ? " on " + formatDate(privacy.accepted_at) : ""}. ${privacy.analysis_allowed ? "The saved configuration allows email analysis." : "Disclosure acceptance alone does not enable email analysis."} The checkbox below starts unchecked each time this step opens.` : "This disclosure has not been approved. Reading it or checking the box does not enable sharing.";
      acceptanceNote.textContent = "Accepting this disclosure does not send email evidence or resume pending analysis. Test connection sends a synthetic note only. Test, save & allow email analysis commits the selected provider and recipient-masking setting together, then allows selected pending historical and future mail to be analyzed automatically.";
      updateActions();
    }
    async function previewDestination() {
      const epoch = ++privacyEpoch;
      privacy = null; ack.checked = false; ackLabel.hidden = true; accept.disabled = true; revoke.hidden = true; receipt.textContent = ""; acceptanceNote.textContent = ""; consentResult.textContent = "";
      privacyArea.replaceChildren(el("p", "control-note", "Loading the exact evidence destination and sharing disclosure…")); updateActions();
      try {
        const response = await api("/api/setup/privacy/preview", {method:"POST",body:JSON.stringify(destinationPayload())});
        if (epoch !== privacyEpoch || !document.contains(form)) return;
        privacy = response; renderPrivacy();
      } catch(error) {
        if (epoch !== privacyEpoch || !document.contains(form)) return;
        privacyArea.replaceChildren(el("p", "error-text", `Sharing disclosure could not be loaded: ${error.message}`)); updateActions();
      }
    }
    function update(changed = false) {
      const hostedJev = provider.value === "jev"; baseField.hidden = hostedJev;
      if (changed) {
        key.value = "";
        model.value = hostedJev ? "jev-1.13.0" : "";
        base.value = provider.value === "ollama" ? "http://host.docker.internal:11434" : provider.value === "openai_compatible" ? "http://host.docker.internal:1234/v1" : "";
      }
      model.placeholder = hostedJev ? "jev-1.13.0" : "Exact name of an installed model";
      description.textContent = hostedJev ? "Jev is a hosted TypeSafe service. Selected past and future email evidence leaves your Mailsec server and is not anonymized by default. Your Jev key incurs usage charges. Read and explicitly accept the full disclosure below before enabling analysis." : "Selected email content and identifiers go to the exact model endpoint below. Evidence stays local only if you actually host that endpoint locally; remote compatible services are third parties too. The endpoint operator controls its own logging and forwarding. Custom model scores are uncalibrated estimates; model-only automatic quarantine stays disabled.";
      const guides = {jev:["Jev quickstart ↗","https://docs.typesafe.ai/introduction/quickstart"],ollama:["Ollama structured-output guide ↗","https://docs.ollama.com/capabilities/structured-outputs"],openai_compatible:["Compatible structured-output example · vLLM ↗","https://docs.vllm.ai/en/latest/features/structured_outputs/"]};
      [providerGuide.textContent,providerGuide.href] = guides[provider.value];
      clearTimeout(previewTimer); previewDestination();
    }
    provider.addEventListener("change", () => update(true));
    base.addEventListener("input", () => {
      ++privacyEpoch; privacy = null; ack.checked = false; ackLabel.hidden = true; revoke.hidden = true; updateActions();
      privacyArea.replaceChildren(el("p", "control-note", "The destination changed. Its disclosure must be reviewed and accepted."));
      clearTimeout(previewTimer); previewTimer = setTimeout(previewDestination,350);
    });
    ack.addEventListener("change", updateActions);
    async function acceptSharing() {
      if (!privacy || !ack.checked || busy || privacy.accepted) return;
      setBusy(true); consentResult.className = "setup-result"; consentResult.textContent = "Recording your explicit sharing approval…";
      let confirmed = false;
      try {
        privacy = await api("/api/setup/privacy/accept", {method:"POST",body:JSON.stringify({...destinationPayload(),disclosure_version:privacy.disclosure_version,disclosure_sha256:privacy.disclosure_sha256,accepted:true})});
        confirmed = true;
        setup.model = await api("/api/setup/model");
        consentResult.className = "setup-result success-text"; consentResult.textContent = "Disclosure accepted. Email analysis has not been enabled by this acknowledgment. Test, save & allow email analysis applies your provider and masking choices together.";
        renderPrivacy(); await refresh({force:true});
      } catch(error) { consentResult.className = "setup-result error-text"; consentResult.textContent = confirmed ? "Disclosure approval was recorded, but current status could not be refreshed. Acknowledgment alone does not enable analysis. Reopen this step to check status before another change." : error.status ? error.message : "Disclosure approval could not be confirmed. Reopen this step to check its status before retrying. Acknowledgment alone does not enable analysis."; privacy = null; }
      finally {setBusy(false);}
    }
    async function revokeSharing() {
      if (!privacy?.accepted || busy) return;
      if (!await confirmAction("Stop future email sharing with this provider?", "New model requests will pause. Requests already sent cannot be recalled. Imported mail, prior results and Gmail permissions are retained. You must explicitly accept again before new analysis resumes.", "Stop future sharing")) return;
      setBusy(true); consentResult.textContent = "Stopping future model requests…";
      let confirmed = false;
      try {
        await api("/api/setup/privacy/revoke", {method:"POST",body:JSON.stringify({destination_sha256:privacy.destination_sha256})});
        confirmed = true;
        setup.model = await api("/api/setup/model"); ack.checked = false;
        await previewDestination(); await refresh({force:true});
        consentResult.className = "setup-result success-text"; consentResult.textContent = "Future model requests are paused. Previously sent requests cannot be recalled.";
      } catch(error) {consentResult.className = "setup-result error-text";consentResult.textContent = confirmed ? "The stop-sharing request was recorded, but current status could not be refreshed. Reopen this step to check status. Previously sent requests cannot be recalled." : error.status ? error.message : "The stop-sharing outcome could not be confirmed. Reopen this step to check the current status.";privacy = null;}
      finally {setBusy(false);}
    }
    async function submit(save) {
      if (!privacy?.accepted || !ack.checked || busy) { result.className = "setup-result error-text"; result.textContent = "Review and explicitly accept this evidence destination before testing or saving."; return; }
      setBusy(true); result.textContent = "Checking the connection with a synthetic note. No mailbox content is used…";
      try {
        const response = await api(save ? "/api/setup/model" : "/api/setup/model/test", {method:"POST",body:JSON.stringify(payload())});
        if (save) key.value = ""; result.textContent = response.note; result.className = "setup-result success-text";
        if (save) {setup.model = response; await refresh({force:true}); go(2);}
      } catch(error) {result.textContent = error.message;result.className = "setup-result error-text";}
      finally {setBusy(false);}
    }
    append(form,field("Decision provider",provider),field("Model name",model),baseField,field("API key",key,"Encrypted on the server; never returned to the browser."),field("Request timeout (seconds)",timeout),maskingField,description,privacyArea,receipt,ackLabel,acceptanceNote,append(el("div","setup-actions"),accept,revoke),consentResult,result,append(el("div","setup-actions"),testButton,saveButton));
    form.addEventListener("submit",event=>{event.preventDefault();submit(true);});
    append(content,form,providerGuide); update();
    if (!setup.model.setup_writable) content.append(el("p","error-text","The server needs its console token and token-encryption key before credentials can be saved. The self-host bootstrap generates these automatically."));
  }
  function googleStep(content) {
    append(content, el("p", "setup-lead", "Connect a free Gmail account or a Google Workspace mailbox."), el("p", "", "Each owner signs in with Google and approves access. We never ask for the account’s main password."));
    const guide = el("details", "setup-guide"); guide.open = !setup.google.configured;
    guide.append(el("summary", "", "Create your Google OAuth application"));
    const steps = el("ol", "setup-steps");
    for (const step of [
      "Create a Google Cloud project named Mailsec Personal Security and enable the Gmail API. A paid Google Workspace subscription is not required.",
      "In Google Auth Platform, set the app name to Mailsec Personal Security and Audience to External for personal Gmail. Add your authorized addresses as test users while testing.",
      "In Data Access, add the Gmail scopes you plan to use: gmail.readonly for Monitor; gmail.modify for Manage, which also permits sending notifications. Each mailbox owner approves the selected access during consent.",
      "Create an OAuth client with application type Web application and name Mailsec Self-Hosted. Register the exact redirect URI below. Download its JSON file.",
      "Upload that JSON file here, select your import range, and save your mailbox addresses. Then connect each account using the buttons below.",
    ]) steps.append(el("li", "", step));
    append(guide, steps, link("Open Google Cloud Console ↗", "https://console.cloud.google.com/auth/overview"), el("p", "control-caveat", "Google’s external Testing status normally gives Gmail refresh tokens a seven-day lifetime. Use the appropriate production authorization/verification path for ongoing monitoring. Workspace administrators may also need to approve the app."));
    content.append(guide);
    const form = el("form", "setup-form");
    const redirect = input("setup-redirect", setup.google.redirect_uri || location.origin + "/oauth/google/callback");
    const mailboxes = el("textarea", ""); mailboxes.id = "setup-mailboxes"; mailboxes.rows = 3;
    mailboxes.value = (setup.google.authorized_mailboxes || []).join("\n"); mailboxes.placeholder = "you@gmail.com\nfamily-member@gmail.com";
    const file = input("setup-google-file", "", "file"); file.accept = ".json,application/json";
    const history = el("select", ""); history.id = "setup-history";
    for (const [value,title] of [["new","New mail only"],["30_days","Last 30 days"],["all","All available incoming history"]]) history.append(new Option(title,value));
    history.value = ["new", "30_days", "all"].includes(setup.google.initial_history) ? setup.google.initial_history : "30_days";
    const result = el("p", "setup-result"); result.setAttribute("role", "status");
    const save = button("Save Google setup", async () => {
      save.disabled = true; result.textContent = "Validating Google configuration…";
      try {
        if (!file.files?.[0]) throw new Error("Choose the Google Web application OAuth JSON file to save setup changes.");
        if (file.files[0].size > 32768) throw new Error("OAuth client file is too large.");
        const client_config = JSON.parse(await file.files[0].text());
        const response = await api("/api/setup/google", {method:"POST",body:JSON.stringify({client_config,
          mailboxes:mailboxes.value.split(/[\s,;]+/).filter(Boolean),redirect_uri:redirect.value,initial_history:history.value})});
        file.value = ""; setup.google = response; result.textContent = "Configuration saved securely. Now authorize each mailbox below.";
        await refresh({force:true}); render();
      } catch(error) { result.textContent = error instanceof SyntaxError ? "Choose a valid Google OAuth JSON file." : error.message; }
      finally { save.disabled = false; }
    }, true);
    append(form, field("Exact Google redirect URI", redirect, "Use the browser’s exact console origin plus /oauth/google/callback. For the default SSH tunnel: http://localhost:8025/oauth/google/callback. Direct remote access requires HTTPS. An existing registered loopback port can be reused with a matching tunnel."),
      field("OAuth client JSON", file, setup.google.configured ? "A client is already configured. Re-upload only when changing setup." : "Downloaded from Google. It is encrypted when saved."),
      field("Authorized mailbox addresses", mailboxes, "One per line. An address only authorizes setup; its owner must still approve Google consent."),
      field("Initial import", history, "Applies to new or restarted imports. Completed checkpoints are preserved. A large history costs more and takes longer to analyze."), result, save);
    if (setup.google.initial_history === "configured" && setup.google.initial_query) {
      const notice = el("p", "control-caveat"); notice.id = "setup-history-existing";
      append(notice, "An import query is already configured: ", el("code", "", setup.google.initial_query), ". It remains unchanged until you save. Saving replaces that query with the selected range for new or restarted imports; completed checkpoints remain intact.");
      form.insertBefore(notice, result);
    }
    form.addEventListener("submit", event => event.preventDefault()); content.append(form);
    const connections = accountControls(); connections.querySelector(".button")?.remove(); content.append(connections);
    content.append(button("Continue to protection →", () => go(3), true));
  }
  function protectionStep(content) {
    content.append(el("p", "setup-lead", "Choose what happens when a message needs attention."));
    const mode = el("select", ""); mode.id = "setup-protection-mode";
    for (const [value,title] of [["passive","Monitor · analyze in the dashboard"],["flag_only","Flag · apply Mailsec/Review in Gmail"],["auto_quarantine","Quarantine high-risk messages automatically"]]) mode.append(new Option(title,value));
    mode.value = currentMode() === "unknown" ? "passive" : currentMode();
    const notifications = input("setup-notifications", "", "checkbox"); notifications.checked = Boolean(state.protection?.notifications_enabled);
    append(content, field("Protection mode", mode), field("Email the affected mailbox after quarantine", notifications),
      el("p", "control-caveat", "Monitor is the recommended starting point. Flagging and quarantine need a Manage authorization. Quarantine removes Inbox and applies a label; the message remains accessible in All Mail. Imported history is analyzed using the same policy."));
    if (setup.model.provider !== "jev") content.append(el("p", "control-caveat", "Your configured model can recommend review. Its estimated scores never authorize automatic quarantine. Confirmed malware signatures can still qualify under your selected policy."));
    const result = el("p", "setup-result"); result.setAttribute("role", "status");
    append(content, result, button("Save protection & finish →", async event => {
      const button = event.currentTarget; button.disabled = true;
      try { await api("/api/protection",{method:"PATCH",body:JSON.stringify({mode:mode.value,notifications_enabled:notifications.checked})}); await refresh({force:true}); go(4); }
      catch(error) {result.textContent = error.message;button.disabled = false;}
    }, true));
  }
  function readyStep(content) {
    const connected = accountRows().filter(account => account.connected && !account.last_error);
    const inspection = state.protection?.services?.inspection;
    const ready = setup.model.configured && !setup.model.analysis_paused && connected.length && inspection?.reachable && inspection?.antivirus?.status === "ready";
    content.append(el("p", "setup-lead", ready ? "Your connections are ready. Watch the first analyses arrive." : "Your setup is saved. A few checks still need attention."));
    const checks = el("div", "setup-checks");
    for (const [name, ok, description] of [
      ["Decision model", setup.model.configured && !setup.model.analysis_paused, setup.model.analysis_paused ? "Email sharing paused · review and explicitly accept the provider disclosure" : setup.model.model || "Choose and test a model"],
      ["Gmail connections", connected.length > 0, `${connected.length} account(s) connected`],
      ["Attachment inspection", inspection?.reachable && inspection?.antivirus?.status === "ready", inspection?.antivirus?.status === "ready" ? "Scanner ready" : "Waiting for scanner and current signatures"],
    ]) append(checks, append(el("div", "setup-check"), el("span", ok ? "success-text" : "error-text", ok ? "✓" : "!"), append(el("div", ""), el("strong", "", name), el("small", "", description))));
    append(content, checks, el("p", "control-note", "URL reputation is optional and excluded from this release setup. Unknown URL reputation remains visible in the evidence. This tool checks messages after delivery and cannot guarantee it will act before a message is opened."),
      button("Open my dashboard →", () => {sessionStorage.removeItem("mailsec-setup-step"); showView("overview"); refresh({force:true});}, true), button("Refresh checks", async () => {await refresh({force:true});await load();render();}));
  }
  $("#nav-setup").addEventListener("click", () => open());
  document.addEventListener("mailsec:refreshed", () => {
    if (isEvaluation || setup.initialized) return;
    setup.initialized = true;
    let saved = null;
    try { saved = sessionStorage.getItem("mailsec-setup-step"); } catch (_) { /* Optional resume only. */ }
    if (saved !== null && /^[0-4]$/.test(saved)) open(Number(saved));
    else if (state.status?.decision && !state.status.decision.configured) open();
  });
  return {open};
})();
