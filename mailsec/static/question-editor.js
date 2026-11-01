"use strict";

// Authenticated, same-origin controls only. Question text and model output are
// displayed as text/form values, never HTML. Drafts and test input are not put
// in local storage, URL parameters, or the mailbox action queue.
window.mailsecQuestions = (() => {
  const groups = [
    ["primary", "Assessment", "The overall verdict and supporting judgments."],
    ["actions", "Requested actions", "Identify what the sender is asking the recipient to do."],
    ["authority", "Authority", "Assess the claimed identity and authority behind that request."],
  ];
  const qs = {data: null, revision: null, bundles: null, dirty: false, loading: false, busy: "", needsRefresh: false, group: "primary", note: "", testMode: "text", text: "", message: "", messageQuery: "", messages: [], tests: [], result: null, error: "", notice: "", leaving: false, poll: null, loadEpoch: 0};
  const copy = value => JSON.parse(JSON.stringify(value));
  const root = () => $("#questions-view");
  const button = (title, action, primary = false, disabled = false) => {
    const node = el("button", `button${primary ? " primary" : ""}`, title);
    node.type = "button"; node.disabled = disabled; node.addEventListener("click", action); return node;
  };
  const field = (title, input, note) => {
    const node = el("label", "question-field", title); node.append(input);
    if (note) node.append(el("small", "", note)); return node;
  };
  const tag = (title, kind = "") => el("span", `status-tag ${kind}`, title);
  const writable = () => qs.data?.writable === true;
  const inFlight = () => Boolean(qs.busy || qs.loading);
  const blocked = () => inFlight() || qs.needsRefresh;
  const statusOf = result => result?.status || "unknown";
  const pending = result => ["queued", "pending", "running", "processing"].includes(statusOf(result));
  const done = result => statusOf(result) === "complete";
  const activeId = () => qs.data?.active?.id;
  const shortHash = value => value ? String(value).slice(0, 12) : "Unavailable";
  const titleOf = revision => revision?.label || "Untitled version";
  function canActivate() {
    const result = qs.result;
    return writable() && !blocked() && qs.data.provider?.privacy?.analysis_allowed === true && !qs.dirty && qs.revision && qs.revision.id !== activeId() && done(result)
      && result.revision_id === qs.revision.id && result.active_revision_id === activeId()
      && result.candidate_sha256 === qs.revision.sha256 && result.provider_fingerprint === qs.data.provider?.fingerprint;
  }
  function selectRevision(revision) {
    qs.revision = copy(revision); qs.bundles = copy(revision.bundles); qs.note = ""; qs.dirty = false;
    qs.result = qs.tests.find(test => test.revision_id === revision.id && test.active_revision_id === activeId() && test.provider_fingerprint === qs.data.provider?.fingerprint && done(test)) || null;
    qs.error = ""; qs.notice = "";
  }
  async function fetchData() {
    const [data, tests] = await Promise.all([api("/api/questions"), api("/api/questions/tests?limit=20")]);
    qs.data = data; qs.tests = tests.tests || [];
    qs.needsRefresh = false;
  }
  async function open() {
    showView("questions");
    if (state.view !== "questions") return;
    if (qs.data) {
      qs.loading = true; render();
      try { await fetchData(); }
      catch (error) { qs.error = `Could not refresh the active questions and provider: ${error.message}`; }
      finally { qs.loading = false; render(); }
      return;
    }
    qs.loading = true; qs.error = ""; render();
    const epoch = ++qs.loadEpoch;
    try {
      await fetchData();
      if (epoch !== qs.loadEpoch) return;
      selectRevision(qs.data.active);
      const recent = qs.tests.find(test => pending(test));
      if (recent) {
        if (recent.revision_id !== qs.revision.id) selectRevision(await api(`/api/questions/revisions/${encodeURIComponent(recent.revision_id)}`));
        qs.result = recent; qs.busy = "Comparing questions"; watchTest(recent.id);
      }
    } catch (error) { qs.error = error.message; }
    finally { if (epoch === qs.loadEpoch) { qs.loading = false; render(); } }
  }
  async function discardThen(action) {
    if (blocked()) return;
    if (qs.dirty && !await confirmAction("Discard unsaved question edits?", "These edits have not been saved as a version. Saved versions and comparison history are kept.", "Discard edits")) return;
    action();
  }
  function markDirty() {
    qs.dirty = true; qs.result = null; qs.notice = ""; qs.error = ""; updateControls();
  }
  function updateControls() {
    const notice = $("#question-notice");
    if (notice) { notice.textContent = qs.error || qs.notice || qs.busy || ""; notice.hidden = !notice.textContent; notice.classList.toggle("error", Boolean(qs.error)); notice.setAttribute("role", qs.error ? "alert" : "status"); }
    const active = qs.revision?.id === activeId();
    const pill = $("#question-edit-status");
    if (pill) { pill.textContent = qs.dirty ? "Unsaved edits" : active ? "Active version" : "Saved version"; pill.classList.toggle("warning", qs.dirty); }
    const save = $("#question-save"); if (save) save.disabled = !writable() || blocked() || !qs.dirty;
    const discard = $("#question-discard"); if (discard) discard.disabled = !qs.dirty || blocked();
    const test = $("#question-compare"); if (test) test.disabled = !writable() || blocked() || qs.dirty || !qs.revision || qs.data.provider?.configured === false || qs.data.provider?.privacy?.analysis_allowed !== true || !(qs.testMode === "text" ? qs.text.trim() : qs.message);
    const activate = $("#question-activate"); if (activate) activate.disabled = !canActivate();
    const helper = $("#question-activation-help");
    if (helper) helper.textContent = active && !qs.dirty ? "This version is already active." : qs.dirty ? "Save edits as a draft before comparing." : canActivate() ? "Comparison complete. Review its results before activating." : "Complete a comparison against the current active version and provider before activating.";
  }
  function render() {
    const container = root(); container.replaceChildren();
    container.setAttribute("aria-busy", String(Boolean(qs.loading || qs.busy)));
    const heading = append(el("div", "question-heading"), append(el("div", ""), el("div", "eyebrow", "ADVANCED / DETECTION DESIGN"), el("h2", "", "Good questions. Clearer decisions."), el("p", "", "Edit a draft, compare it with the active questions, then choose when to activate it.")));
    if (qs.data) heading.append(button("Refresh versions", async () => {
      if (inFlight()) return;
      if (qs.dirty && !await confirmAction("Discard unsaved question edits?", "Saved versions and comparison history are kept. Refreshing reloads the active version.", "Discard and refresh")) return;
      qs.data = null; qs.dirty = false; await open();
    }, false, inFlight()));
    container.append(heading);
    const alert = el("div", `question-notice${qs.error ? " error" : ""}`, qs.error || qs.notice || qs.busy || "");
    alert.id = "question-notice"; alert.setAttribute("role", qs.error ? "alert" : "status"); alert.hidden = !alert.textContent; container.append(alert);
    if (!qs.data) {
      container.append(el("p", "control-note", qs.loading ? "Loading your detection questions…" : "Question settings could not be loaded."));
      if (!qs.loading) container.append(button("Try again", open)); return;
    }
    const summary = el("div", "question-summary");
    append(summary, append(el("div", ""), el("span", "question-overline", "ACTIVE FOR NEW ANALYSES"), el("strong", "", titleOf(qs.data.active)), el("span", "question-hash", `SHA-256 ${shortHash(qs.data.active.sha256)}`)), append(el("div", ""), el("span", "question-overline", "DECISION PROVIDER"), el("strong", "", `${label(qs.data.provider?.provider)} · ${qs.data.provider?.model || "Not configured"}`), el("span", "", "Changing questions does not change protection thresholds.")));
    container.append(summary);
    if (qs.needsRefresh) container.append(el("p", "control-caveat", "Current version status needs to be refreshed. Changes and comparisons are disabled until you use Refresh versions."));
    if (!writable()) container.append(el("p", "control-caveat", "Question settings are read-only on this installation. Existing questions and history remain available."));
    container.append(el("p", "control-caveat", "Saved drafts do not affect scanning. Activating a version applies to new analyses only; existing classifications and Gmail labels stay as recorded. A comparison is a spot check, not proof of detection accuracy. Custom model scores alone still cannot trigger automatic quarantine."));
    if (qs.revision) {
      const portable = el("div", "question-portable");
      append(portable, append(el("div", ""), el("strong", "", "Take your questions with you"), el("p", "control-note", "Copy or paste all three question groups as plain text. Credentials, email evidence, and version history are excluded.")), button("Copy questions", () => transferDialog(false), false, inFlight()), button("Paste questions", () => transferDialog(true), false, !writable() || blocked()));
      container.append(portable);
    }
    if (qs.revision) {
      const layout = el("div", "question-layout");
      const rail = el("nav", "question-rail"); rail.setAttribute("aria-label", "Question groups");
      for (const [key, title, description] of groups) {
        const choice = button(title, () => { qs.group = key; render(); });
        choice.className = `question-group${qs.group === key ? " current" : ""}`;
        choice.dataset.group = key; choice.setAttribute("aria-pressed", String(qs.group === key));
        choice.append(el("small", "", `${Object.keys(qs.bundles[key] || {}).length} questions · ${description}`)); rail.append(choice);
      }
      append(layout, rail, editor()); container.append(layout, comparison());
    }
    container.append(history()); updateControls();
  }
  function editor() {
    const area = el("section", "question-editor"); area.setAttribute("aria-label", "Question draft editor");
    const status = tag("", ""); status.id = "question-edit-status";
    append(area, append(el("div", "question-editor-heading"), append(el("div", ""), el("h3", "", titleOf(qs.revision)), el("p", "", `${formatDate(qs.revision.created_at)} · ${shortHash(qs.revision.sha256)}`)), status));
    area.append(el("p", "control-note", "Instructions and criterion descriptions are editable. Question IDs, answer types, and answer keys stay fixed so the protection policy continues to understand each answer."));
    const disabled = !writable() || blocked();
    for (const [id, question] of Object.entries(qs.bundles[qs.group] || {})) {
      const details = el("details", "question-item");
      const summary = el("summary", ""); append(summary, el("strong", "", label(id)), el("span", "", question.type === "noul" ? "Yes / no judgment" : "Choice judgment")); details.append(summary);
      const metadata = el("p", "question-schema"); append(metadata, el("code", "", id), document.createTextNode(` · ${question.type} · fixed keys: ${Object.keys(question.criteria).join(", ")}`)); details.append(metadata);
      const instructions = el("textarea", ""); instructions.value = question.instructions; instructions.rows = 5; instructions.maxLength = 8192; instructions.required = true; instructions.disabled = disabled;
      instructions.dataset.question = id; instructions.dataset.part = "instructions";
      instructions.addEventListener("input", () => { question.instructions = instructions.value; markDirty(); });
      details.append(field("Instructions", instructions, "Use only supplied evidence. Keep legitimate requests distinct from affirmative hostile evidence."));
      for (const [key, description] of Object.entries(question.criteria)) {
        const criterion = el("textarea", ""); criterion.value = description; criterion.rows = 3; criterion.maxLength = 8192; criterion.required = true; criterion.disabled = disabled;
        criterion.dataset.question = id; criterion.dataset.criterion = key;
        criterion.addEventListener("input", () => { question.criteria[key] = criterion.value; markDirty(); });
        details.append(field(`When the answer is “${label(key)}”`, criterion));
      }
      area.append(details);
    }
    const note = el("input", ""); note.type = "text"; note.value = qs.note; note.maxLength = 120; note.placeholder = "For example: clarify forwarded invoices"; note.disabled = disabled;
    note.id = "question-version-note"; note.addEventListener("input", () => { qs.note = note.value; });
    area.append(field("Version note", note, "Describe the reason for this change. Avoid personal data and secrets."));
    const save = button("Save draft", saveDraft, true); save.id = "question-save";
    const discard = button("Discard edits", () => discardThen(() => { selectRevision(qs.revision); render(); }), false, !qs.dirty || blocked()); discard.id = "question-discard";
    append(area, append(el("div", "setup-actions"), save, discard));
    return area;
  }
  async function saveDraft() {
    if (!writable() || blocked() || !qs.dirty) return;
    const fields = [...root().querySelectorAll("textarea[data-question]")];
    if (fields.some(input => !input.value.trim())) { qs.error = "Instructions and criterion descriptions cannot be blank."; render(); return; }
    qs.busy = "Saving your draft…"; qs.error = ""; render();
    let confirmed = false;
    try {
      const revision = await api("/api/questions/drafts", {method: "POST", body: JSON.stringify({bundles: qs.bundles, label: qs.note.trim() || "Custom detection questions", parent_revision_id: qs.revision.id})});
      confirmed = true; selectRevision(revision);
      await fetchData(); qs.notice = "Draft saved. Scanning still uses the active version. Compare this draft before activating it.";
    } catch (error) {
      if (confirmed) { qs.needsRefresh = true; qs.notice = "Draft saved. Current version status could not be refreshed. Use Refresh versions before making another change."; qs.error = ""; }
      else { qs.error = mutationError(error); }
    }
    finally { qs.busy = ""; render(); }
  }
  function comparison() {
    const area = el("section", "question-comparison"); area.setAttribute("aria-label", "Compare question versions");
    append(area, el("div", "eyebrow", "TRY BEFORE YOU ACTIVATE"), el("h3", "", "Compare with active"), el("p", "control-note", "The same evidence is assessed with the active and selected versions. The test does not change classifications, contact Gmail, follow links, or send notifications."));
    const provider = qs.data.provider?.provider;
    area.append(el("p", "control-caveat", provider === "jev" ? "This comparison sends the supplied evidence to hosted Jev and can make up to six billable model calls: three question groups for each version. Only submit mail you are authorized to analyze." : "This comparison sends the supplied evidence to your configured model endpoint. It can make up to six model calls and consumes that server’s resources; hosted compatible servers may charge. Only submit mail you are authorized to analyze."));
    if (qs.data.provider?.privacy) {
      const disclosure = el("details", "question-sharing-details"); disclosure.open = qs.data.provider.privacy.analysis_allowed !== true;
      append(disclosure, el("summary", "", provider === "jev" ? "Jev receives email content and identifiers · review the sharing disclosure" : "This endpoint receives email content and identifiers · review the sharing disclosure"), providerSharingDisclosure(qs.data.provider.privacy)); area.append(disclosure);
    }
    if (qs.data.provider?.privacy?.analysis_allowed !== true) {
      area.append(el("p", "error-text", "Question comparisons are paused until you explicitly accept this provider’s sharing disclosure, then save and allow analysis with your chosen masking setting."), button("Review and allow email sharing", () => window.mailsecSetup?.open(1)));
    }
    if (qs.data.provider?.data_flow) area.append(el("p", "control-note", qs.data.provider.data_flow));
    const controls = el("div", "question-test-inputs");
    const mode = el("select", ""); mode.id = "question-test-mode"; mode.setAttribute("aria-label", "Comparison evidence source");
    mode.append(new Option("Paste email text", "text"), new Option("Use an analyzed message", "message")); mode.value = qs.testMode; mode.disabled = blocked();
    mode.addEventListener("change", async () => { qs.testMode = mode.value; if (mode.value === "message") await loadMessages(); render(); }); controls.append(field("Evidence source", mode));
    if (qs.testMode === "text") {
      const text = el("textarea", ""); text.id = "question-test-text"; text.rows = 7; text.maxLength = 24000; text.value = qs.text; text.disabled = blocked(); text.placeholder = "Paste headers and message text. Do not include an expected answer or dataset label.";
      text.addEventListener("input", () => { qs.text = text.value; updateControls(); }); controls.append(field("Email text", text, "Up to 24,000 characters. Pasted text has no independent authentication or attachment scan; absent enrichment remains unknown."));
    } else {
      const search = el("input", ""); search.type = "search"; search.value = qs.messageQuery; search.id = "question-message-search"; search.placeholder = "Search sender or subject"; search.disabled = blocked();
      search.addEventListener("input", () => { qs.messageQuery = search.value; });
      controls.append(field("Find an analyzed message", search, "Search retained mail across your history. Up to 200 matching messages are shown."), button("Search messages", async () => { await loadMessages(); render(); }, false, blocked()));
      const select = el("select", ""); select.id = "question-test-message"; select.disabled = blocked(); select.append(new Option("Choose an analyzed message…", ""));
      for (const message of qs.messages) select.append(new Option(`${message.subject || "(No subject)"} · ${message.from_address || "Unknown sender"}`, message.id));
      select.value = qs.message; select.addEventListener("change", () => { qs.message = select.value; updateControls(); });
      controls.append(field("Analyzed message", select, "Uses retained evidence from its latest analysis. Original verdicts, analyst feedback, and expected answers are excluded from model input."));
      if (!qs.messages.length) controls.append(button("Load analyzed messages", async () => { await loadMessages(); render(); }, false, blocked()));
    }
    const compare = button("Compare with active", runComparison, true); compare.id = "question-compare";
    const activate = button("Activate tested version", activateRevision); activate.id = "question-activate";
    const helper = el("p", "control-note"); helper.id = "question-activation-help";
    append(area, controls, append(el("div", "setup-actions"), compare, activate), helper);
    if (qs.result) area.append(testResult(qs.result));
    return area;
  }
  async function loadMessages() {
    try {
      const query = new URLSearchParams({limit: "200", offset: "0"}); if (qs.messageQuery.trim()) query.set("q", qs.messageQuery.trim());
      const data = await api(`/api/messages?${query}`); qs.messages = (data.messages || []).filter(message => message.run_count > 0 || message.status === "complete");
      if (!qs.messages.some(message => message.id === qs.message)) qs.message = "";
    }
    catch (error) { qs.error = error.message; }
  }
  function transferDialog(pasteMode) {
    if (!qs.bundles || inFlight() || (pasteMode && (!writable() || blocked()))) return;
    const dialog = el("dialog", "modal question-transfer-modal"); dialog.id = "question-transfer-dialog";
    const title = el("h2", "", pasteMode ? "Paste detection questions" : "Copy detection questions"); title.id = "question-transfer-title"; dialog.setAttribute("aria-labelledby", title.id);
    append(dialog, el("div", "eyebrow", "PORTABLE PLAIN TEXT"), title, el("p", "control-note", pasteMode ? "Paste one JSON object containing primary, actions, and authority. Validation checks the fixed schema before loading an unsaved draft. Nothing is saved or activated by pasting." : "This text contains all three question groups, including unsaved edits. It does not contain credentials, message evidence, or version history. Copy it to another Mailsec installation with the same question schema."));
    const textarea = el("textarea", "question-transfer-text"); textarea.id = "question-transfer-text"; textarea.rows = 15; textarea.maxLength = 65536; textarea.readOnly = !pasteMode; textarea.spellcheck = false;
    textarea.value = pasteMode ? "" : JSON.stringify(qs.bundles, null, 2);
    dialog.append(field(pasteMode ? "Question JSON text" : "All question groups", textarea));
    const result = el("p", "setup-result"); result.id = "question-transfer-result"; result.setAttribute("role", "status"); dialog.append(result);
    let validating = false;
    const close = () => { if (validating) return; dialog.close(); dialog.remove(); };
    const cancel = button(pasteMode ? "Cancel" : "Done", close);
    const perform = button(pasteMode ? "Validate and load draft" : "Copy to clipboard", async () => {
      if (!pasteMode) {
        try {
          if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
          await navigator.clipboard.writeText(textarea.value); result.className = "setup-result success-text"; result.textContent = "Question text copied.";
        } catch (_) { textarea.focus(); textarea.select(); result.className = "setup-result"; result.textContent = "Text selected. Use your browser’s Copy command (Ctrl+C or ⌘C)."; }
        return;
      }
      result.className = "setup-result error-text";
      let bundles;
      try {
        if (!textarea.value.trim()) throw new Error("Paste the question JSON text first.");
        if (new TextEncoder().encode(textarea.value).length > 48 * 1024) throw new Error("Question text exceeds the 48 KiB limit. Paste only the three question groups.");
        try { bundles = JSON.parse(textarea.value); } catch (_) { throw new Error("This is not valid JSON. Copy the complete question text, including its opening and closing braces."); }
        validating = true; perform.disabled = true; cancel.disabled = true; textarea.disabled = true; result.textContent = "Validating the question schema…";
        const validated = await api("/api/questions/validate", {method: "POST", body: JSON.stringify({bundles})});
        if (qs.dirty && !await confirmAction("Replace unsaved question edits?", "The validated pasted questions will replace the edits in this browser. Saved versions, current active questions, and history stay unchanged.", "Load pasted draft")) { result.textContent = "Pasted questions were validated. Your existing edits are unchanged."; return; }
        qs.bundles = copy(validated.bundles); qs.note = "Imported question draft"; qs.dirty = true; qs.result = null; qs.group = "primary"; qs.error = "";
        qs.notice = "Questions validated and loaded as an unsaved draft. Save and compare the draft before activating it.";
        validating = false; close(); render();
      } catch (error) {
        result.className = "setup-result error-text";
        result.textContent = error.status === 422 ? "The pasted question schema is incompatible with this release. Use the complete primary, actions, and authority groups from Copy questions; keep the fixed IDs, types, and answer keys." : error.message;
      }
      finally { validating = false; perform.disabled = false; cancel.disabled = false; textarea.disabled = false; }
    }, true);
    append(dialog, append(el("div", "modal-footer confirm-footer"), cancel, perform));
    dialog.addEventListener("cancel", event => { event.preventDefault(); close(); });
    document.body.append(dialog); dialog.showModal(); textarea.focus(); if (!pasteMode) textarea.select();
  }
  async function runComparison() {
    if (blocked() || qs.dirty || !writable() || qs.data.provider?.privacy?.analysis_allowed !== true) return;
    const payload = {revision_id: qs.revision.id, expected_provider_fingerprint: qs.data.provider?.fingerprint};
    if (qs.testMode === "text") payload.text = qs.text;
    else payload.message_id = qs.message;
    if (!(payload.text?.trim() || payload.message_id)) return;
    qs.busy = "Starting comparison…"; qs.error = ""; qs.notice = ""; qs.result = null; render();
    try {
      const result = await api("/api/questions/test", {method: "POST", body: JSON.stringify(payload)});
      qs.result = result;
      if (pending(result)) { qs.busy = "Comparing questions… You can leave this page; the test continues on the server."; watchTest(result.id); }
      else { qs.busy = ""; await updateAfterTest(); }
    } catch (error) {
      qs.busy = ""; qs.error = error.message;
      // A stale provider fingerprint is rejected by the server before any model
      // call. Refresh metadata so the next click discloses the current target.
      try { await fetchData(); } catch (_) { /* Keep the original error. */ }
    }
    render();
  }
  async function updateAfterTest() {
    try { await fetchData(); }
    catch (error) { qs.needsRefresh = true; qs.error = `Comparison finished, but version status could not be refreshed: ${error.message} Use Refresh versions before activating.`; }
  }
  function watchTest(id) {
    clearTimeout(qs.poll);
    qs.poll = setTimeout(async () => {
      try {
        const result = await api(`/api/questions/tests/${encodeURIComponent(id)}`); qs.result = result;
        if (pending(result)) { watchTest(id); }
        else { qs.busy = ""; await updateAfterTest(); }
        if (state.view === "questions") render();
      } catch (error) {
        qs.busy = ""; qs.needsRefresh = true; qs.error = `Comparison status is unavailable: ${error.message} Use Refresh versions to check saved test history before retrying.`;
        if (state.view === "questions") render();
      }
    }, 1500);
  }
  function testResult(result) {
    const box = el("section", "question-test-result"); box.setAttribute("aria-label", "Comparison results");
    append(box, append(el("div", "question-editor-heading"), el("h4", "", "Comparison results"), tag(label(statusOf(result)), done(result) ? "confirmed" : "warning")));
    if (!done(result)) box.append(el("p", "control-note", pending(result) ? "The server is processing this comparison. Activation is unavailable until both versions finish successfully." : "This comparison did not finish successfully. Review the stage errors and retry; partial output cannot authorize activation."));
    if (result.error) box.append(el("p", "error-text", display(result.error)));
    if (result.results?.active || result.results?.candidate) box.append(judgmentComparison(result));
    const columns = el("div", "question-result-grid");
    for (const [key, name] of [["active", "Active questions"], ["candidate", "Selected questions"]]) {
      const output = result.results?.[key];
      const column = el("article", "question-result-card"); column.append(el("h4", "", name));
      if (!output) column.append(el("p", "control-note", "No completed output yet."));
      else {
        const verdict = output.primary?.output?.answers?.verdict || output.primary?.answers?.verdict || output.primary?.response?.answers?.verdict || output.answers?.verdict;
        if (verdict?.choice) append(column, badge(verdict.choice), el("p", "control-note", (result.provider?.provider || qs.data.provider?.provider) === "jev" ? `Jev confidence: ${percent(verdict.confidence)}` : `Estimated score: ${percent(verdict.confidence)} · Uncalibrated estimate`));
        const details = el("details", "audit-details"); append(details, el("summary", "", "Inspect all question-group outputs"), el("pre", "question-output", pretty(output))); column.append(details);
      }
      columns.append(column);
    }
    box.append(columns);
    if (result.note) box.append(el("p", "control-note", result.note));
    box.append(el("p", "question-schema", `Test ${result.id} · Active ${shortHash(result.active_revision_id)} · Selected ${shortHash(result.revision_id)}`));
    return box;
  }
  function judgmentComparison(result) {
    const wrapper = el("div", "question-judgments");
    append(wrapper, el("h4", "", "Question-by-question comparison"), el("p", "control-note", "These are model judgments, not verified answers. Changed marks a different choice or a score difference of at least 10 percentage points. The policy can still require review."));
    const answers = (side, group) => {
      const output = result.results?.[side];
      if (group === "primary") return output?.primary?.answers || {};
      return output?.action_review?.stages?.[group === "actions" ? "facts" : "authority"]?.response?.answers || {};
    };
    const hosted = (result.provider?.provider || qs.data.provider?.provider) === "jev";
    const answerText = (answer, type) => {
      if (!answer) return "Not completed";
      if (type === "noul") return numeric(answer.noul) === null ? "Not completed" : `Probability of yes: ${percent(answer.noul)}`;
      return answer.choice ? `${label(answer.choice)} · ${hosted ? "Jev confidence" : "Estimated score"}: ${percent(answer.confidence)}` : "Not completed";
    };
    for (const [group, title] of groups) {
      const scroll = el("div", "question-table-scroll"); scroll.tabIndex = 0; scroll.setAttribute("role", "region"); scroll.setAttribute("aria-label", `${title} judgment comparison`);
      const table = el("table", "question-judgment-table"); table.append(el("caption", "", title));
      const head = el("thead", ""); const headings = el("tr", "");
      for (const text of ["Question", "Active questions", "Selected questions"]) { const cell = el("th", "", text); cell.scope = "col"; headings.append(cell); }
      head.append(headings); table.append(head); const body = el("tbody", "");
      for (const [id, question] of Object.entries(qs.data.defaults?.bundles?.[group] || qs.bundles[group] || {})) {
        const active = answers("active", group)[id], candidate = answers("candidate", group)[id];
        const a = numeric(question.type === "noul" ? active?.noul : active?.confidence), b = numeric(question.type === "noul" ? candidate?.noul : candidate?.confidence);
        const changed = Boolean(active && candidate && ((question.type === "choice" && active.choice !== candidate.choice) || (a !== null && b !== null && Math.abs(a - b) >= .1)));
        const row = el("tr", changed ? "changed" : "");
        const name = el("th", "", label(id)); name.scope = "row"; if (changed) name.append(tag("Changed", "warning"));
        append(row, name, el("td", "", answerText(active, question.type)), el("td", "", answerText(candidate, question.type))); body.append(row);
      }
      table.append(body); scroll.append(table); wrapper.append(scroll);
    }
    return wrapper;
  }
  function mutationError(error) {
    if (error.status) return error.message;
    qs.needsRefresh = true;
    return "The outcome could not be confirmed. Use Refresh versions to check saved history before retrying; the server may have completed the change.";
  }
  async function activateRevision() {
    if (!canActivate()) return;
    if (!await confirmAction("Activate these detection questions?", `“${titleOf(qs.revision)}” will apply to future analyses using the configured provider. The comparison is a spot check, not an accuracy guarantee. Existing classifications and Gmail labels are unchanged.`, "Activate version")) return;
    qs.busy = "Activating questions…"; qs.error = ""; render();
    let confirmed = false;
    try {
      await api("/api/questions/activate", {method: "POST", body: JSON.stringify({revision_id: qs.revision.id, expected_active_id: activeId(), test_id: qs.result.id})});
      confirmed = true;
      await fetchData(); selectRevision(qs.data.active); qs.notice = "Version activated for new analyses. Earlier results and all version history are retained.";
    } catch (error) {
      if (confirmed) { qs.needsRefresh = true; qs.notice = "Version activated. Current status could not be refreshed. Use Refresh versions before making another change."; qs.error = ""; }
      else { qs.error = mutationError(error); }
      qs.result = null;
    }
    finally { qs.busy = ""; render(); }
  }
  function history() {
    const area = el("section", "question-history"); area.setAttribute("aria-label", "Question version history");
    const restore = button("Restore shipped defaults", restoreDefaults, false, !writable() || blocked()); restore.id = "question-restore";
    append(area, append(el("div", "question-editor-heading"), append(el("div", ""), el("div", "eyebrow", "EVERY CHANGE RETAINED"), el("h3", "", "Version history")), restore), el("p", "control-note", "View any saved version. To return to an older custom version, compare it against the current active questions, then activate it. Restoring shipped defaults creates a new active revision without deleting history."));
    const list = el("div", "question-history-list");
    for (const revision of qs.data.history || []) {
      const row = el("article", "question-history-row");
      const active = revision.id === activeId(), selected = revision.id === qs.revision?.id;
      append(row, append(el("div", ""), el("strong", "", titleOf(revision)), el("p", "", `${formatDate(revision.created_at)} · ${label(revision.source)} · ${shortHash(revision.sha256)}`)), tag(active ? "Active" : selected ? "Selected" : "Saved", active ? "confirmed" : ""));
      const view = button(selected ? "Viewing version" : "View version", () => discardThen(async () => {
        qs.busy = "Loading version…"; render();
        try { const loaded = await api(`/api/questions/revisions/${encodeURIComponent(revision.id)}`); selectRevision(loaded); }
        catch (error) { qs.error = error.message; }
        finally { qs.busy = ""; render(); }
      }), false, selected || blocked());
      row.append(view); list.append(row);
    }
    area.append(list);
    const total = qs.data.history_total ?? (qs.data.history || []).length;
    if ((qs.data.history || []).length < total) {
      area.append(el("p", "control-note", `Showing ${qs.data.history.length} of ${total} saved versions.`), button("Load older versions", loadOlderVersions, false, blocked()));
    }
    if (qs.tests.length) {
      const details = el("details", "audit-details"); details.append(el("summary", "", "Recent comparison history"));
      for (const test of qs.tests) {
        const row = el("div", "question-test-history");
        append(row, el("span", "", `${formatDate(test.created_at)} · ${label(statusOf(test))} · ${shortHash(test.revision_id)}`), button("View comparison", () => discardThen(async () => {
          qs.busy = "Loading comparison…"; render();
          try {
            const [result, revision] = await Promise.all([api(`/api/questions/tests/${encodeURIComponent(test.id)}`), api(`/api/questions/revisions/${encodeURIComponent(test.revision_id)}`)]);
            selectRevision(revision); qs.result = result;
            if (pending(result)) { qs.busy = "Comparing questions…"; watchTest(result.id); }
            else qs.busy = "";
          } catch (error) { qs.busy = ""; qs.error = error.message; }
          render();
        }), false, blocked())); details.append(row);
      }
      area.append(details);
    }
    return area;
  }
  async function loadOlderVersions() {
    if (blocked()) return;
    qs.busy = "Loading older versions…"; render();
    try {
      const page = await api(`/api/questions?limit=100&offset=${qs.data.history.length}`);
      const known = new Set(qs.data.history.map(revision => revision.id));
      qs.data.history.push(...(page.history || []).filter(revision => !known.has(revision.id)));
      qs.data.history_total = page.history_total ?? qs.data.history.length;
      qs.data.provider = page.provider; qs.data.active = page.active;
    } catch (error) { qs.error = error.message; }
    finally { qs.busy = ""; render(); }
  }
  async function restoreDefaults() {
    if (!writable() || blocked()) return;
    if (!await confirmAction("Restore shipped detection questions?", "This activates a new version containing this release’s original questions. Unsaved edits will be discarded. Existing classifications, Gmail labels, saved versions, and test history are retained. The shipped baseline does not require another provider test.", "Restore defaults")) return;
    qs.busy = "Restoring shipped defaults…"; qs.error = ""; render();
    let confirmed = false;
    try {
      await api("/api/questions/restore-defaults", {method: "POST", body: JSON.stringify({expected_active_id: activeId()})});
      confirmed = true;
      await fetchData(); selectRevision(qs.data.active); qs.notice = "Shipped defaults restored as a new active version. Your previous versions are still in history.";
    } catch (error) {
      if (confirmed) { qs.needsRefresh = true; qs.dirty = false; qs.notice = "Shipped defaults activated. Current status could not be refreshed. Use Refresh versions before making another change."; qs.error = ""; }
      else { qs.error = mutationError(error); }
    }
    finally { qs.busy = ""; render(); }
  }
  function guardNavigation(view) {
    if (view === "questions" || state.view !== "questions" || qs.leaving) return false;
    if (qs.busy && !pending(qs.result)) { toast("Please wait for the question change to finish before leaving this view."); return true; }
    if (!qs.dirty) return false;
    discardThen(() => { selectRevision(qs.revision); qs.leaving = true; showView(view); qs.leaving = false; }); return true;
  }
  window.addEventListener("beforeunload", event => {
    if (!qs.dirty) return; event.preventDefault(); event.returnValue = "";
  });
  $("#nav-questions").hidden = isEvaluation; $("#advanced-label").hidden = isEvaluation;
  $("#nav-questions").addEventListener("click", open);
  return {open, guardNavigation};
})();
