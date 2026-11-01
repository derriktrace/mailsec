"use strict";

// The console never interprets email HTML, fetches message URLs, or loads remote images.
// All API-supplied strings enter the document through textContent or form values.
const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];
const verdicts = ["clean", "spam", "suspicious", "phishing"];
const workspaceBase = location.pathname.startsWith('/evaluation/') ? '/evaluation' : '';
const isEvaluation = Boolean(workspaceBase);
const state = { status: null, overview: null, protection: null, accounts: null, actions: null, actionFilter: "all", policyDirty: false, view: "overview", keepSelection: false, messages: [], selected: null, detail: null, tab: "assessment", filter: "", query: "", offset: 0, total: 0, busy: false, refreshQueued: false, detailSignature: "", listSignature: "", overviewSignature: "", selectionEpoch: 0, apiError: false };
let accessToken = "";
try { accessToken = sessionStorage.getItem("mailsec-access-token") || ""; } catch (_) { /* Session storage may be disabled. */ }

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function append(parent, ...children) { for (const child of children) if (child) parent.append(child); return parent; }
function pretty(value) { return typeof value === "string" ? value : JSON.stringify(value, null, 2); }
function display(value, fallback = "Not supplied") {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length ? value.map(v => display(v, "")).join(", ") : fallback;
  if (typeof value === "object") return pretty(value);
  return String(value);
}
function label(value) { return String(value || "").replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase()); }
function numeric(value) { const n = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN; return Number.isFinite(n) ? Math.max(0, Math.min(1, n)) : null; }
function percent(value) { const n = numeric(value); return n === null ? "—" : `${Math.round(n * 100)}%`; }
function badge(value) { const safe = [...verdicts, "error", "pending", "processing", "queued"].includes(value) ? value : "pending"; return el("span", `badge ${safe}`, value || "pending"); }
function formatDate(value, short = false) {
  if (!value) return "Date unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Date unavailable";
  return short ? date.toLocaleDateString(undefined, { month: "short", day: "numeric" }) : date.toLocaleString(undefined, { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" });
}
function toast(message, error = false) {
  const node = el("div", `toast${error ? " error" : ""}`, message);
  while ($("#toasts").children.length >= 3) $("#toasts").firstElementChild.remove();
  $("#toasts").append(node);
  setTimeout(() => node.remove(), error ? 11000 : 6500);
}
async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const response = await fetch(workspaceBase + path, { ...options, headers, credentials: "same-origin", cache: "no-store" });
  if (response.status === 401) {
    if (!$("#auth-dialog").open) $("#auth-dialog").showModal();
    throw new Error("A console access token is required.");
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail || data.error;
    const error = new Error(typeof detail === "string" ? detail : `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function renderStatus() {
  const selector = $('#workspace-select');
  const spaces = state.workspaces?.workspaces || [];
  if (spaces.length && document.activeElement !== selector) {
    selector.replaceChildren(...spaces.map(space => new Option(space.name, space.path)));
    selector.value = workspaceBase + '/';
    selector.disabled = spaces.length < 2;
  }
  $('.brand').href = workspaceBase + '/';
  $('#evaluation-banner').hidden = !isEvaluation;
  $('#connection-button').hidden = isEvaluation;
  $('#nav-actions').hidden = isEvaluation;
  if (isEvaluation) {
    $('.page-header h1').textContent = 'Put detection to the test.';
    document.title = 'Phishing Pot · Mailsec evaluation';
    $('#corpus-progress').textContent = state.corpus ? `${state.corpus.completed.toLocaleString()} / ${state.corpus.imported.toLocaleString()} analyzed · ${state.corpus.errors} errors · ${state.corpus.batches_complete} batches complete` : '';
  }
  const status = state.status || {};
  renderProviderPrivacyBanner();
  const counts = status.counts || {};
  for (const verdict of verdicts) $("#count-" + verdict).textContent = counts[verdict] ?? "—";
  const countValues = Object.values(counts).filter(value => typeof value === "number");
  $("#nav-count").textContent = countValues.length ? countValues.reduce((a, b) => a + b, 0).toLocaleString() : "—";
  const pending = (Number(counts.pending) || 0) + (Number(counts.processing) || 0) + (Number(counts.queued) || 0);
  $("#pending-count").textContent = pending ? `${pending} in progress` : Number(counts.error) ? `${counts.error} need attention` : "";
  const modelState = $("#model-state");
  modelState.replaceChildren(el("span", "live-dot"), document.createTextNode(status.decision?.analysis_paused ? `${status.model || "Model"} · Sharing paused` : status.key_configured ? `${status.model || "JEV"} · Configured` : "Choose a decision model"));
  modelState.classList.toggle("offline", !status.key_configured || status.decision?.analysis_paused === true);
  $("#connection-dot").classList.toggle("connected", accountRows().some(account => account.connected && account.status === "connected" && !account.last_error));
  const mode = currentMode();
  const awaitingManage = ["flag_only", "auto_quarantine"].includes(mode) && !isEvaluation && !writableAccounts().length;
  $("#mode-pill").textContent = awaitingManage ? "MANAGE ACCESS NEEDED" : modeName(mode).toUpperCase();
  $("#mode-description").textContent = awaitingManage ? `${modeName(mode)} is saved, but no connected mailbox permits changes.` : modeDescription(mode);
  $("#sidebar-mode").replaceChildren(document.createTextNode(modeName(mode)), el("small", "", awaitingManage ? "Configured only · Manage access needed" : mode === "passive" ? "Automatic mailbox changes disabled" : "Mailbox actions recorded in the ledger"));
  $("#action-count").textContent = state.actions ? String(state.actions.length) : "—";
  const blockers = readinessBlockers();
  const banner = $("#readiness-banner");
  banner.hidden = !blockers.length;
  if (blockers.length) {
    const open = el("button", "text-button", "Review setup →"); open.addEventListener("click", () => showView("protection"));
    banner.replaceChildren(append(el("div", ""), el("strong", "", "Protection setup needs attention"), el("span", "", blockers[0] + (blockers.length > 1 ? ` · ${blockers.length - 1} more ${blockers.length === 2 ? "item" : "items"}` : ""))), open);
  }
  $("#last-update").textContent = `Updated ${new Date().toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}`;
  if ($("#connections-dialog").open) renderConnections();
  $$(".stat-card").forEach(card => { card.classList.toggle("selected", state.view === "review" && card.dataset.filter === state.filter); card.setAttribute("aria-pressed", String(state.view === "review" && card.dataset.filter === state.filter)); });
}

function providerSharingDisclosure(privacy, className = "") {
  const section = el("section", `provider-sharing-disclosure ${className}`);
  append(section, el("div", "eyebrow", privacy.provider === "jev" ? "THIRD-PARTY EMAIL CONTENT SHARING" : "EMAIL EVIDENCE DESTINATION"), el("h3", "", privacy.title), el("p", "sharing-summary", privacy.summary));
  const destination = el("p", "sharing-destination"); append(destination, el("strong", "", "Destination: "), el("code", "", privacy.destination)); section.append(destination);
  for (const part of privacy.sections || []) section.append(append(el("div", "sharing-section"), el("h4", "", part.title), el("p", "", part.body)));
  section.append(el("p", "sharing-version", `Disclosure ${privacy.disclosure_version} · ${String(privacy.disclosure_sha256 || "").slice(0,12)}`));
  return section;
}
function renderProviderPrivacyBanner() {
  const banner = $("#provider-privacy-banner"); if (!banner) return;
  const model = state.status?.decision || state.protection?.services?.decision;
  const privacy = model?.privacy;
  const paused = model?.analysis_paused === true || privacy?.blocking === true;
  banner.hidden = !paused;
  if (!paused) { banner.replaceChildren(); return; }
  const signature = JSON.stringify([model?.provider, privacy?.destination_sha256, privacy?.disclosure_sha256, privacy?.accepted, privacy?.analysis_allowed]);
  if (banner.dataset.signature === signature && banner.children.length) return;
  banner.dataset.signature = signature;
  const hosted = model.provider === "jev" || privacy?.provider === "jev";
  const review = el("button", "button primary", hosted ? "Review Jev email sharing" : "Review this evidence destination"); review.type = "button";
  review.addEventListener("click", () => window.mailsecSetup?.open(1));
  banner.replaceChildren();
  banner.append(append(el("div", ""), el("div", "eyebrow", "ANALYSIS PAUSED · OWNER APPROVAL REQUIRED"), el("h2", "", hosted ? "Jev sends email evidence to TypeSafe, a third party." : "Approve where your email evidence will be sent."), el("p", "", hosted ? "Sender and recipient addresses, message content, complete links, extracted attachment text and related context can leave your server. The evidence is not anonymized. Selected historical and future mail stays paused until you review the disclosure, explicitly accept it, then save and allow analysis with your chosen settings." : "Your configured model endpoint receives email content and identifiers. An Ollama or compatible endpoint can be local or remote; its operator controls logging and forwarding. Review its disclosure, explicitly accept it, then save and allow analysis with your chosen settings.")), review);
}

async function refresh({ force = false, reportError = false } = {}) {
  if (state.busy) { if (force) state.refreshQueued = true; return; }
  state.busy = true;
  try {
    const params = new URLSearchParams();
    if (state.query) params.set("q", state.query);
    if (state.filter) params.set("verdict", state.filter);
    params.set("limit", "200");
    params.set("offset", String(state.offset));
    const [status, data, overview, protection, accounts, actions, workspaces, corpus] = await Promise.all([api("/api/status"), api(`/api/messages?${params}`), api("/api/overview").catch(() => null), api("/api/protection").catch(() => null), api("/api/accounts").catch(() => null), api("/api/actions?limit=200").catch(() => null), api('/api/workspaces').catch(() => null), isEvaluation ? api('/api/corpus').catch(() => null) : Promise.resolve(null)]);
    state.workspaces = workspaces;
    state.corpus = corpus;
    state.status = status;
    state.overview = overview;
    state.protection = protection;
    state.accounts = accounts;
    state.actions = actions?.actions ?? null;
    state.messages = data.messages || [];
    state.total = data.total ?? state.messages.length;
    state.apiError = false;
    renderStatus();
    document.dispatchEvent(new CustomEvent("mailsec:refreshed"));
    const overviewSignature = JSON.stringify([overview, corpus, status.key_configured, status.google_configured, status.mailboxes, status.worker, protection, accounts]);
    if (overviewSignature !== state.overviewSignature || force) { renderOverview(); state.overviewSignature = overviewSignature; }
    if (state.view === "protection" && !state.policyDirty) renderProtection();
    if (state.view === "accounts") renderAccounts();
    if (state.view === "actions") renderActionsView();
    $("#queue-total").textContent = String(state.total);
    $("#queue-pagination").hidden = state.total <= 200;
    $("#page-label").textContent = `${Math.floor(state.offset / 200) + 1} / ${Math.max(1, Math.ceil(state.total / 200))}`;
    $("#previous-page").disabled = state.offset === 0;
    $("#next-page").disabled = state.offset + 200 >= state.total;
    if (state.selected && !state.keepSelection && !state.messages.some(message => message.id === state.selected)) {
      state.selected = null; state.detail = null; state.detailSignature = ""; state.selectionEpoch += 1;
    }
    if (!state.selected && state.messages.length) { state.selected = state.messages[0].id; state.tab = "assessment"; state.detailSignature = ""; }
    const signature = JSON.stringify([state.messages, state.selected, state.filter, state.query]);
    if (signature !== state.listSignature || force) { renderList(); state.listSignature = signature; }
    if (state.selected) await loadDetail(state.selected, force);
    else renderWelcome();
  } catch (error) {
    $("#last-update").textContent = "Service connection needs attention";
    $("#model-state").replaceChildren(el("span", "live-dot"), document.createTextNode("Service unavailable"));
    $("#model-state").classList.add("offline");
    if ((!state.apiError || reportError) && !$("#auth-dialog").open) toast(error.message, true);
    state.apiError = true;
    if (!state.status) { renderList(); renderWelcome(); }
  } finally {
    state.busy = false;
    if (state.refreshQueued) { state.refreshQueued = false; setTimeout(() => refresh({ force: true }), 0); }
  }
}

function renderList() {
  const container = $("#message-list");
  container.replaceChildren();
  if (!state.messages.length) {
    const empty = el("div", "queue-empty");
    append(empty, el("strong", "", state.filter || state.query ? "No matching messages" : "Your queue is ready"), el("span", "", state.filter || state.query ? "Try another search or verdict filter." : "Imported emails will appear here."));
    container.append(empty);
    return;
  }
  for (const message of state.messages) {
    const row = el("button", `message-row${message.id === state.selected ? " active" : ""}`);
    row.type = "button";
    row.setAttribute("aria-pressed", String(message.id === state.selected));
    const sender = message.from_name || message.from_address || "Unknown sender";
    append(row, append(el("div", "message-row-top"), el("span", "message-sender", sender), el("span", "message-time", formatDate(message.received_at, true))), el("div", "message-subject", message.subject || "(No subject)"), append(el("div", "message-bottom"), badge(message.status === "error" ? "error" : message.verdict || message.status || "pending"), el("span", "message-address", message.from_address || message.mailbox || "Imported email")));
    row.addEventListener("click", () => selectMessage(message.id));
    container.append(row);
  }
}

async function selectMessage(id) {
  if (state.selected === id && state.detail) return;
  state.selected = id; state.tab = "assessment"; state.detail = null; state.detailSignature = ""; state.selectionEpoch += 1;
  renderList();
  $("#detail").replaceChildren(el("div", "loading-line"), el("div", "loading-label", "Loading message evidence…"));
  await loadDetail(id, true);
}

function showView(view) {
  if (window.mailsecQuestions?.guardNavigation(view)) return;
  state.view = view;
  if (state.status) renderStatus();
  $("#setup-view").hidden = view !== "setup";
  $("#nav-setup").hidden = isEvaluation;
  $("#nav-setup").classList.toggle("active", view === "setup");
  $("#questions-view").hidden = view !== "questions";
  $("#nav-questions").hidden = isEvaluation;
  $("#advanced-label").hidden = isEvaluation;
  $("#nav-questions").classList.toggle("active", view === "questions");
  $("#overview").hidden = view !== "overview";
  $("#workbench").hidden = view !== "review";
  $("#protection-view").hidden = view !== "protection";
  $("#accounts-view").hidden = view !== "accounts";
  $("#actions-view").hidden = view !== "actions";
  $(".stats").hidden = !["overview", "review"].includes(view);
  $("#nav-overview").classList.toggle("active", view === "overview");
  $("#nav-inbox").classList.toggle("active", view === "review");
  $("#nav-protection").classList.toggle("active", view === "protection");
  $("#nav-actions").classList.toggle("active", view === "actions");
  $("#connection-button").classList.toggle("active", view === "accounts");
  const names = { setup: "SETUP WALKTHROUGH", questions: "DETECTION QUESTIONS", overview: "OVERVIEW", review: "REVIEW QUEUE", protection: "PROTECTION POLICY", accounts: "CONNECTED ACCOUNTS", actions: "ACTION LEDGER" };
  const descriptions = { setup: "Your email, your model, your choice of protection.", questions: "Tune the questions. Test the evidence. Keep every version.", overview: "A live view of mail evidence, risk, and review.", review: "Evidence, judgments, and a clear path to review.", protection: "Control enforcement. Inspect readiness and coverage.", accounts: "Connect your authorized mailboxes and review sync health.", actions: "Every mailbox change and notification, with its recorded outcome." };
  $("#page-eyebrow").textContent = `MAIL SECURITY / ${names[view] || "OVERVIEW"}`;
  $("#page-description").textContent = descriptions[view] || descriptions.overview;
  if (view === "protection") renderProtection();
  if (view === "accounts") renderAccounts();
  if (view === "actions") renderActionsView();
  for (const [id, active] of [["nav-overview", "overview"], ["nav-inbox", "review"], ["nav-protection", "protection"], ["nav-actions", "actions"], ["connection-button", "accounts"], ["nav-questions", "questions"]]) $("#" + id).setAttribute("aria-current", view === active ? "page" : "false");
}

function svgNode(tag, attributes = {}, text) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  if (text !== undefined) node.textContent = String(text);
  return node;
}
function cardHeading(title, subtitle) { return append(el("div", "dashboard-card-heading"), append(el("div", ""), el("h2", "", title), el("p", "", subtitle))); }
function openRisk(message) {
  state.keepSelection = true;
  showView("review");
  selectMessage(message.id);
}
function renderOverview() {
  const data = state.overview;
  const dashboard = $("#overview");
  if (!data) {
    const placeholder = el("div", "dashboard-loading", state.status ? "Dashboard metrics are unavailable. Mail review remains available." : "Connecting to your mail evidence…");
    if (state.status) { const open = el("button", "button", "Open mail review"); open.addEventListener("click", () => showView("review")); placeholder.append(open); }
    dashboard.replaceChildren(placeholder);
    return;
  }
  const counts = data.verdict_counts || {};
  const analyzed = Number(data.analyzed_messages) || 0;
  const grid = el("div", "overview-grid");
  const activity = el("section", "dashboard-card activity-card");
  append(activity, cardHeading(isEvaluation ? "Evaluation progress" : "Mail activity", isEvaluation ? "Verdicts by batch · up to 250 unique emails per batch" : "Daily message arrivals · last 14 days · UTC"));
  const metrics = el("div", "activity-metrics");
  for (const [number, title] of [[data.total_messages, isEvaluation ? "samples imported" : "messages received"], [analyzed, "analyzed"], [data.pending_messages, "processing"], [data.error_messages, "errors"]]) metrics.append(append(el("div", "activity-metric"), el("strong", "", (Number(number) || 0).toLocaleString()), el("span", "", title)));
  activity.append(metrics);
  const daily = (isEvaluation ? state.corpus?.batch_summary : data.daily) || [];
  const chart = svgNode("svg", { viewBox: "0 0 700 190", role: "img", "aria-label": `${isEvaluation ? 'Evaluation batches' : 'Mail received each day in UTC'}. ${daily.map(day => `${day.date}: ${day.total}`).join("; ")}`, class: "activity-chart", preserveAspectRatio: "xMidYMid meet" });
  const max = Math.max(1, ...daily.map(day => Number(day.total) || 0));
  const top = 14, baseline = 154, height = baseline - top;
  for (let i = 0; i < 3; i++) {
    const y = baseline - (height * i / 2);
    append(chart, svgNode("line", { x1: 29, x2: 693, y1: y, y2: y, class: "chart-grid" }), svgNode("text", { x: 0, y: y + 3, class: "chart-axis" }, Number.isInteger(max * i / 2) ? max * i / 2 : ""));
  }
  const slot = 660 / Math.max(daily.length, 1);
  daily.forEach((day, index) => {
    const x = 35 + index * slot + slot * .12;
    let bottom = baseline;
    const group = svgNode("g");
    group.append(svgNode("title", {}, `${day.date}${isEvaluation ? '' : ' UTC'} · ${day.total} messages`));
    for (const verdict of [...verdicts, "pending", "error"]) {
      const count = Math.max(0, Number(day[verdict]) || 0);
      if (!count) continue;
      const barHeight = count / max * height;
      group.append(svgNode("rect", { x, y: bottom - barHeight, width: slot * .68, height: barHeight, rx: 2, class: `chart-fill ${verdict}` }));
      bottom -= barHeight;
    }
    if (!Number(day.total)) group.append(svgNode("rect", { x, y: baseline - 2, width: slot * .68, height: 2, rx: 1, class: "chart-empty-bar" }));
    chart.append(group);
    if ([0, Math.floor((daily.length - 1) / 3), Math.floor((daily.length - 1) * 2 / 3), daily.length - 1].includes(index)) {
      const date = new Date(`${day.date}T00:00:00Z`);
      const title = Number.isNaN(date.valueOf()) ? day.date : date.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
      chart.append(svgNode("text", { x: x + slot * .34, y: 179, "text-anchor": "middle", class: "chart-axis" }, title));
    }
  });
  activity.append(chart);
  const chartLegend = el("div", "chart-legend");
  for (const verdict of [...verdicts, ...["pending", "error"].filter(key => daily.some(day => Number(day[key]) > 0))]) chartLegend.append(append(el("span", ""), el("span", `verdict-dot ${verdict}`), document.createTextNode(label(verdict))));
  append(activity, chartLegend);
  const mix = el("section", "dashboard-card mix-card");
  append(mix, cardHeading("Verdict mix", "Current completed assessments"));
  const mixBody = el("div", "mix-body");
  const ring = svgNode("svg", { viewBox: "0 0 176 176", role: "img", "aria-label": verdicts.map(verdict => `${verdict}: ${counts[verdict] || 0}`).join(", "), class: "verdict-ring" });
  ring.append(svgNode("circle", { cx: 88, cy: 88, r: 68, fill: "none", "stroke-width": 17, class: "ring-track" }));
  const totalDecisions = verdicts.reduce((sum, verdict) => sum + (Number(counts[verdict]) || 0), 0);
  let offset = 0;
  for (const verdict of verdicts) {
    const share = totalDecisions ? (Number(counts[verdict]) || 0) / totalDecisions * 100 : 0;
    if (share) ring.append(svgNode("circle", { cx: 88, cy: 88, r: 68, fill: "none", "stroke-width": 17, pathLength: 100, "stroke-dasharray": `${Math.max(0, share - (totalDecisions > (counts[verdict] || 0) ? 1.1 : 0))} 100`, "stroke-dashoffset": -offset, transform: "rotate(-90 88 88)", class: `ring-segment ${verdict}` }));
    offset += share;
  }
  append(ring, svgNode("text", { x: 88, y: 91, "text-anchor": "middle", class: "ring-total" }, totalDecisions.toLocaleString()), svgNode("text", { x: 88, y: 110, "text-anchor": "middle", class: "ring-label" }, "ANALYZED"));
  mixBody.append(ring);
  const legend = el("div", "mix-legend");
  for (const verdict of verdicts) {
    const row = el("button", "mix-legend-row");
    const count = Number(counts[verdict]) || 0;
    append(row, el("span", `verdict-dot ${verdict}`), el("span", "", label(verdict)), el("strong", "", count.toLocaleString()), el("small", "", totalDecisions ? `${Math.round(count / totalDecisions * 100)}%` : "—"));
    row.addEventListener("click", () => { state.filter = verdict; state.offset = 0; state.keepSelection = false; $("#verdict-filter").value = verdict; showView("review"); refresh({ force: true }); });
    legend.append(row);
  }
  append(mixBody, legend); mix.append(mixBody);
  mix.append(el("p", "dashboard-footnote", "Probabilities and source evidence are available in each message’s assessment."));
  const risks = el("section", "dashboard-card risks-card");
  const riskHead = cardHeading("Needs a closer look", "Suspicious and phishing messages awaiting analyst review");
  riskHead.append(el("span", "review-count", `${Number(data.review_needed) || 0} to review`));
  risks.append(riskHead);
  const recent = data.recent_risks || [];
  if (!recent.length) risks.append(append(el("div", "overview-empty"), el("strong", "", analyzed ? "Your review queue is clear." : "Your first assessment starts here."), el("p", "", analyzed ? "No suspicious or phishing messages are awaiting analyst review." : "Import an .eml file, or explore synthetic samples with your configured model.")));
  for (const message of recent.slice(0, 5)) {
    const row = el("button", "risk-row");
    const marker = el("span", `risk-marker ${message.verdict}`, message.verdict === "phishing" ? "!" : "?");
    const info = el("div", "risk-message");
    append(info, el("strong", "", message.subject || "(No subject)"), append(el("span", "risk-sender"), document.createTextNode(message.from_name || message.from_address || "Unknown sender"), message.provider === "demo" ? el("span", "source-tag", "SYNTHETIC") : null));
    const trailing = append(el("div", "risk-trailing"), badge(message.verdict), el("span", "", "Review →"));
    append(row, marker, info, trailing); row.addEventListener("click", () => openRisk(message)); risks.append(row);
  }
  const riskFoot = el("div", "risk-footer");
  const openQueue = el("button", "text-button", "Open mail review →"); openQueue.addEventListener("click", () => showView("review"));
  append(riskFoot, el("span", "", `${Number(data.reviewed_messages) || 0} ${Number(data.reviewed_messages) === 1 ? "message" : "messages"} reviewed by an analyst`), openQueue); risks.append(riskFoot);
  const pipeline = el("section", "dashboard-card pipeline-card");
  const pipelineHead = cardHeading("Protection readiness", "Configuration and account state"); pipelineHead.append(el("span", "passive-pill", modeName(currentMode()))); pipeline.append(pipelineHead);
  const connected = accountRows().filter(account => account.connected).length;
  const healthy = accountRows().filter(account => account.connected && account.status === "connected" && !account.last_error).length;
  const googleConfigured = state.accounts?.oauth_configured ?? state.protection?.services?.google_oauth?.configured ?? false;
  const statuses = [
    ["01", isEvaluation ? "Sample collection" : "Mailbox access", isEvaluation ? "Isolated evaluation · Gmail disabled" : connected ? `${connected} connected accounts${healthy < connected ? ` · ${connected - healthy} need attention` : ""}` : googleConfigured ? "Ready to connect · Google consent required" : "Not connected · Google setup required", isEvaluation || healthy > 0],
    ["02", "Inspection", state.protection?.services?.inspection?.configured ? "Configured · per-message coverage recorded" : "Unavailable · scanner setup required", Boolean(state.protection?.services?.inspection?.configured)],
    ["03", "Decision model", state.status?.key_configured ? `${state.status.model || "JEV"} · configured` : "Choose a decision provider", Boolean(state.status?.key_configured)],
    ["04", "URL reputation", state.protection?.services?.url_reputation?.configured ? "Configured · lookup limits apply" : "Unavailable · Web Risk setup required", Boolean(state.protection?.services?.url_reputation?.configured)]
  ];
  for (const [number, title, description, ready] of statuses) pipeline.append(append(el("div", "pipeline-step"), el("span", "step-number", number), append(el("div", "step-text"), el("strong", "", title), el("span", "", description)), el("span", ready ? "step-configured" : "step-needed", ready ? "·" : "!")));
  const connection = el("div", "overview-connection");
  append(connection, el("div", "connection-monogram", "G"), append(el("div", "connection-copy"), el("strong", "", "Google accounts"), el("span", "", `${connected} of ${accountRows().length} accounts connected`)));
  const setup = el("button", "text-button", "Manage →"); setup.addEventListener("click", () => showView("accounts")); connection.append(setup); if (!isEvaluation) pipeline.append(connection);
  append(grid, activity, mix, risks, pipeline);
  const strip = el("div", "overview-bottom-strip");
  append(strip, el("span", "", modeDescription(currentMode())), el("span", "", "Actual outcomes are recorded in the action ledger."));
  dashboard.replaceChildren(grid, strip);
  if (!data.total_messages && !isEvaluation) {
    const demo = el("button", "button", "Analyze demo emails"); demo.addEventListener("click", () => analyzeDemo(demo));
    const emptyActions = append(el("div", "dashboard-empty-actions"), demo, el("span", "", "Synthetic examples · uses your configured model")); risks.insertBefore(emptyActions, riskFoot);
  }
}

async function loadDetail(id, force = false) {
  const epoch = state.selectionEpoch;
  try {
    const data = await api(`/api/messages/${encodeURIComponent(id)}`);
    if (state.selected !== id || epoch !== state.selectionEpoch) return;
    const signature = JSON.stringify(data);
    state.detail = data;
    if (signature !== state.detailSignature || force) {
      const editing = ["#feedback-form", "#gmail-label-form"].some(selector => $(selector)?.contains(document.activeElement));
      if (editing && !force) return;
      state.detailSignature = signature; renderDetail();
    }
  } catch (error) {
    if (state.selected !== id || epoch !== state.selectionEpoch) return;
    if (!state.detail) $("#detail").replaceChildren(el("div", "error-panel", `Unable to load this message. ${error.message}`));
  }
}

function mailIllustration() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 48 48"); svg.setAttribute("fill", "none"); svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M5 12h38v25H5zM5 12l19 15 19-15M5 37l14-14m24 14L29 23M33 8V3m5 6 4-4m-1 10h5");
  svg.append(path); return append(el("div", "welcome-art"), svg);
}
function renderWelcome() {
  const welcome = el("div", "welcome");
  const filtered = Boolean(state.filter || state.query);
  const importButton = el("button", "button primary", "Import .eml files");
  importButton.addEventListener("click", () => $("#file-input").click());
  const demoButton = el("button", "button", "Analyze demo emails");
  demoButton.addEventListener("click", () => analyzeDemo(demoButton));
  const actions = append(el("div", "welcome-actions"), importButton, demoButton);
  append(welcome, mailIllustration(), el("div", "eyebrow", "A CLEARER VIEW OF YOUR MAIL"), el("h2", "", filtered ? "Nothing in this view." : "Start with the evidence."), el("p", "", filtered ? "Adjust your search or filter to review another message, or import an email to begin a new investigation." : "Drop an email into the console. Your selected model evaluates the supplied evidence, and every decision stays available for your review."), actions, el("p", "footnote", "Demo emails are synthetic and use your configured model. Hosted providers may charge for analysis. Original messages remain untouched."), append(el("div", "welcome-features"), el("span", "", "Four clear verdicts"), el("span", "", "Inspectable evidence"), el("span", "", "No mailbox actions")));
  $("#detail").replaceChildren(welcome);
}

function latestRun() { return state.detail?.runs?.[0] || null; }
function evidenceFor(run) { return run?.evidence || {}; }
function messageBody(evidence) {
  if (typeof evidence.body === "string") return evidence.body;
  return evidence.body?.text || evidence.body?.plain_text || evidence.body_text || evidence.message?.body || "No readable message body was supplied.";
}
function renderDetail() {
  const detail = state.detail;
  if (!detail) return renderWelcome();
  const message = detail.message || {};
  const run = latestRun();
  const evidence = evidenceFor(run);
  const sender = evidence.message?.sender || {};
  const header = el("header", "detail-header");
  const replay = el("button", "button subtle", "↻  Replay analysis");
  replay.type = "button";
  replay.addEventListener("click", () => replayMessage(replay));
  const runCount = (detail.runs || []).length || message.run_count || 0;
  append(header, append(el("div", "detail-overline"), el("span", "eyebrow", "MESSAGE INVESTIGATION"), append(el("div", "detail-actions"), replay)), el("h2", "detail-subject", message.subject || evidence.message?.subject || "(No subject)"), append(el("div", "detail-meta"), el("span", "sender", message.from_name || sender.display_name || message.from_address || "Unknown sender"), el("span", "address", message.from_address || sender.address || "")), el("div", "detail-date", `${formatDate(message.received_at)} · ${message.mailbox || "Imported email"} · ${runCount} ${runCount === 1 ? "analysis" : "analyses"}`));
  const correct = el("button", "button subtle", "Correct classification");
  correct.type = "button";
  correct.addEventListener("click", () => { state.tab = "actions"; renderDetail(); $("#feedback-form select")?.focus(); });
  $(".detail-actions", header).prepend(correct);
  if (message.analyst_override) {
    const correction = message.analyst_override;
    header.append(append(el("div", "control-caveat analyst-verdict"), badge(correction.verdict),
      el("strong", "", `Your classification: ${label(correction.verdict)}`),
      el("p", "", `${correction.reviewer || "Analyst"} · ${formatDate(correction.created_at)}. Original automated classification: ${label(message.system_verdict || run?.policy?.verdict || run?.output?.answers?.verdict?.choice || "unavailable")}. The original analysis is retained below and in the audit trail.`)));
  }
  if (message.provider === "demo") header.append(el("span", "source-tag detail-source", "SYNTHETIC DEMO · MODEL ANALYSIS"));
  const tabs = el("div", "tabs"); tabs.setAttribute("role", "tablist");
  for (const [name, title] of [["assessment", "Assessment"], ["message", "Message"], ["actions", "Actions"], ["history", "Audit trail"]]) {
    const button = el("button", `tab${state.tab === name ? " active" : ""}`, title);
    button.type = "button"; button.id = `tab-${name}`;
    button.setAttribute("role", "tab"); button.setAttribute("aria-selected", String(state.tab === name));
    button.setAttribute("aria-controls", "tab-content");
    button.addEventListener("click", () => { state.tab = name; renderDetail(); });
    button.addEventListener("keydown", event => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const names = ["assessment", "message", "actions", "history"];
      const next = event.key === "Home" ? 0 : event.key === "End" ? 3 : (names.indexOf(name) + (event.key === "ArrowLeft" ? 3 : 1)) % 4;
      state.tab = names[next]; renderDetail(); $(`#tab-${state.tab}`).focus();
    });
    tabs.append(button);
  }
  header.append(tabs);
  const content = el("div", "tab-content"); content.id = "tab-content"; content.setAttribute("role", "tabpanel"); content.setAttribute("aria-labelledby", `tab-${state.tab}`);
  if (state.tab === "assessment") renderAssessment(content, message, run, evidence);
  if (state.tab === "message") renderMessage(content, evidence, message);
  if (state.tab === "actions") renderMessageActions(content, detail);
  if (state.tab === "history") renderHistory(content, detail);
  const previousScroll = $("#detail").scrollTop;
  $("#detail").replaceChildren(header, content);
  $("#detail").scrollTop = previousScroll;
}

function sectionHeading(title, annotation) { return append(el("div", "section-heading"), el("h3", "", title), annotation ? el("span", "", annotation) : null); }
function fact(title, value, note) { return append(el("div", "fact-card"), el("span", "label", title), el("strong", "", display(value)), note ? el("small", "", note) : null); }
function rawDetails(title, data) { const details = el("details", "audit-details"); append(details, el("summary", "", title), el("pre", "", pretty(data ?? {}))); return details; }
function bar(value, className = "") { const track = el("progress", `bar-track ${className}`); track.max = 1; track.value = numeric(value) ?? 0; track.setAttribute("aria-label", `${label(className) || "Yes probability"}: ${percent(value)}`); return track; }
function noulValue(answer) {
  if (typeof answer === "number") return answer;
  return answer?.noul ?? answer?.probability ?? answer?.value ?? answer?.probabilities?.true ?? null;
}
function authValue(auth, field) {
  const value = auth[field] ?? auth.results?.[field];
  const result = typeof value === "object" && value !== null ? value.result || value.status || value.verdict || display(value) : value;
  if (!result || String(result).toLowerCase() === "unknown") return auth.status === "receiver_reported" ? "Not reported by receiver" : "Not verified";
  return result;
}
function renderAuthentication(authSection, auth) {
  const receiverReported = auth.status === "receiver_reported";
  append(authSection, sectionHeading("Authentication evidence", "Domain control ≠ brand identity"), el("p", "small-note", receiverReported ? `Trusted receiver-reported results${auth.trusted_authserv_id ? ` · ${auth.trusted_authserv_id}` : ""}` : "Authentication is not verified for this message."));
  const cards = el("div", "facts-grid");
  for (const method of ["spf", "dkim", "dmarc"]) cards.append(fact(method.toUpperCase(), authValue(auth, method), receiverReported && auth[`${method}_domain`] ? `Reported domain: ${auth[`${method}_domain`]}` : undefined));
  authSection.append(cards);
  if (auth.provenance) authSection.append(el("p", "small-note", auth.provenance));

  const assertions = Array.isArray(auth.unverified_header_assertions) ? auth.unverified_header_assertions : [];
  const resultSignature = rows => JSON.stringify((Array.isArray(rows) ? rows : []).map(row => [row.method, row.result, row.domain ?? null]));
  let selectedHeaderIndex = receiverReported ? auth.selected_header_index ?? auth.receiver_header_index ?? auth.header_index : null;
  if (receiverReported && selectedHeaderIndex == null && Array.isArray(auth.receiver_results)) {
    // Older evidence has no selected index. Exclude only a unique exact match;
    // repeated or contradictory claims remain visible without inferred trust.
    const matching = assertions.filter(header => header.authserv_id === auth.trusted_authserv_id && resultSignature(header.results) === resultSignature(auth.receiver_results));
    if (matching.length === 1) selectedHeaderIndex = matching[0].header_index;
  }
  const unverified = assertions.filter(header => selectedHeaderIndex == null || header.header_index !== selectedHeaderIndex);
  if (unverified.length) {
    const claims = el("div", "section-block");
    claims.append(sectionHeading("Header-reported results · unverified"));
    const list = el("div", "evidence-list");
    for (const header of unverified) {
      const item = el("div", "evidence-item");
      const source = header.authserv_id || "Authserv ID not reported";
      item.append(el("strong", "", `${source}${header.header_index != null ? ` · header index ${header.header_index}` : ""}`));
      const results = Array.isArray(header.results) ? header.results : [];
      for (const result of results) item.append(el("div", "evidence-value", `${String(result.method || "Unspecified method").toUpperCase()}: ${display(result.result, "Result not reported")} · ${result.domain ? `domain ${display(result.domain)}` : "Domain not reported"}`));
      if (!results.length) item.append(el("div", "", "No SPF, DKIM, or DMARC result reported in this header."));
      list.append(item);
    }
    append(claims, list, el("p", "small-note", "These are source-header assertions. They have not been independently verified and do not establish a trusted authentication result."));
    authSection.append(claims);
  }
  const reportedMethods = new Set(assertions.flatMap(header => Array.isArray(header.results) ? header.results.map(result => String(result.method).toLowerCase()) : []));
  if (receiverReported) {
    for (const method of ["spf", "dkim", "dmarc"]) if (auth[method] && String(auth[method]).toLowerCase() !== "unknown") reportedMethods.add(method);
    for (const result of auth.receiver_results || []) reportedMethods.add(String(result.method).toLowerCase());
  }
  const missing = ["spf", "dkim", "dmarc"].filter(method => !reportedMethods.has(method));
  if (missing.length) authSection.append(el("p", "small-note", missing.map(method => `No ${method.toUpperCase()} result reported.`).join(" ")));
}
function antivirusText(antivirus) {
  if (!antivirus) return "Not recorded";
  if (antivirus.status === "clean") return antivirus.signatures_current === false ? "Stale signature evidence" : "No signature detection";
  return ({ malicious: "Malware signature detected", stale: "Stale signatures", unavailable: "Unavailable", error: "Scan error" })[antivirus.status] || label(antivirus.status || "unknown");
}
function evidenceExpiry(value) {
  if (typeof value === "number") return value * 1000;
  return value ? new Date(value).valueOf() : null;
}
function reputationText(result) {
  const expiry = evidenceExpiry(result.expires_at);
  if (expiry && expiry <= Date.now()) return "Expired evidence";
  return ({ not_listed: "No known threat", malicious: "Known threat", unavailable: "Unavailable", budget_exhausted: "Lookup budget exhausted", unknown: "Unknown", stale: "Stale evidence" })[result.status] || label(result.status || "unknown");
}
function renderInspection(container, evidence) {
  const inspection = evidence.inspection;
  const reputation = evidence.url_inspection;
  const section = el("section", "section-block inspection-section");
  append(section, sectionHeading("Inspection & URL coverage", "Recorded evidence · bounded inspection"));
  if (!inspection && !reputation) {
    section.append(el("p", "control-caveat", "Inspection and URL reputation evidence were not recorded in this analysis. This is not a clean scan; historical runs are preserved as originally evaluated."));
    container.append(section); return;
  }
  const antivirus = inspection?.antivirus;
  const results = reputation?.results || [];
  const expired = results.some(result => { const expiry = evidenceExpiry(result.expires_at); return expiry && expiry <= Date.now(); });
  const complete = Boolean(reputation?.complete) && !expired;
  append(section, append(el("div", "facts-grid"), fact("Inspection", inspection ? label(inspection.status || "unknown") : "Not recorded"), fact("Antivirus", antivirusText(antivirus), antivirus?.objects_total != null ? `${antivirus.objects_scanned ?? "—"} / ${antivirus.objects_total} objects scanned` : undefined), fact("URL lookup coverage", reputation ? expired ? "Expired evidence present" : complete ? "Complete for submitted URLs" : "Incomplete" : "Not recorded", reputation ? `${results.length} results · ${reputation.omitted_urls || 0} URLs omitted` : undefined)));
  const coverage = inspection?.coverage || {};
  const coverageList = el("div", "coverage-list");
  for (const [key, title] of [["mime", "MIME"], ["archives", "Archives"], ["documents", "Documents"], ["ocr", "Image text"], ["antivirus", "Antivirus"]]) if (coverage[key]) coverageList.append(statusTag(`${title}: ${label(coverage[key])}`, statusTone(coverage[key])));
  if (antivirus?.signatures_current === false) coverageList.append(statusTag("Signatures not current", "warning"));
  if (antivirus?.signature_stable_during_inspection === false) coverageList.append(statusTag("Signatures changed during inspection", "warning"));
  section.append(coverageList);
  if (antivirus?.signature_timestamp) section.append(el("p", "small-note", `Signature database timestamp: ${formatDate(antivirus.signature_timestamp)}${antivirus.signature_age_hours != null ? ` · recorded age ${antivirus.signature_age_hours} hours` : ""}`));
  if (inspection?.status !== "complete" || !complete) section.append(el("p", "control-caveat", "Inspection coverage is missing, partial, unavailable, or expired. No detection and no known threat are not proof of safety."));
  const findings = inspection?.findings || [];
  if (findings.length) {
    const list = el("div", "evidence-list");
    for (const finding of findings) list.append(append(el("div", "evidence-item"), append(el("div", "finding-title"), el("strong", "", finding.summary || label(finding.kind)), statusTag(label(finding.severity || "info"), ["critical", "high"].includes(finding.severity) ? "danger" : "warning")), el("span", "evidence-value", [finding.evidence_ref, finding.signature].filter(Boolean).join(" · "))));
    section.append(list);
  }
  const gaps = [...(coverage.limitations || []), ...(antivirus?.limitations || [])];
  for (const limitation of [...new Set(gaps.filter(value => typeof value === "string"))]) section.append(el("p", "small-note", limitation));
  if (inspection?.attachments?.length) {
    const attachments = el("div", "section-block"); attachments.append(sectionHeading("Extracted attachment coverage", `${inspection.attachments.length} objects`));
    const list = el("div", "evidence-list");
    for (const attachment of inspection.attachments) {
      const row = el("div", "evidence-item");
      append(row, el("strong", "", attachment.filename || "Unnamed object"), el("div", "", `${label(attachment.kind || attachment.content_type || "unknown")} · Extraction: ${label(attachment.coverage?.status || "unknown")} · Antivirus: ${antivirusText(attachment.antivirus)}`), el("div", "evidence-value", attachment.evidence_ref || "Evidence reference not supplied"));
      if (attachment.coverage?.ocr) row.append(el("div", "", `Image text (OCR): ${label(attachment.coverage.ocr)}${attachment.coverage.ocr_material_gap ? " · Important content remains unread" : ""}`));
      if (attachment.coverage?.material_content_gap) row.append(el("div", "", "Important document content remains unread."));
      for (const limitation of attachment.coverage?.limitations || []) row.append(el("div", "", display(limitation)));
      if (attachment.coverage?.scope_exclusions?.length) row.append(el("div", "", `Outside scope: ${attachment.coverage.scope_exclusions.map(label).join(", ")}`));
      list.append(row);
    }
    attachments.append(list); section.append(attachments);
  }
  const urls = el("div", "section-block"); urls.append(sectionHeading("URL reputation results", "Destinations remain inert text"));
  if (!results.length) urls.append(el("p", "small-note", reputation?.complete ? "No URLs were submitted for reputation lookup in this run." : "No URL reputation results were supplied."));
  for (const result of results) {
    const row = el("div", "reputation-row");
    const status = reputationText(result);
    append(row, statusTag(status, status === "Known threat" ? "danger" : ["No known threat"].includes(status) ? "neutral" : "warning"), el("div", "evidence-value", result.url || result.evidence_ref || "URL not supplied"));
    if (result.reason) row.append(el("p", "small-note", result.reason));
    if (result.threat_types?.length) row.append(el("p", "small-note", `Reported threats: ${result.threat_types.join(", ")}`));
    row.append(el("p", "small-note", [result.source ? `Source: ${label(result.source)}` : "", result.checked_at ? `Checked ${formatDate(result.checked_at)}` : "", result.cache_hit ? "Cached result" : "", result.expires_at ? `Expires ${formatDate(evidenceExpiry(result.expires_at))}` : ""].filter(Boolean).join(" · ")));
    urls.append(row);
  }
  append(urls, el("p", "small-note", "Reputation checks do not open the destination page. A result can expire after the analysis; original evidence and policy decisions remain unchanged."));
  section.append(urls);
  section.append(rawDetails("Complete inspection and reputation evidence", { inspection: inspection || null, url_inspection: reputation || null }));
  container.append(section);
}
function renderActionReview(container, review) {
  const section = el("section", "section-block action-review-section");
  append(section, sectionHeading("Action and authority review", review.status === "complete" ? "Additional model checks" : "Incomplete checks"), el("p", "small-note", "These additional judgments describe the requested action and the authority behind it. They come from the same model, are not independent corroboration, and cannot authorize phishing classification or quarantine."));
  if (review.status !== "complete") section.append(el("p", "control-caveat action-review-incomplete", review.status === "error" ? "The additional review did not finish because a model stage failed. Missing answers are not evidence of safety. Inspect the audit details before replaying." : "The additional review could not assess all important evidence. Missing answers are not evidence of safety; inspect the retained coverage details."));
  const findings = Array.isArray(review.findings) ? review.findings : [];
  if (findings.length) {
    const list = el("div", "evidence-list action-review-findings");
    for (const finding of findings) list.append(append(el("div", "evidence-item"), el("strong", "", finding.reason || "The requested action needs review."), el("span", "", "Review finding · composed model estimates, not independently confirmed deception.")));
    section.append(list);
  } else if (review.status === "complete") section.append(el("p", "small-note", "No additional action/authority review finding was recorded. This does not certify that the message is safe."));
  const facts = review.stages?.facts?.response?.answers || {};
  const rows = el("div", "signals action-fact-signals");
  for (const [key, title] of [["software_execution_requested", "Install or run software"], ["wallet_control_requested", "Change wallet access or control"], ["payment_requested", "Make a payment"], ["transaction_callback", "Use a supplied transaction or security phone contact"], ["secrets_or_login_requested", "Provide sensitive data or sign in"]]) {
    if (!Object.hasOwn(facts, key)) continue;
    const value = noulValue(facts[key]);
    rows.append(append(el("div", "signal-row"), el("span", "signal-label", title), bar(value), el("span", "signal-value", percent(value))));
  }
  if (rows.children.length) section.append(append(el("div", "section-block"), sectionHeading("Requested actions", "Probability of yes · not probability of fraud"), rows));
  if (facts.claimed_authority?.choice) section.append(el("p", "small-note", `Author’s claimed role: ${label(facts.claimed_authority.choice)}. This is a reading of the claim, not verification of the author.`));
  const authority = review.stages?.authority?.response?.answers?.authority_relationship;
  if (authority?.choice) {
    const details = el("details", "audit-details authority-distribution");
    details.append(el("summary", "", `Authority relationship: ${label(authority.choice)} · view model probabilities`));
    const body = el("div", "evidence-item");
    body.append(el("p", "small-note", "These probabilities concern the sender/action relationship. They are not confidence in the effective email verdict."));
    const grid = el("div", "probability-grid");
    for (const choice of ["coherent", "contradicted", "unresolved", "no_authority_claim"]) {
      if (!Object.hasOwn(authority.probabilities || {}, choice)) continue;
      append(grid, append(el("div", "probability-item"), append(el("div", "probability-top"), el("span", "", label(choice)), el("strong", "", percent(authority.probabilities[choice]))), bar(authority.probabilities[choice], choice)));
    }
    body.append(grid); details.append(body); section.append(details);
  }
  section.append(rawDetails("Action review audit · exact inputs, questions and responses", review));
  container.append(section);
}
function renderAssessment(container, message, run, evidence) {
  const output = run?.output || {};
  const answers = output.answers || {};
  const policy = run?.policy || {};
  const materialReview = policy.verdict_review_basis === "material_evidence_gap";
  const actionReview = output.action_review;
  const authorityReview = policy.verdict_review_basis === "action_authority_gap";
  const reviewRequired = materialReview || authorityReview;
  const sectionJudgment = Boolean(output.aggregation?.count > 1);
  const queued = ["pending", "processing"].includes(message.status);
  const decision = queued ? null : policy.verdict || answers.verdict?.choice || (!run ? message.verdict : null);
  const processing = queued || (!decision && run?.status !== "error" && message.status !== "error");
  const error = !queued && (run?.status === "error" || message.status === "error");
  const bannerKind = error ? "error" : decision || "pending";
  const banner = el("div", `assessment-banner ${bannerKind}`);
  const descriptions = {
    clean: "The supplied evidence supports a legitimate message with a coherent identity.",
    spam: "Unwanted or bulk mail, without affirmative evidence of a hostile request or payload.",
    suspicious: "A consequential uncertainty remains. Review the evidence before acting.",
    phishing: "The analysis supports a phishing classification. Review the supporting evidence and policy reasons below."
  };
  append(banner, el("div", "assessment-icon", error ? "!" : decision === "clean" ? "✓" : decision === "phishing" || decision === "suspicious" ? "!" : "·"), append(el("div", "assessment-content"), el("h3", "", error ? "Analysis needs attention" : processing ? "Analysis in progress" : reviewRequired ? "Suspicious — review required" : `${label(decision)} assessment`), el("p", "", error ? "The last analysis failed. Inspect the error below, then replay when the issue is resolved." : processing ? "The message is queued for scanning and model assessment. This view refreshes automatically." : authorityReview ? "A requested action relies on a sender or destination whose authority needs review. Check the concrete findings below before acting." : materialReview ? "The readable content appeared clean, but important evidence is unread or unresolved. Review it before acting." : descriptions[decision] || "Review the supplied evidence and the recorded decision.")));
  if (!error && !processing) append(banner, append(el("div", "assessment-confidence", reviewRequired ? "!" : percent(answers.verdict?.confidence ?? message.confidence)), el("small", "", reviewRequired ? "REVIEW REQUIRED" : sectionJudgment ? "SECTION JUDGMENT" : output.score_semantics === "uncalibrated_model_estimates" ? "MODEL ESTIMATE" : "JEV CONFIDENCE")));
  container.append(banner);
  if (message.analyst_override) banner.prepend(el("span", "original-assessment-label", "ORIGINAL AUTOMATED ASSESSMENT · YOUR CORRECTION IS SHOWN ABOVE"));
  if (queued) {
    const retry = run?.policy?.scan_retry;
    if (retry) container.append(el("p", "error-text", `${retry.reason} Attempt ${retry.failures}. Next retry: ${new Date(retry.next_attempt_at).toLocaleString()}.${retry.failures >= 3 ? " Repeated failures need operator attention; automatic retries continue." : ""} No classification is final until scanning recovers.`));
    container.append(el("p", "small-note", "A fresh classification is pending. Previous analyses remain available in the Audit trail; the original email is available in Message."));
    return;
  }
  if (error && run?.error) container.append(el("p", "error-text", display(run.error)));
  if (!Object.keys(evidence).length) {
    container.append(el("p", "evidence-empty", "Normalized evidence will appear when processing completes. Check the audit trail for available run details."));
    return;
  }
  if (!error && !processing) {
    if (authorityReview) {
      const notice = el("section", "control-caveat action-review-notice");
      append(notice, el("strong", "", "Why this needs review"), el("p", "", `The model’s initial verdict was ${label(policy.model_verdict || answers.verdict?.choice)} (${percent(answers.verdict?.confidence)} initial model confidence). The effective verdict is Suspicious because the additional action and authority checks require review. No combined verdict-confidence score is assigned.`));
      container.append(notice);
    }
    if (materialReview) {
      const notice = el("section", "control-caveat material-review-notice");
      append(notice, el("strong", "", "Why this needs review"), el("p", "", `The model’s semantic verdict was ${label(policy.model_verdict || answers.verdict?.choice)} (${percent(answers.verdict?.confidence)} model confidence). The effective verdict is Suspicious because these material gaps remain:`));
      const gaps = el("ul", "");
      for (const gap of policy.material_evidence_gaps || []) gaps.append(el("li", "", gap.reason || label(gap.kind)));
      notice.append(gaps); container.append(notice);
    }
    if (sectionJudgment) container.append(el("p", "control-caveat section-judgment-note", `${output.aggregation.count} bounded sections were analyzed. The probabilities below belong to the selected section judgment; they are not calibrated confidence for the entire email. Original section results are retained in the audit trail.`));
    if (actionReview) renderActionReview(container, actionReview);
    if (output.score_semantics === "uncalibrated_model_estimates") container.append(el("p", "control-caveat", "This configured model reports uncalibrated estimates. They are not measured accuracy or Jev probabilities, and cannot authorize model-only automatic quarantine. Its endpoint may be locally hosted or remote."));
    container.append(sectionHeading(actionReview ? "Initial verdict probabilities" : "Verdict probabilities", sectionJudgment ? "Selected section · relative probability" : output.score_semantics === "uncalibrated_model_estimates" ? "Custom model · estimated scores" : actionReview ? "Initial Jev stage · relative probability" : "Jev · relative probability"));
    const grid = el("div", "probability-grid");
    const probabilities = answers.verdict?.probabilities || {};
    for (const verdict of verdicts) append(grid, append(el("div", "probability-item"), append(el("div", "probability-top"), el("span", "", verdict), el("strong", "", percent(probabilities[verdict]))), bar(probabilities[verdict], verdict)));
    container.append(grid);
    container.append(sectionHeading(actionReview ? "Initial supporting judgments" : "Supporting judgments", "Probability of yes"));
    const signals = el("div", "signals");
    for (const [key, title] of [["deceptive_identity", "Deceptive identity"], ["requests_sensitive_action", "Requests a sensitive action"], ["hostile_destination_or_payload", "Hostile destination or payload"], ["business_context_anomaly", "Business-context anomaly"], ["callback_fraud", "Callback or refund fraud"], ["platform_content_abuse", "Abuse of hosted platform content"], ["execution_or_wallet_fraud", "Execution or wallet fraud"]]) {
      if (!Object.hasOwn(answers, key)) continue;
      const value = noulValue(answers[key]);
      signals.append(append(el("div", "signal-row"), el("span", "signal-label", title), bar(value), el("span", "signal-value", percent(value))));
    }
    container.append(signals);
    if (actionReview) container.append(el("p", "small-note initial-stage-note", "These judgments belong to the initial model stage. They may differ from the additional action and authority checks above; all original answers are retained."));
    if (["callback_fraud", "platform_content_abuse", "execution_or_wallet_fraud"].some(key => Object.hasOwn(answers, key))) container.append(el("p", "small-note", "These supporting model judgments describe the supplied evidence. The added fraud signals do not independently authorize quarantine."));
    if (answers.recommended_security_action) {
      const proposed = answers.recommended_security_action;
      const recommendation = el("section", "section-block");
      append(recommendation, sectionHeading(actionReview ? "Initial model action recommendation" : "Model action recommendation", `Proposed: ${label(proposed.choice)}`), el("p", "small-note", "A model recommendation does not execute a mailbox action. The policy gates and action ledger determine what happens."));
      const choices = el("div", "probability-grid");
      for (const choice of ["deliver", "junk", ...(Object.hasOwn(proposed.probabilities || {}, "review") ? ["review"] : []), "quarantine", "block"]) choices.append(append(el("div", "probability-item"), append(el("div", "probability-top"), el("span", "", choice), el("strong", "", percent(proposed.probabilities?.[choice]))), bar(proposed.probabilities?.[choice], choice)));
      recommendation.append(choices); container.append(recommendation);
    } else container.append(el("p", "small-note", "Historical run: business-context and action-recommendation judgments were not recorded. Earlier results are preserved without inventing new answers."));
    if (!reviewRequired && policy.model_verdict && policy.model_verdict !== decision) container.append(el("p", "control-caveat", `The policy verdict is ${label(decision)}; the model verdict was ${label(policy.model_verdict)}. Review the policy’s detection evidence and reasons below.`));
  }
  if (policy.recommended_action || policy.reasons?.length) {
    const reasons = el("div", "section-block");
    reasons.append(sectionHeading("Policy decision", modeName(policy.mode || "passive")));
    const list = el("div", "evidence-list");
    if (policy.recommended_action) list.append(append(el("div", "evidence-item"), el("strong", "", `Recommended: ${label(policy.recommended_action)}`), el("span", "", `Eligible under this run’s policy: ${label(policy.eligible_action || "none")}. Actual execution is recorded in the Actions tab.`)));
    for (const reason of policy.reasons || []) list.append(el("div", "evidence-item", display(reason)));
    if (policy.hard_detection) list.append(el("div", "evidence-item", "A structured signature or URL reputation detection met a hard-detection gate."));
    if (policy.semantic_quarantine_gate) {
      const basis = ({ identity_or_established_context: "Identity or established business context", sensitive_fraud_agreement: "Sensitive-action and protective-action agreement" })[policy.semantic_basis] || "Recorded model gate";
      list.append(append(el("div", "evidence-item"), el("strong", "", `Model policy basis: ${basis}`), el("span", "", "The recorded scores met this run’s model gate. These judgments come from the same model; agreement is not independent proof.")));
    }
    if (policy.inspection_incomplete) list.append(el("div", "evidence-item", "Inspection coverage was incomplete for this decision. Missing evidence is not a clean scan."));
    if (policy.evidence_refs?.length) list.append(append(el("div", "evidence-item"), el("strong", "", "Decision evidence references"), el("span", "evidence-value", policy.evidence_refs.join("\n"))));
    append(reasons, list); container.append(reasons);
  }
  renderInspection(container, evidence);
  const auth = evidence.authentication || {};
  const authSection = el("section", "section-block");
  renderAuthentication(authSection, auth);
  const identity = evidence.message || {};
  if (identity.sender?.domain || identity.reply_to || identity.return_path) {
    const list = el("div", "evidence-list");
    for (const [title, value] of [["Sender domain", identity.sender?.domain], ["Reply-to", identity.reply_to], ["Return-path", identity.return_path]]) if (value) list.append(append(el("div", "evidence-item"), el("strong", "", title), el("span", "evidence-value", displayAddress(value))));
    authSection.append(list);
  }
  container.append(authSection);
  const identityFindings = evidence.identity || {};
  if (identityFindings.identity_contradictions?.length || identityFindings.lookalike_domain || identityFindings.reply_to_mismatch) {
    const identitySection = el("section", "section-block");
    identitySection.append(sectionHeading("Identity findings", "Supplied evidence"));
    const list = el("div", "evidence-list");
    for (const finding of identityFindings.identity_contradictions || []) list.append(append(el("div", "evidence-item"), el("strong", "", label(finding.kind || "Identity contradiction")), el("span", "", finding.interpretation || display(finding))));
    if (identityFindings.lookalike_domain) list.append(el("div", "evidence-item", `Lookalike domain signal${identityFindings.lookalike_target ? `: ${identityFindings.lookalike_target}` : ""}. Inspect the supplied brand and domain evidence.`));
    if (identityFindings.reply_to_mismatch) list.append(el("div", "evidence-item", "The reply-to differs from the sender. A difference alone does not establish deceptive identity."));
    identitySection.append(list); container.append(identitySection);
  }
  renderLinks(container, evidence.links || []);
  renderAttachments(container, evidence.attachments || []);
  append(container, append(el("section", "section-block"), sectionHeading("Message preview", "Text only · external content disabled"), el("pre", "message-preview", messageBody(evidence))));
  if (evidence.quality && Object.keys(evidence.quality).length) container.append(rawDetails("Evidence completeness & limitations", evidence.quality));
  container.append(rawDetails("Normalized evidence", evidence));
  container.append(rawDetails("Model, policy & schema versions", run?.versions || state.status?.versions || {}));
  renderFeedbackForm(container, message);
}

function displayAddress(value) {
  if (Array.isArray(value)) return value.map(displayAddress).join(", ");
  if (typeof value === "object" && value !== null) return value.address || value.email || display(value);
  return display(value);
}
function renderLinks(container, links) {
  const section = el("section", "section-block");
  append(section, sectionHeading("Links & destinations", `${links.length} extracted · inert text`));
  if (!links.length) section.append(el("div", "evidence-empty", "No links were extracted from the supplied message."));
  else {
    const list = el("div", "evidence-list");
    for (const link of links) {
      const value = typeof link === "string" ? { url: link } : link;
      const item = el("div", "evidence-item");
      append(item, value.text || value.display_text ? el("strong", "", value.text || value.display_text) : null, el("div", "evidence-value", value.normalized_url || value.raw_url || value.url || value.href || value.original_url || display(value)), el("div", "", [value.domain || value.hostname, value.display_mismatch === true || value.text_domain_mismatch === true || value.display_domain_mismatch === true ? "Display / destination mismatch" : "", typeof value.reputation === "string" ? `Reputation ${value.reputation}` : value.reputation?.verdict || value.reputation?.status, value.affirmatively_malicious === true ? "Affirmative hostile evidence" : ""].filter(Boolean).join(" · ")));
      list.append(item);
    }
    append(section, list, el("p", "small-note", "URLs are shown as text. An unknown or unscanned destination alone is not evidence of hostility."));
  }
  container.append(section);
}
function renderAttachments(container, attachments) {
  const section = el("section", "section-block");
  append(section, sectionHeading("Attachments", `${attachments.length} extracted`));
  if (!attachments.length) section.append(el("div", "evidence-empty", "No attachments were extracted from the supplied message."));
  else {
    const list = el("div", "evidence-list");
    for (const item of attachments) {
      const bytes = item.size ?? item.size_bytes;
      const size = typeof bytes === "number" ? `${Math.round(bytes / 1024 * 10) / 10} KB` : "Size unavailable";
      append(list, append(el("div", "evidence-item"), el("strong", "", item.filename || item.name || "Unnamed attachment"), el("div", "", [item.detected_mime_type || item.declared_mime_type || item.content_type || item.mime_type, size, item.scan?.verdict || item.scan?.status || label(item.scan_status) || "No scan verdict supplied", item.affirmatively_malicious ? "Affirmative hostile evidence" : ""].filter(Boolean).join(" · ")), item.sha256 ? el("div", "evidence-value", `SHA-256 ${item.sha256}`) : null));
    }
    section.append(list);
  }
  container.append(section);
}
function renderMessage(container, evidence, message) {
  container.append(el("div", "safety-note", "Safe message view. Only extracted text is displayed. Message HTML, remote images, attachments, and links are never executed or opened here."));
  const meta = el("div", "evidence-list");
  for (const [title, value] of [["From", evidence.message?.sender?.address || message.from_address], ["To", evidence.message?.recipients], ["Reply-to", evidence.message?.reply_to], ["Subject", message.subject || evidence.message?.subject]]) if (value) meta.append(append(el("div", "evidence-item"), el("strong", "", title), el("span", "evidence-value", displayAddress(value))));
  container.append(meta);
  append(container, append(el("section", "section-block"), sectionHeading("Plaintext message", "Email content is untrusted"), el("pre", "email-body", messageBody(evidence))));
  container.append(rawDetails("Normalized source evidence", evidence));
}
function renderFeedbackForm(container, message) {
  const reviewedRun = latestRun();
  const reviewedRunId = reviewedRun?.status === "complete" ? reviewedRun.id : null;
  const form = el("form", "review-box"); form.id = "feedback-form";
  append(form, sectionHeading("Correct this classification", "Your reviewed verdict"), el("p", "", "Choose Clean, Spam, Suspicious, or Phishing. Your correction updates the console and its category counts; the original model result stays in the audit trail, including after replay."));
  const fields = el("div", "feedback-fields");
  const selectLabel = el("label", ""); append(selectLabel, el("span", "field-label", "Your verdict"));
  const select = el("select", ""); select.name = "verdict"; select.required = true;
  append(select, new Option("Select a verdict", ""), ...verdicts.map(verdict => new Option(label(verdict), verdict)));
  selectLabel.append(select);
  const reviewerLabel = el("label", ""); append(reviewerLabel, el("span", "field-label", "Reviewer (optional)"));
  const reviewer = el("input", ""); reviewer.name = "reviewer"; reviewer.placeholder = "Name or team"; reviewer.maxLength = 120; reviewerLabel.append(reviewer);
  append(fields, selectLabel, reviewerLabel); form.append(fields);
  const reasonLabel = el("label", "sr-only", "Review reason"); reasonLabel.htmlFor = "feedback-reason";
  const reason = el("textarea", ""); reason.name = "reason"; reason.id = "feedback-reason"; reason.placeholder = "What evidence supports your verdict?"; reason.maxLength = 4000; reason.required = true;
  select.value = message.verdict || "";
  const submit = el("button", "button primary", "Save correction"); submit.type = "submit";
  append(form, reasonLabel, reason);
  let gmailOptions = null;
  if (message.provider === "gmail" && !isEvaluation) {
    gmailOptions = gmailLabelOptions(form, message, {optional:true});
  }
  append(form, append(el("div", "review-footer"), el("span", "", "Gmail changes require the separate option above. A correction alone does not move or release mail."), submit));
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const chosen = select.value;
    if (!verdicts.includes(chosen) || !reason.value.trim()) return;
    const applyGmail = Boolean(gmailOptions?.apply.checked);
    const move = Boolean(gmailOptions?.move.checked && applyGmail);
    if (applyGmail && !await confirmAction("Save correction and change Gmail?", `${gmailLabelDescription(chosen, move)} Your console correction is saved first; Gmail completion is recorded separately in the action ledger.`, "Save and queue Gmail change")) return;
    submit.disabled = true;
    const id = message.id;
    let saved = false;
    try {
      await api(`/api/messages/${encodeURIComponent(id)}/feedback`, { method: "POST", body: JSON.stringify({ verdict: chosen, reason: reason.value.trim(), reviewer: reviewer.value.trim() || "analyst", run_id: reviewedRunId, apply_verdict:true }) });
      saved = true;
      if (applyGmail) await api(`/api/messages/${encodeURIComponent(id)}/gmail-label`, {method:"POST",body:JSON.stringify({verdict:chosen,move_to_label:move,idempotency_key:crypto.randomUUID()})});
      toast(applyGmail ? "Correction saved. Gmail change queued; check its recorded outcome." : "Classification corrected. Gmail was not changed.");
    } catch (error) { toast(`${saved ? "Correction saved; Gmail change was not confirmed as queued. " : ""}${error.message}`, true); }
    finally { submit.disabled = false; if (saved && state.selected === id) { state.keepSelection = true; state.tab = "actions"; await refresh({force:true}); } }
  });
  container.append(form);
}
function renderMessageActions(container, detail) {
  container.append(sectionHeading("Mailbox actions", "Execution is separate from model recommendations"));
  const actions = detail.actions || state.actions?.filter(action => action.message_id === detail.message?.id) || [];
  if (canRelease(actions, detail.message?.id)) container.append(el("p", "control-caveat quarantine-remains", "This message still has an active or unconfirmed quarantine action. Correcting it to Clean or changing its verdict label does not release quarantine. Use the release control below to restore only the Inbox state Mailsec previously removed; Manage access is required."));
  renderFeedbackForm(container, detail.message || {});
  if (detail.message?.provider === "gmail" && !isEvaluation) renderGmailLabelForm(container, detail.message);
  if (detail.message?.provider !== "gmail") container.append(el("p", "control-caveat", "This message was imported or generated as a demo. It is not a connected Gmail message, so mailbox actions are unavailable."));
  if (!actions.length) container.append(el("p", "evidence-empty", "No mailbox action is recorded for this message. A quarantine recommendation does not mean the message was moved."));
  for (const action of actions) container.append(actionCard(action, actions, false));
}
function gmailLabelDescription(verdict, move) {
  return `Apply Mailsec/${label(verdict)}, replace other Mailsec verdict labels, and clear Mailsec/Review. ${move ? "Remove it from Inbox so it appears under that label and in All Mail." : "Keep its current Inbox membership."} Existing Mailsec/Quarantine stays until an explicit release; unrelated Gmail labels are preserved. This does not use Gmail’s system Spam or Trash folders.`;
}
function gmailLabelOptions(container, message, {optional = false} = {}) {
  const access = mailboxWriteAccess(message.mailbox);
  const apply = el("input", ""); apply.type = "checkbox"; apply.name = "apply_gmail"; apply.checked = !optional; apply.disabled = !access.allowed;
  if (optional) container.append(append(el("label", "toggle-label"), apply, append(el("span", ""), el("strong", "", "Also apply the matching Gmail label"), el("small", "", "Replaces the Mailsec verdict label and clears Mailsec/Review. Existing quarantine requires a separate release. Gmail writes are recorded separately."))));
  const move = el("input", ""); move.type = "checkbox"; move.name = "move_to_label"; move.disabled = !access.allowed || !apply.checked;
  const moveLabel = append(el("label", "toggle-label"), move, append(el("span", ""), el("strong", "", "Move out of Inbox into this label"), el("small", "", "Optional. Gmail keeps the message in All Mail; it is not deleted. Undo restores only the state this manual action changed.")));
  apply.addEventListener("change", () => { move.disabled = !access.allowed || !apply.checked; if (move.disabled) move.checked = false; });
  container.append(moveLabel);
  if (!access.allowed) {
    container.append(el("p", "control-caveat", access.reason));
    container.append(manageAccessButton(message.mailbox));
  }
  return {apply, move, allowed:access.allowed};
}
function renderGmailLabelForm(container, message) {
  const form = el("form", "review-box gmail-label-form"); form.id = "gmail-label-form";
  append(form, sectionHeading("Organize this message in Gmail", "Manual mailbox change"), el("p", "", "Change Gmail labels without changing the console’s classification. To correct the classification too, use the form above. Manual changes are available in Passive mode when the account has Manage access."));
  const field = el("label", "control-label", "Gmail label"); field.htmlFor = "gmail-verdict-label";
  const select = el("select", "control-select"); select.id = "gmail-verdict-label"; select.required = true;
  append(select, new Option("Choose a Mailsec label", ""), ...verdicts.map(verdict => new Option(`Mailsec/${label(verdict)}`, verdict)));
  append(form, field, select);
  const options = gmailLabelOptions(form, message);
  select.disabled = !options.allowed;
  const submit = el("button", "button primary", "Queue Gmail label change"); submit.type = "submit"; submit.disabled = !options.allowed;
  form.append(submit);
  let requestKey = null;
  form.addEventListener("change", () => { requestKey = null; });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (!options.allowed || !verdicts.includes(select.value)) return;
    const chosen = select.value, move = options.move.checked;
    if (!await confirmAction("Change this message in Gmail?", gmailLabelDescription(chosen, move), "Queue Gmail change")) return;
    requestKey ||= crypto.randomUUID(); submit.disabled = true;
    try {
      await api(`/api/messages/${encodeURIComponent(message.id)}/gmail-label`, {method:"POST",body:JSON.stringify({verdict:chosen,move_to_label:move,idempotency_key:requestKey})});
      toast("Gmail change queued. It is applied only when the ledger confirms it.");
      await refresh({force:true});
    } catch (error) { toast(error.message,true); submit.disabled = false; }
  });
  container.append(form);
}
function renderHistory(container, detail) {
  container.append(sectionHeading("Analysis history", "Newest first · original results retained"));
  if (!detail.runs?.length) container.append(el("p", "evidence-empty", "No completed analysis is available yet."));
  for (const run of detail.runs || []) {
    const output = run.output || {}; const policy = run.policy || {};
    const card = el("article", "run-card");
    append(card, append(el("div", "run-header"), el("span", "", formatDate(run.created_at)), badge(run.status === "error" ? "error" : policy.verdict || output.answers?.verdict?.choice || run.status)), el("p", "", `Run ${run.id} · ${output.model || state.status?.model || "JEV"}`));
    if (run.error) card.append(el("p", "error-text", display(run.error)));
    if (output.usage) card.append(el("div", "run-usage", `Usage: ${Object.entries(output.usage).map(([key, value]) => `${label(key)} ${display(value)}`).join(" · ")}`));
    append(card, rawDetails("Recorded model output", output), rawDetails("Policy decision", policy), rawDetails("Versions & normalized evidence", { versions: run.versions || {}, evidence: run.evidence || {} }));
    container.append(card);
  }
  const section = el("section", "section-block"); section.append(sectionHeading("Analyst reviews", `${detail.feedback?.length || 0} recorded`));
  if (!detail.feedback?.length) section.append(el("p", "evidence-empty", "No analyst review has been recorded for this message."));
  for (const feedback of detail.feedback || []) {
    section.append(append(el("article", "feedback-card"), append(el("div", "run-header"), el("span", "", `${feedback.reviewer || "Analyst"} · ${formatDate(feedback.created_at)}`), badge(feedback.verdict)), el("p", "", feedback.reason || "No reason supplied.")));
  }
  container.append(section);
}

async function importFiles(files) {
  const accepted = [...files].filter(file => file.name.toLowerCase().endsWith(".eml") || file.type === "message/rfc822");
  if (!accepted.length) return toast("Choose an .eml email file to import.", true);
  if (accepted.length < files.length) toast("Only .eml email files were selected for import.");
  const button = $("#import-button"); button.disabled = true;
  let imported = 0, duplicates = 0, firstId = null;
  for (const file of accepted) {
    try {
      const body = new FormData(); body.append("file", file);
      const result = await api("/api/import", { method: "POST", body });
      if (result.duplicate) duplicates++; else imported++;
      if (!firstId) firstId = result.id;
    } catch (error) { toast(`${file.name}: ${error.message}`, true); }
  }
  button.disabled = false; $("#file-input").value = "";
  if (imported || duplicates) {
    toast([imported ? `${imported} ${imported === 1 ? "email" : "emails"} imported and queued.` : "", duplicates ? `${duplicates} already in the workspace.` : ""].filter(Boolean).join(" "));
    state.filter = ""; state.query = ""; state.offset = 0; $("#verdict-filter").value = ""; $("#search").value = "";
    if (firstId) { state.selected = firstId; state.detail = null; state.detailSignature = ""; state.tab = "assessment"; state.selectionEpoch += 1; }
    state.keepSelection = true; showView("review");
    await refresh({ force: true });
  }
}
async function analyzeDemo(button) {
  button.disabled = true; button.textContent = "Queueing demo emails…";
  try {
    await api("/api/demo", { method: "POST", body: "{}" });
    toast("Synthetic demo emails loaded. Analyses with your configured model are queued.");
    state.filter = ""; state.query = ""; state.offset = 0; $("#verdict-filter").value = ""; $("#search").value = "";
    showView("review");
    await refresh({ force: true });
  } catch (error) { toast(error.message, true); button.disabled = false; button.textContent = "Analyze demo emails"; }
}
async function replayMessage(button) {
  const id = state.selected;
  button.disabled = true; button.textContent = "Queueing…";
  try {
    await api(`/api/messages/${encodeURIComponent(id)}/replay`, { method: "POST", body: "{}" });
    toast("A new analysis is queued. Previous results remain in the audit trail.");
    await loadDetail(id, true);
  } catch (error) { toast(error.message, true); button.disabled = false; button.textContent = "↻  Replay analysis"; }
}

function currentMode() { return state.protection?.mode || state.status?.mode || "unknown"; }
function modeName(mode) { return ({ passive: "Passive mode", flag_only: "Flag only", auto_quarantine: "Automatic quarantine" })[mode] || "Policy unavailable"; }
function modeDescription(mode) { return ({ passive: "Analysis and recommendations; no automatic mailbox changes.", flag_only: "Eligible mail is flagged for review; no automatic quarantine.", auto_quarantine: "Eligible mail is labeled and removed from Inbox; it remains in All Mail." })[mode] || "Waiting for verified configuration."; }
function accountRows() { return state.accounts?.accounts || (Array.isArray(state.protection?.accounts) ? state.protection.accounts : state.protection?.accounts?.accounts) || []; }
function writableAccounts() { return accountRows().filter(account => account.connected && account.can_modify === true); }
function mailboxWriteAccess(mailbox) {
  const account = accountRows().find(item => item.mailbox?.toLowerCase() === mailbox?.toLowerCase());
  if (isEvaluation) return {allowed:false,reason:"Evaluation messages cannot change Gmail."};
  if (!account?.connected) return {allowed:false,reason:"This mailbox is not connected. Connect it with Manage access to change Gmail labels or Inbox membership."};
  if (account.can_modify !== true) return {allowed:false,reason:"This mailbox has read-only or unverified write access. Connect Manage access to label, move, release, or send quarantine notifications. Console corrections still work."};
  return {allowed:true,reason:""};
}
function manageAccessButton(mailbox) {
  const configured = state.accounts?.oauth_configured ?? state.protection?.services?.google_oauth?.configured ?? false;
  const known = accountRows().some(account => account.mailbox?.toLowerCase() === mailbox?.toLowerCase());
  const button = el("button", "button", configured && known ? "Connect Manage access" : "Open Gmail setup"); button.type = "button";
  button.addEventListener("click", () => configured && known ? beginConnect(mailbox, button, "manage") : showView("setup"));
  return button;
}
function readinessBlockers() {
  const supplied = [...(state.protection?.blockers || []), ...(state.accounts?.setup_blockers || [])].filter(value => typeof value === "string");
  if (state.status?.decision?.analysis_paused || state.status?.decision?.privacy?.blocking) supplied.unshift("Email analysis is paused. In Setup walkthrough → Decision model, review and accept the provider’s sharing disclosure, then save and allow analysis with your chosen settings.");
  if (!state.protection) supplied.push("Protection configuration could not be loaded.");
  if (!isEvaluation && !accountRows().some(account => account.connected)) supplied.push("No mailbox is connected. Connect an authorized account to start Gmail protection.");
  else if (!isEvaluation && !accountRows().some(account => account.connected && account.status === "connected" && !account.last_error)) supplied.push("Connected mailbox access needs attention. Review the account status below.");
  for (const account of accountRows()) if (account.last_error) supplied.push(`${account.mailbox}: ${account.last_error}`);
  if (!isEvaluation && ["flag_only", "auto_quarantine"].includes(currentMode())) {
    const restricted = accountRows().filter(account => account.connected && account.can_modify !== true);
    if (!writableAccounts().length) supplied.push("The selected protection policy is saved, but no connected mailbox has Manage access. Automatic labels, quarantine, and notifications cannot run yet.");
    else if (restricted.length) supplied.push(`${restricted.length} connected ${restricted.length === 1 ? "mailbox is" : "mailboxes are"} read-only. Automatic mailbox changes apply only to accounts with Manage access.`);
  }
  if (state.protection && !state.protection.services?.jev?.configured) supplied.push("Choose and test a decision provider in the setup walkthrough.");
  if (state.protection && !state.protection.services?.inspection?.configured) supplied.push("The attachment inspection service is not configured. Attachment scan coverage is unavailable.");
  return [...new Set(supplied)];
}
function statusTag(text, tone = "neutral") { return el("span", `status-tag ${["neutral", "warning", "danger", "confirmed"].includes(tone) ? tone : "neutral"}`, text); }
function statusTone(value) { return ["failed", "error", "malicious", "uncertain"].includes(value) ? "danger" : ["pending", "processing", "retry", "attention", "not_connected", "stale", "partial", "unavailable", "budget_exhausted"].includes(value) ? "warning" : "neutral"; }
function serviceStatus(key, service) {
  if (!service) return ["Status unavailable", "warning"];
  if (!service.configured) return ["Not configured", "warning"];
  if (key === "inspection") {
    if (service.reachable === false) return ["Configured · unavailable", "warning"];
    if (service.antivirus?.status === "stale") return ["Reachable · signatures stale", "warning"];
    if (service.antivirus && service.antivirus.status !== "ready") return ["Reachable · antivirus unavailable", "warning"];
    if (service.antivirus?.status === "ready") return ["Reachable · signatures current", "neutral"];
    if (service.ready === false) return ["Reachable · coverage needs attention", "warning"];
    if (service.reachable === true) return ["Reachable · check scan coverage", "neutral"];
  }
  return ["Configured · health not verified", "neutral"];
}
function confirmAction(title, description, acceptLabel) {
  const dialog = $("#confirm-dialog");
  if (dialog.open) return Promise.resolve(false);
  $("#confirm-title").textContent = title; $("#confirm-description").textContent = description; $("#confirm-accept").textContent = acceptLabel;
  return new Promise(resolve => {
    let settled = false;
    const finish = accepted => {
      if (settled) return; settled = true;
      $("#confirm-accept").removeEventListener("click", accept); $("#confirm-cancel").removeEventListener("click", cancel); dialog.removeEventListener("cancel", escape);
      dialog.close(); resolve(accepted);
    };
    const accept = () => finish(true);
    const cancel = () => finish(false);
    const escape = event => { event.preventDefault(); finish(false); };
    $("#confirm-accept").addEventListener("click", accept); $("#confirm-cancel").addEventListener("click", cancel); dialog.addEventListener("cancel", escape);
    dialog.showModal(); $("#confirm-cancel").focus();
  });
}
function renderProtection() {
  const container = $("#protection-view");
  if (state.policyDirty && $("#policy-form", container)) return;
  container.replaceChildren();
  const protection = state.protection;
  const grid = el("div", "control-grid");
  const policyCard = el("section", "control-card");
  append(policyCard, cardHeading("Protection policy", "Model recommendations pass through deterministic enforcement gates."));
  const form = el("form", "policy-form"); form.id = "policy-form";
  const modeLabel = el("label", "control-label", "Enforcement mode");
  const mode = el("select", "control-select"); mode.id = "enforcement-mode"; mode.name = "mode"; modeLabel.htmlFor = mode.id;
  append(mode, new Option("Select a mode", ""), new Option("Passive — analyze and recommend", "passive"), new Option("Flag only — label for review", "flag_only"), new Option("Automatic quarantine — eligible threats", "auto_quarantine"));
  mode.value = protection?.mode || ""; mode.disabled = !protection || isEvaluation;
  const explanation = el("p", "control-note", modeDescription(mode.value));
  const capability = el("p", "control-caveat protection-access", `${writableAccounts().length} connected ${writableAccounts().length === 1 ? "mailbox permits" : "mailboxes permit"} Gmail changes. ${writableAccounts().length ? "Read-only accounts remain monitoring-only regardless of the saved policy." : "Selecting a policy does not grant permission. Connect Manage access before expecting labels, quarantine, or notifications."}`);
  const notificationLabel = el("label", "toggle-label");
  const notifications = el("input", ""); notifications.type = "checkbox"; notifications.id = "notifications-enabled"; notifications.checked = Boolean(protection?.notifications_enabled); notifications.disabled = !protection || isEvaluation;
  append(notificationLabel, notifications, append(el("span", ""), el("strong", "", "Email action notifications"), el("small", "", "Send a summary to the affected mailbox after confirmed quarantine. Delivery status is recorded separately.")));
  const onChange = () => { state.policyDirty = true; explanation.textContent = modeDescription(mode.value); };
  mode.addEventListener("change", onChange); notifications.addEventListener("change", onChange);
  const submit = el("button", "button primary", isEvaluation ? "Evaluation: mailbox actions disabled" : "Save protection settings"); submit.type = "submit"; submit.disabled = !protection || isEvaluation;
  append(form, modeLabel, mode, explanation, capability, notificationLabel, el("p", "control-caveat", "Quarantine adds a Mailsec label and removes Inbox membership. Messages remain accessible in Gmail All Mail. This is reversible mailbox organization, not a restricted storage vault."), submit);
  form.addEventListener("submit", async event => {
    event.preventDefault(); if (!mode.value) return;
    const description = `${modeDescription(mode.value)} ${notifications.checked ? "Action notification emails will be enabled." : "Action notification emails will be disabled."} These settings affect future eligible Gmail actions; existing actions remain recorded.`;
    if (!await confirmAction("Update protection settings?", description, "Save settings")) return;
    submit.disabled = true;
    try {
      state.protection = await api("/api/protection", { method: "PATCH", body: JSON.stringify({ mode: mode.value, notifications_enabled: notifications.checked }) });
      state.policyDirty = false; toast("Protection settings saved."); renderProtection(); await refresh({ force: true });
    } catch (error) { toast(error.message, true); submit.disabled = false; }
  });
  policyCard.append(form);
  if (protection?.thresholds) {
    const thresholds = protection.thresholds;
    const fraudGate = numeric(thresholds.sensitive_fraud) !== null && numeric(thresholds.protective_action) !== null;
    const gates = append(el("div", "section-block"), sectionHeading("Automatic quarantine gates", "Configured model scores"));
    const facts = append(el("div", "facts-grid threshold-grid"), fact("Phishing probability", percent(thresholds.quarantine_phishing)), fact("Identity / context branch", percent(thresholds.corroboration), "Both sensitive action and identity/context"));
    if (fraudGate) append(facts, fact("Fraud: sensitive action", percent(thresholds.sensitive_fraud)), fact("Fraud: protective action", percent(thresholds.protective_action), "Probability of the chosen quarantine/block action"));
    append(gates, facts, el("p", "control-note", "The model gate requires a phishing verdict at the configured threshold and a quarantine/block recommendation, plus the identity/context branch" + (fraudGate ? " or both fraud-branch scores. The fraud branch does not require deceptive identity." : ".")), el("p", "control-note", "These are judgments from the same model; agreement is not independent proof. Stale reputation cannot qualify a model gate. Current signature or reputation detections can independently qualify. Unknown scans alone never establish maliciousness."));
    policyCard.append(gates);
  }
  const readiness = el("section", "control-card");
  const blockers = readinessBlockers();
  append(readiness, cardHeading("Readiness & limitations", "Configured credentials do not prove a service is currently healthy."));
  if (blockers.length) {
    readiness.append(statusTag(`${blockers.length} setup ${blockers.length === 1 ? "item" : "items"}`, "warning"));
    const list = el("ul", "blocker-list"); blockers.forEach(blocker => list.append(el("li", "", blocker))); readiness.append(list);
  } else readiness.append(el("p", "control-note", "No configuration blockers were reported. Inspect per-message coverage and recent action outcomes for runtime health."));
  const openAccounts = el("button", "button", "Manage mailbox connections"); openAccounts.addEventListener("click", () => showView("accounts")); if (!isEvaluation) readiness.append(openAccounts);
  for (const limitation of protection?.limitations || []) readiness.append(el("p", "control-note", display(limitation)));
  const services = el("section", "control-card control-wide");
  services.append(cardHeading("Evidence services", "Unavailable or stale evidence remains explicit in each assessment."));
  const serviceGrid = el("div", "service-grid");
  for (const [key, name, description] of [["jev", "Decision model", "Structured evidence judgments. Successful results and provider errors are recorded per run."], ["inspection", "Attachment inspection", "Signature scanning and bounded document, archive, HTML, and QR extraction."], ["url_reputation", "URL reputation", "Google Web Risk lookups. No known threat is not proof that a URL is safe."]]) {
    const service = protection?.services?.[key];
    const card = el("div", "service-card");
    append(card, el("h3", "", name), statusTag(...serviceStatus(key, service)), el("p", "", description));
    if (key === "jev" && service?.model) card.append(el("code", "", service.model));
    if (key === "inspection" && service?.antivirus?.signature_timestamp) card.append(el("small", "", `Signature database: ${formatDate(service.antivirus.signature_timestamp)}`));
    if (key === "url_reputation" && service?.monthly_limit != null) card.append(el("small", "", `Monthly lookup ceiling: ${Number(service.monthly_limit).toLocaleString()}`));
    if (service) card.append(rawDetails("Configuration details", service));
    serviceGrid.append(card);
  }
  services.append(serviceGrid);
  if (protection?.cache) services.append(rawDetails("Cache and lookup usage", protection.cache));
  append(grid, policyCard, readiness, services); container.append(grid);
}
function renderAccounts() {
  const container = $("#accounts-view"); container.replaceChildren(); append(container, accountControls());
}
function accountControls() {
  const wrapper = el("div", "account-controls");
  const accounts = accountRows();
  const configured = state.accounts?.oauth_configured ?? state.protection?.services?.google_oauth?.configured ?? false;
  const heading = cardHeading("Your authorized mailboxes", "Each Google account requires its own consent. Adding an address alone does not connect it.");
  wrapper.append(heading);
  const walkthrough = el("button", "button", "Open setup walkthrough"); walkthrough.addEventListener("click", () => window.mailsecSetup?.open(2)); wrapper.append(walkthrough);
  const grid = el("div", "account-grid");
  if (!accounts.length) grid.append(el("div", "control-card control-note", state.accounts ? "No mailboxes are configured yet. Use the setup walkthrough to add Gmail or Google Workspace accounts." : "Account status is unavailable. Restore the service connection before making account changes."));
  for (const account of accounts) {
    const card = el("section", "control-card account-card");
    const name = account.mailbox || "Unknown mailbox";
    const status = account.status || (account.connected ? "connected" : "not_connected");
    const statusNames = { not_connected: "Not connected", connected: "Connected", configured_unverified: "Configured · not verified", attention: "Needs attention" };
    append(card, el("span", "account-icon", "@"), el("h3", "account-address", name), statusTag(statusNames[status] || label(status), statusTone(status)), el("p", "control-note", account.connection_type ? `${label(account.connection_type)} connection` : "Google consent has not been completed for this mailbox."));
    if (account.last_verified_at) card.append(el("p", "control-note", `Account access last verified: ${formatDate(account.last_verified_at)}`));
    if (account.last_error) card.append(el("p", "error-text", account.last_error));
    const sync = (state.status?.mailboxes || []).find(item => item.mailbox === name) || account.sync;
    if (sync?.last_successful_poll) card.append(el("p", "control-note", `Last successful sync: ${formatDate(sync.last_successful_poll)}`));
    if (sync?.last_error) card.append(el("p", "error-text", `Sync: ${sync.last_error}`));
    if (sync?.sync_summary?.complete === false) card.append(el("p", "control-note", "Historical import is in progress. The next pass continues from the saved page; imported messages are queued for analysis."));
    if (sync?.sync_summary) card.append(rawDetails("Mailbox sync coverage", sync.sync_summary));
    const modeLabel = el("label", "control-note", "Gmail access");
    const accessMode = el("select", "account-access-mode"); accessMode.setAttribute("aria-label", `Gmail access for ${name}`);
    accessMode.append(new Option("Monitor only · read mail", "monitor"), new Option("Manage protection · labels and quarantine", "manage"));
    accessMode.value = account.access_mode || "monitor"; modeLabel.append(accessMode); card.append(modeLabel);
    if (account.connected) card.append(el("p", "control-note", account.can_modify !== true ? "Read-only or unverified write authorization. Mailbox labels, quarantine, release, and notification sends are disabled." : "Authorized for mailbox changes, subject to your protection policy and explicit manual requests."));
    const connect = el("button", "button primary", account.connected ? "Reconnect Google account" : "Connect Google account");
    connect.disabled = !configured || !account.mailbox;
    connect.addEventListener("click", () => beginConnect(account.mailbox, connect, accessMode.value));
    card.append(connect);
    if (account.can_disconnect) {
      const disconnect = el("button", "button", "Disconnect");
      disconnect.addEventListener("click", async () => {
        if (!await confirmAction("Disconnect this mailbox?", `Stop future access to ${name} and remove its stored authorization. Imported emails and analysis history remain on this server. You can also revoke the app in your Google Account.`, "Disconnect")) return;
        disconnect.disabled = true;
        try { await api("/api/accounts/disconnect", {method:"POST",body:JSON.stringify({mailbox:name})}); toast("Mailbox disconnected. Imported history is retained."); await refresh({force:true}); }
        catch(error) { toast(error.message,true); disconnect.disabled = false; }
      }); card.append(disconnect);
    }
    if (!configured) card.append(el("p", "control-note", "Connection is unavailable until the server’s Google OAuth setup is complete."));
    grid.append(card);
  }
  wrapper.append(grid);
  if (!configured) {
    const setup = el("section", "control-card setup-card");
    append(setup, cardHeading("Complete Google setup", "No Google Cloud project or credentials are supplied automatically."));
    const blockers = state.accounts?.setup_blockers || [];
    if (blockers.length) { const list = el("ul", "blocker-list"); blockers.forEach(value => list.append(el("li", "", display(value)))); setup.append(list); }
    const steps = el("ol", "setup-steps");
    for (const step of ["Create a Google Cloud project named Mailsec Personal Security and enable the Gmail API. Free personal Gmail and Google Workspace are supported.", "Configure the OAuth consent screen with app name Mailsec Personal Security. Choose an External audience for personal Gmail and add each authorized account as a test user while testing.", "Create a Web application OAuth client named Mailsec Self-Hosted. Register the browser’s exact console origin plus /oauth/google/callback: loopback HTTP is supported with an SSH tunnel; direct remote access requires HTTPS.", "Upload the client JSON and choose authorized mailboxes and the initial import range in the setup walkthrough. Credentials are encrypted on this server.", "Connect each mailbox with its owner’s consent. Monitor requests read-only Gmail access. Manage permits labels, reversible quarantine, release, and sending action notifications; the selected protection policy controls their use."]) steps.append(el("li", "", step));
    append(setup, steps, el("p", "control-note", "Google credentials belong in server configuration, never in this console’s token prompt. Authentication tokens are encrypted at rest using the separately configured key."));
    wrapper.append(setup);
  }
  wrapper.append(el("p", "control-caveat", state.accounts?.quarantine_limitation || "Gmail quarantine is a label and removal from Inbox. Messages remain accessible in All Mail. Releasing a message restores Inbox only if the original quarantine removed it."));
  return wrapper;
}
async function beginConnect(mailbox, button, accessMode = "monitor") {
  if (!await confirmAction("Connect this Google account?", `Continue to Google to authorize ${mailbox}. ${accessMode === "monitor" ? "Read-only access allows analysis without mailbox changes." : "Manage access allows reading mail, labels, reversible quarantine/release, and sending configured notifications. Google bundles these capabilities in its modify permission."} Selected email evidence is sent to your configured decision provider. The account is not connected until Google consent and server verification finish.`, "Continue to Google")) return;
  button.disabled = true;
  try {
    const result = await api("/api/accounts/connect", { method: "POST", body: JSON.stringify({ mailbox, access_mode: accessMode }) });
    const destination = new URL(result.authorization_url);
    if (destination.origin !== "https://accounts.google.com" || destination.pathname !== "/o/oauth2/v2/auth") throw new Error("The server returned an unexpected Google authorization destination.");
    if (state.view === "setup") sessionStorage.setItem("mailsec-setup-step", "3");
    window.location.assign(destination.href);
  } catch (error) { toast(error.message, true); button.disabled = false; }
}
function canRelease(actions, messageId, actionId) {
  const relevant = (actions || []).filter(action => action.message_id === messageId && (action.action === "quarantine" ? action.status === "applied" || Number(action.attempts) > 0 : action.action === "release" && !["failed", "cancelled"].includes(action.status)));
  return relevant.length > 0 && relevant[0].action === "quarantine" && (actionId == null || relevant[0].id === actionId);
}
function actionCard(action, allActions, showMessage = true) {
  const card = el("article", "ledger-card");
  const head = el("div", "ledger-header");
  append(head, append(el("div", ""), el("h3", "", label(action.action)), el("span", "", formatDate(action.updated_at || action.created_at))), statusTag(label(action.status || "unknown"), statusTone(action.status)));
  card.append(head);
  if (showMessage) {
    const open = el("button", "ledger-message text-button", action.subject || `Inspect message ${String(action.message_id || "").slice(0, 8)} →`);
    open.addEventListener("click", () => { state.keepSelection = true; showView("review"); selectMessage(action.message_id); }); card.append(open);
    card.append(el("p", "control-note", action.mailbox || "Mailbox not recorded"));
  }
  const descriptions = { quarantine: "Gmail quarantine label and Inbox removal. Message remains accessible in All Mail.", flag: "Gmail review label; Inbox membership is preserved.", clear_review: "A newer clean or spam analysis cleared Mailsec/Review. Other labels and Inbox membership were preserved.", release: "Mailsec labels removed. Inbox restored only if the original action removed it." };
  if (action.manual) {
    descriptions.manual_label = `${action.manual.label || "Mailsec verdict label"}${action.manual.move_to_label ? " and removal from Inbox" : "; Inbox membership preserved"}. Clears Mailsec/Review; existing quarantine remains until release. Explicit operator request; the original model analysis is unchanged.`;
    descriptions.manual_undo = "Undo the recorded manual label change. Only the affected labels and Inbox membership are restored; unrelated Gmail changes are preserved.";
  }
  card.append(el("p", "control-note", descriptions[action.action] || "See recorded action details."));
  const delivery = action.notification_status;
  append(card, append(el("div", "ledger-meta"), statusTag(`Notification: ${delivery ? label(delivery) : "Not queued"}`, statusTone(delivery)), el("span", "", `${Number(action.attempts) || 0} attempts`)));
  if (action.error) card.append(el("p", "error-text", action.error));
  if (delivery === "uncertain") {
    const resumed = action.notification_resolution === "resume_without_retry";
    card.append(el("p", "control-caveat", resumed ? "Notification delivery remains uncertain. An operator explicitly resumed mailbox scanning without a resend. This does not establish that the notification was delivered." : "Notification delivery is uncertain. It is not automatically resent, and mailbox polling is paused until delivery is reconciled or an operator explicitly resumes without resending."));
    if (action.notification_id) {
      const buttons = el("div", "ledger-buttons");
      const reconcile = el("button", "button", "Check notification delivery");
      reconcile.addEventListener("click", async () => {
        reconcile.disabled = true;
        try { await api(`/api/notifications/${encodeURIComponent(action.notification_id)}/reconcile`, { method: "POST", body: "{}" }); toast("Delivery check completed. Review the recorded notification status."); await refresh({ force: true }); }
        catch (error) { toast(error.message, true); reconcile.disabled = false; }
      });
      const abandon = el("button", "button", "Resume mailbox without resend");
      abandon.addEventListener("click", async () => {
        if (!await confirmAction("Resume without resending?", "Notification delivery will remain unconfirmed. This acknowledges unresolved delivery and permits mailbox polling to resume. Read-only reconciliation remains available. It does not send another email or undo the mailbox action; the original notification may already have been delivered.", "Resume without resend")) return;
        abandon.disabled = true;
        try { await api(`/api/notifications/${encodeURIComponent(action.notification_id)}/abandon`, { method: "POST", body: "{}" }); toast("Notification handling updated. Review its final status in the ledger."); await refresh({ force: true }); }
        catch (error) { toast(error.message, true); abandon.disabled = false; }
      });
      append(buttons, reconcile, resumed ? null : abandon); card.append(buttons);
    }
  }
  if (action.action === "quarantine" && canRelease(allActions, action.message_id, action.id)) {
    const uncertain = action.status !== "applied";
    if (uncertain) card.append(el("p", "control-caveat", "A quarantine attempt may have changed Gmail even though completion was not confirmed. Reconcile and release to remove any Mailsec labels and restore the recorded Inbox state."));
    const release = el("button", "button", uncertain ? "Reconcile and release" : "Release from quarantine"); release.disabled = !mailboxWriteAccess(action.mailbox).allowed; release.addEventListener("click", () => releaseMessage(action.message_id, release, uncertain)); card.append(release);
    if (release.disabled) { card.append(el("p", "control-note", "Release requires this mailbox’s Manage access.")); card.append(manageAccessButton(action.mailbox)); }
  }
  if (action.manual?.can_undo) {
    const undo = el("button", "button", "Undo manual Gmail change"); undo.disabled = !mailboxWriteAccess(action.mailbox).allowed;
    undo.addEventListener("click", async () => {
      if (!await confirmAction("Undo this manual Gmail change?", "Queue restoration of the Mailsec verdict/review labels and Inbox membership changed by this action. Unrelated Gmail labels are preserved. An intervening mailbox change can prevent undo; check the recorded outcome. The console correction and original analysis are not changed.", "Queue undo")) return;
      undo.disabled = true;
      try { await api(`/api/actions/${encodeURIComponent(action.id)}/undo`,{method:"POST",body:"{}"}); toast("Undo queued. Check the ledger for confirmation."); await refresh({force:true}); }
      catch(error) { toast(error.message,true); undo.disabled = false; }
    });
    card.append(undo);
    if (undo.disabled) { card.append(el("p", "control-note", "Undo requires this mailbox’s Manage access.")); card.append(manageAccessButton(action.mailbox)); }
  }
  card.append(rawDetails("Action audit record", action));
  return card;
}
function renderActionsView() {
  const container = $("#actions-view"); container.replaceChildren();
  const heading = cardHeading("Mailbox action ledger", "Execution and notification delivery are tracked independently. Records below are the latest 200 returned by the service.");
  const filter = el("select", "control-select action-filter"); filter.setAttribute("aria-label", "Filter action ledger");
  for (const [value, text] of [["all", "All actions"], ["quarantine", "Quarantine"], ["release", "Releases"], ["flag", "Flags"], ["clear_review", "Review cleared"], ["manual_label", "Manual labels"], ["manual_undo", "Manual undo"], ["attention", "Needs attention"]]) filter.append(new Option(text, value));
  filter.value = state.actionFilter; filter.addEventListener("change", () => { state.actionFilter = filter.value; renderActionsView(); }); heading.append(filter); container.append(heading);
  if (!state.actions) { container.append(el("div", "control-card control-note", "Action history is unavailable. Restore the service connection to inspect execution state.")); return; }
  const actions = state.actions.filter(action => state.actionFilter === "all" || (state.actionFilter === "attention" ? ["failed", "retry", "blocked"].includes(action.status) || action.notification_status === "uncertain" : action.action === state.actionFilter));
  if (!actions.length) container.append(el("div", "control-card control-note", "No recorded actions match this view. An analysis or model recommendation does not itself mean a mailbox change occurred."));
  const list = el("div", "ledger-grid"); actions.forEach(action => list.append(actionCard(action, state.actions))); container.append(list);
}
async function releaseMessage(id, button, uncertain = false) {
  const context = uncertain ? "The prior quarantine attempt may have changed Gmail without a confirmed response. " : "";
  if (!await confirmAction(uncertain ? "Reconcile and release this message?" : "Release this message?", `${context}This queues removal of the Mailsec quarantine and review labels. Inbox is restored only if the original quarantine removed it. The message is already accessible in Gmail All Mail. Release does not mark the content safe.`, "Queue release")) return;
  button.disabled = true;
  try { await api(`/api/messages/${encodeURIComponent(id)}/release`, { method: "POST", body: "{}" }); toast("Release queued. Check the action ledger for its outcome."); await refresh({ force: true }); }
  catch (error) { toast(error.message, true); button.disabled = false; }
}

function renderConnections() {
  const container = $("#connection-content");
  container.replaceChildren(accountControls());
}

$("#import-button").addEventListener("click", () => $("#file-input").click());
$("#file-input").addEventListener("change", event => importFiles(event.target.files));
$("#refresh-button").addEventListener("click", () => refresh({ reportError: true }));
$("#nav-overview").addEventListener("click", () => { showView("overview"); refresh(); });
$("#nav-inbox").addEventListener("click", () => { state.filter = ""; state.query = ""; state.offset = 0; state.keepSelection = false; showView("review"); $("#search").value = ""; $("#verdict-filter").value = ""; refresh({ force: true }); });
$("#verdict-filter").addEventListener("change", event => { state.filter = event.target.value; state.offset = 0; state.keepSelection = false; refresh({ force: true }); });
let searchTimer;
$("#search").addEventListener("input", event => { clearTimeout(searchTimer); state.query = event.target.value; state.offset = 0; state.keepSelection = false; searchTimer = setTimeout(() => refresh({ force: true }), 250); });
$$(".stat-card").forEach(card => card.addEventListener("click", () => { state.filter = state.filter === card.dataset.filter && state.view === "review" ? "" : card.dataset.filter; state.offset = 0; state.keepSelection = false; showView("review"); $("#verdict-filter").value = state.filter; refresh({ force: true }); }));
$("#previous-page").addEventListener("click", () => { state.offset = Math.max(0, state.offset - 200); state.keepSelection = false; refresh({ force: true }); });
$("#next-page").addEventListener("click", () => { state.offset += 200; state.keepSelection = false; refresh({ force: true }); });
$("#connection-button").addEventListener("click", () => { showView("accounts"); refresh(); });
$("#nav-protection").addEventListener("click", () => { showView("protection"); refresh(); });
$("#nav-actions").addEventListener("click", () => { showView("actions"); refresh(); });
$$(".close-dialog").forEach(button => button.addEventListener("click", () => $("#connections-dialog").close()));
$("#auth-form").addEventListener("submit", async event => {
  event.preventDefault(); accessToken = $("#access-token").value.trim();
  try { sessionStorage.setItem("mailsec-access-token", accessToken); } catch (_) { /* Continue without persistence. */ }
  $("#access-token").value = ""; $("#auth-dialog").close(); state.apiError = false;
  await refresh({ force: true, reportError: true });
});
let dragDepth = 0;
document.addEventListener("dragenter", event => { if ([...event.dataTransfer?.types || []].includes("Files")) { event.preventDefault(); dragDepth++; $("#drop-overlay").hidden = false; } });
document.addEventListener("dragover", event => { if ([...event.dataTransfer?.types || []].includes("Files")) { event.preventDefault(); event.dataTransfer.dropEffect = "copy"; } });
document.addEventListener("dragleave", event => { if (dragDepth > 0) { event.preventDefault(); dragDepth--; if (!dragDepth) $("#drop-overlay").hidden = true; } });
document.addEventListener("drop", event => { if (event.dataTransfer?.files?.length) { event.preventDefault(); dragDepth = 0; $("#drop-overlay").hidden = true; importFiles(event.dataTransfer.files); } });
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
$("#nav-overview").setAttribute("aria-label", "Mail overview");
$("#nav-inbox").setAttribute("aria-label", "Mail review");
renderList(); renderWelcome(); renderOverview(); refresh();
setInterval(() => { if (!document.hidden && !$("#auth-dialog").open) refresh(); }, 5000);

$('#workspace-select').addEventListener('change', event => {
  const path = event.target.value;
  if (!['/', '/evaluation/'].includes(path) || path === workspaceBase + '/') return;
  location.assign(path);
});
