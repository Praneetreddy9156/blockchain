// AeroTrace Simple - the dashboard. Plain JavaScript, no build step.
// Every page asks the Python server (app.py) for data and shows it; all rules are enforced on the server.

const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (hash, n = 10) => (hash ? `${hash.slice(0, n)}…${hash.slice(-6)}` : "");
const num = (value) => Number(value).toLocaleString("en-GB");

const view = { page: "overview", state: null, blocks: [], passport: null, result: null, verify: null, tamper: null,
               docFileHash: null, docResult: null, registerCertificate: null };

const SCENARIOS = [
  { title: "Wrong role", text: "The regulator tries to register a part", member: "DAA", action: "REGISTER",
    data: { serial: "ATX-TEST-0001", description: "Test part", max_cycles: 1000, max_hours: 3000 } },
  { title: "Not the holder", text: "Northwind tries to record usage on TB90210", member: "NORTHWIND", action: "USAGE",
    data: { serial: "ATX-CFM56-TB90210", cycles: 10, hours: 20 } },
  { title: "Roll back the clock", text: "SkyLink enters -500 cycles", member: "SKYLINK", action: "USAGE",
    data: { serial: "ATX-CFM56-TB90210", cycles: -500, hours: 0 } },
  { title: "Reach the limit", text: "SkyLink adds 800 cycles (4,200 to 5,000)", member: "SKYLINK", action: "USAGE",
    data: { serial: "ATX-CFM56-TB90210", cycles: 800, hours: 500 } },
  { title: "Reuse a retired part", text: "Northwind tries to install TB90210", member: "NORTHWIND", action: "INSTALL",
    data: { serial: "ATX-CFM56-TB90210", aircraft: "NW-A320-DEMO5" } },
];

// ------------------------------------------------------------------ talking to the server
async function api(path, body) {
  const options = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
  return response.json();
}

// The certificate's fingerprint is made HERE, inside the browser, so the file is never uploaded.
async function sha256OfFile(file) {
  // 1. read the file's bytes, 2. let the browser's built-in Web Crypto compute SHA-256 (32 bytes)
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  // 3. write each byte as two hex characters -> the 64-character fingerprint that goes on the chain
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function refresh() {
  view.state = await api("/api/state");
  if (view.page === "ledger") view.blocks = await api("/api/blocks");
  renderTopbar();
  render();
}

// ------------------------------------------------------------------ small helpers
const memberName = (id) => view.state.members.find((m) => m.id === id)?.name ?? id;
const memberRole = (id) => view.state.members.find((m) => m.id === id)?.role ?? "";
const actor = () => $("#actor").value;
const part = (serial) => view.state.parts.find((p) => p.serial === serial);

function stateBadge(state) {
  const tone = { IN_STOCK: "sky", INSTALLED: "green", RETIRED: "red" }[state] || "";
  return `<span class="badge ${tone}">${esc(state.replace("_", " "))}</span>`;
}

function limitBar(used, limit, kind) {
  const pct = Math.min(100, (used / limit) * 100);
  return `<div class="small">${num(used)} / ${num(limit)} ${kind}</div><div class="bar"><span class="${kind}" style="width:${pct.toFixed(1)}%"></span></div>`;
}

function checksList(report) {
  return `<ul class="checks">${report.checks.map((c) => `<li><span class="mark ${c.passed ? "pass" : "fail"}">${c.passed ? "✓" : "✗"}</span>
    <code>${esc(c.name)}</code><span>${esc(c.description)}</span></li>`).join("")}</ul>`;
}

// ------------------------------------------------------------------ top bar
function renderTopbar() {
  const s = view.state;
  const pill = $("#chain-pill");
  pill.className = `pill ${s.valid ? "ok" : "bad"}`;
  pill.textContent = `${s.valid ? "Chain valid" : "Chain INVALID"} · ${s.blocks} blocks · ${s.tip.slice(0, 8)}`;
  const select = $("#actor");
  if (!select.options.length) {
    select.innerHTML = s.members.map((m) => `<option value="${m.id}">${esc(m.role)} · ${esc(m.name)}</option>`).join("");
    let saved = null;
    try { saved = localStorage.getItem("aerotrace-simple-actor"); } catch { /* storage may be blocked */ }
    select.value = saved && s.members.some((m) => m.id === saved) ? saved : "AEROWORKS";
  }
}

// ------------------------------------------------------------------ pages
function overviewPage() {
  const s = view.state;
  const steps = [
    ["Sign", "The member signs the record with its private Ed25519 key."],
    ["Check the rules", "The safety rules decide if the action is allowed."],
    ["Approve", `Each of the 5 peers re-checks and signs. ${s.policy.min_approvals} are needed, including the regulator.`],
    ["Seal a block", "Merkle root, block hash and the orderer's signature. Linked to the previous block."],
    ["Verify any time", "Anyone can re-check every hash, link and signature from block 0."],
  ];
  return `
  <section class="hero">
    <p class="eyebrow">Individual project · Blockchain Technology · simplified version</p>
    <h1>Every component has a history.<br>Make every handover verifiable.</h1>
    <p class="text">A small permissioned blockchain for aircraft parts. Every record is signed, approved by the member
      organisations, sealed in a hash-linked block and checked against safety rules written in code.</p>
    <div class="row"><a class="btn btn-accent" href="#actions">Try an action</a><a class="btn btn-light" href="#ledger">Verify the chain</a></div>
  </section>
  <div class="grid4" style="margin-top:20px">
    <div class="card card-pad stat"><p class="eyebrow">Parts registered</p><p class="value">${s.parts.length}</p></div>
    <div class="card card-pad stat"><p class="eyebrow">Blocks on the chain</p><p class="value">${s.blocks}</p></div>
    <div class="card card-pad stat"><p class="eyebrow">Chain integrity</p><p class="value" style="color:${s.valid ? "#15803D" : "#B91C1C"}">${s.valid ? "Valid" : "Invalid"}</p></div>
    <div class="card card-pad stat"><p class="eyebrow">Members</p><p class="value">${s.members.length}</p></div>
  </div>
  <section class="card card-pad" style="margin-top:20px">
    <p class="eyebrow">How a record is added</p><h2>Five steps for every action</h2>
    <ol class="steps">${steps.map(([t, d], i) => `<li><span class="num">${i + 1}</span><h3>${t}</h3><p>${d}</p></li>`).join("")}</ol>
  </section>
  <section class="card card-pad" style="margin-top:20px">
    <p class="eyebrow">The consortium</p><h2>Five members, one shared ledger</h2>
    <div class="grid5" style="margin-top:16px">${s.members.map((m) => `<div class="member"><h3>${esc(m.name)}</h3><span class="badge sky">${esc(m.role)}</span>
      <p class="small" style="margin-top:8px">${m.role === "REGULATOR" ? "Read-only. Its approval is required for every block." :
        Object.entries(s.actions).filter(([a]) => allowedFor(a, m.role)).map(([, label]) => label).join(" · ")}</p></div>`).join("")}</div>
  </section>`;
}

function allowedFor(action, role) {
  const roles = { REGISTER: ["OEM"], TRANSFER: ["OEM", "AIRLINE", "MRO"], INSTALL: ["AIRLINE"], REMOVE: ["AIRLINE"], USAGE: ["AIRLINE"] };
  return roles[action].includes(role);
}

function partsPage() {
  const s = view.state;
  const rows = s.parts.map((p) => `<tr>
      <td><span class="mono">${esc(p.serial)}</span><div class="small">${esc(p.description)}</div></td>
      <td>${esc(memberName(p.holder))}${p.aircraft ? `<div class="small">on ${esc(p.aircraft)}</div>` : ""}</td>
      <td>${stateBadge(p.state)}</td>
      <td>${limitBar(p.cycles, p.max_cycles, "cycles")}</td>
      <td>${limitBar(p.hours, p.max_hours, "hours")}</td>
      <td><button class="btn btn-secondary btn-sm" data-passport="${esc(p.serial)}">Passport</button></td></tr>`).join("");
  return `
  <header class="page-head"><p class="eyebrow">Parts</p><h1>Every part and its passport</h1>
    <p class="lead">The current state below is not stored separately: it is rebuilt by replaying every block from block 0.</p></header>
  <div class="card table-wrap"><table><thead><tr><th>Serial</th><th>Holder</th><th>State</th><th>Flight cycles</th><th>Flight hours</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>
  ${view.passport && part(view.passport) ? passportCard(part(view.passport)) : ""}`;
}

function passportCard(p) {
  return `<section class="card card-pad" style="margin-top:20px" id="passport">
    <p class="eyebrow">Part passport · back to birth</p><h2 class="mono" style="font-size:18px">${esc(p.serial)}</h2>
    <div class="grid2" style="margin-top:12px">
      <dl class="kv">
        <dt>Description</dt><dd>${esc(p.description)}</dd>
        <dt>Made by</dt><dd>${esc(memberName(p.maker))}</dd>
        <dt>Held by</dt><dd>${esc(memberName(p.holder))}</dd>
        <dt>State</dt><dd>${stateBadge(p.state)}${p.retired_reason ? `<div class="small">${esc(p.retired_reason)}</div>` : ""}</dd>
        <dt>Aircraft</dt><dd>${esc(p.aircraft || "-")}</dd>
        <dt>Certificate</dt><dd class="mono">${p.certificate ? esc(short(p.certificate, 16)) : "none"}</dd>
      </dl>
      <div>${limitBar(p.cycles, p.max_cycles, "cycles")}<div style="height:12px"></div>${limitBar(p.hours, p.max_hours, "hours")}
        <p class="small" style="margin-top:10px">Two separate limits, never added together. Reaching either one retires the part for good.</p></div>
    </div>
    <h3 style="margin-top:20px">History (every event is a signed, approved transaction in a block)</h3>
    <ol class="timeline">${p.history.map((h) => `<li><span class="badge sky">Block #${h.block}</span> <b>${esc(h.action)}</b>
      <div>${esc(h.summary)}</div><div class="small">${esc(h.timestamp)} · signed by ${esc(memberName(h.member))}</div></li>`).join("")}</ol>
  </section>`;
}

function actionsPage() {
  const s = view.state;
  return `
  <header class="page-head"><p class="eyebrow">Actions</p><h1>Sign and submit an action</h1>
    <p class="lead">You act as the organisation chosen at the top right. The server checks your role and every rule;
      if anything is wrong the action is rejected and nothing is written to the ledger.</p></header>
  <div class="grid2">
    <form class="card card-pad" id="action-form">
      <div class="field"><label class="label" for="act-type">Action</label>
        <select class="input" id="act-type">${Object.entries(s.actions).map(([a, label]) => `<option value="${a}">${esc(label)}</option>`).join("")}</select></div>
      <div id="act-fields"></div>
      <p class="hint" style="margin-top:14px">Acting as <b>${esc(memberName(actor()))}</b> (${esc(memberRole(actor()))}).</p>
      <div class="row" style="margin-top:14px"><button class="btn btn-primary" type="submit">Sign and submit</button></div>
    </form>
    <div class="stack">
      ${view.result ? resultCard(view.result) : `<div class="card card-pad muted">The result of your action will appear here.</div>`}
      <section class="card card-pad"><p class="eyebrow">Try it</p><h2>One-click demonstrations</h2>
        ${SCENARIOS.map((sc, i) => `<div class="scenario"><div><b>${esc(sc.title)}</b><div class="small">${esc(sc.text)}</div></div>
          <button class="btn btn-secondary btn-sm" type="button" data-scenario="${i}">Run</button></div>`).join("")}
      </section>
    </div>
  </div>`;
}

function fieldsFor(action) {
  const s = view.state;
  const parts = s.parts.map((p) => `<option value="${esc(p.serial)}">${esc(p.serial)} (${esc(p.state.replace("_", " ").toLowerCase())})</option>`).join("");
  const partField = `<div class="field"><label class="label" for="f-serial">Part</label><select class="input" id="f-serial">${parts}</select></div>`;
  if (action === "REGISTER") return `
    <div class="field"><label class="label" for="f-serial">New serial number</label><input class="input mono" id="f-serial" placeholder="ATX-DEMO-0001"></div>
    <div class="field"><label class="label" for="f-description">Description</label><input class="input" id="f-description" placeholder="Fan blade set"></div>
    <div class="grid2"><div class="field"><label class="label" for="f-max-cycles">Cycle limit</label><input class="input" id="f-max-cycles" type="number" value="5000"></div>
      <div class="field"><label class="label" for="f-max-hours">Hour limit</label><input class="input" id="f-max-hours" type="number" value="20000"></div></div>
    <div class="field"><label class="label" for="f-cert">Certificate file (optional)</label><input class="input" id="f-cert" type="file">
      <p class="hint" id="f-cert-hash">Only its SHA-256 fingerprint goes on the chain; the file stays on your computer.</p>
      <p class="hint">Sample to try: <a href="/samples/new_part_certificate.pdf" download>new_part_certificate.pdf</a> (for ATX-DEMO-0001)</p></div>`;
  if (action === "TRANSFER") return partField + `<div class="field"><label class="label" for="f-to">Transfer to</label>
    <select class="input" id="f-to">${s.members.filter((m) => m.id !== actor()).map((m) => `<option value="${m.id}">${esc(m.name)}</option>`).join("")}</select></div>`;
  if (action === "INSTALL") return partField + `<div class="field"><label class="label" for="f-aircraft">Aircraft registration</label>
    <input class="input mono" id="f-aircraft" placeholder="SL-A320-DEMO2"></div>`;
  if (action === "USAGE") return partField + `<div class="grid2"><div class="field"><label class="label" for="f-cycles">Flight cycles to add</label>
    <input class="input" id="f-cycles" type="number" value="100"></div><div class="field"><label class="label" for="f-hours">Flight hours to add</label>
    <input class="input" id="f-hours" type="number" value="250"></div></div>`;
  return partField;  // REMOVE
}

function resultCard(r) {
  if (!r.ok) return `<div class="result bad"><p class="title">REJECTED by ${esc(r.rule)}</p><p>${esc(r.message)}</p>
    <p class="small">Nothing was written to the ledger. The chain still has ${view.state.blocks} blocks.</p></div>`;
  return `<div class="result ok"><p class="title">ACCEPTED · added in block #${r.block}</p><p>${esc(r.message)}</p>
    <dl class="kv"><dt>Block hash</dt><dd class="mono">${esc(short(r.block_hash, 16))}</dd>
      <dt>Merkle root</dt><dd class="mono">${esc(short(r.merkle_root, 16))}</dd>
      <dt>Approved by</dt><dd><div class="chips">${r.approvals.map((a) => `<span class="badge green">✓ ${esc(a)}</span>`).join("")}</div>
        <div class="small" style="margin-top:6px">${view.state.policy.min_approvals} of 5 needed, including the regulator.</div></dd></dl></div>`;
}

function documentsPage() {
  const withCert = view.state.parts.filter((p) => p.certificate);
  const r = view.docResult;
  return `
  <header class="page-head"><p class="eyebrow">Documents</p><h1>Is this certificate the original?</h1>
    <p class="lead">Certificates stay off the chain. Only their SHA-256 fingerprint is stored in the part's birth record.
      Change one byte of the file and the fingerprint no longer matches.</p></header>
  <div class="grid2">
    <div class="card card-pad">
      <div class="field"><label class="label" for="d-serial">Part</label><select class="input" id="d-serial">
        ${withCert.map((p) => `<option value="${esc(p.serial)}" ${p.serial === view.docSerial ? "selected" : ""}>${esc(p.serial)}</option>`).join("")}</select></div>
      <div class="field"><label class="label" for="d-file">File to check</label><input class="input" id="d-file" type="file">
        <p class="hint mono">${view.docFileHash ? `SHA-256: ${esc(view.docFileHash)}` : "The fingerprint is computed in your browser; the file is not uploaded."}</p></div>
      <div class="row" style="margin-top:14px"><button class="btn btn-primary" id="d-check" ${view.docFileHash ? "" : "disabled"}>Compare with the ledger</button></div>
      <p class="small" style="margin-top:16px">Sample files: <a href="/samples/certificate_original.pdf" download>original certificate</a> ·
        <a href="/samples/certificate_altered.pdf" download>altered copy (one character changed)</a></p>
      <p class="small" style="margin-top:4px">For ATX-DEMO-0001 (after you register it with its certificate):
        <a href="/samples/new_part_certificate.pdf" download>certificate</a> ·
        <a href="/samples/new_part_certificate_altered.pdf" download>altered copy (one character changed)</a></p>
    </div>
    <div>${!r ? `<div class="card card-pad muted">The comparison will appear here.</div>` : !r.ok ? `<div class="result bad"><p>${esc(r.message)}</p></div>` :
      `<div class="result ${r.match ? "ok" : "bad"}"><p class="title">${r.match ? "MATCH - the file is exactly the anchored original" : "MISMATCH - the file has been changed"}</p>
       <dl class="kv"><dt>On the ledger</dt><dd class="mono">${esc(r.on_chain)}</dd><dt>This file</dt><dd class="mono">${esc(r.file)}</dd>
       <dt>Bits different</dt><dd><b>${r.bits_different}</b> of 256</dd></dl>
       <p class="small">A match proves the bytes are unchanged. It does not prove that the physical part is genuine.</p></div>`}</div>
  </div>`;
}

function ledgerPage() {
  const t = view.tamper;
  const failed = (report) => report.checks.filter((c) => !c.passed).map((c) => `<span class="badge red">✗ ${esc(c.name)}</span>`).join("") || `<span class="badge green">all checks pass</span>`;
  return `
  <header class="page-head"><p class="eyebrow">Ledger</p><h1>The chain of blocks</h1>
    <p class="lead">Each block stores the hash of the block before it, a Merkle root of its transactions and the orderer's signature.</p></header>
  <div class="row"><button class="btn btn-primary" id="l-verify">Verify the whole chain</button>
    <button class="btn btn-secondary" id="l-tamper">Run the tamper test</button>
    <button class="btn btn-danger" id="l-reset">Reset demo data</button></div>
  <div class="grid2" style="margin-top:20px">
    <div class="card card-pad"><p class="eyebrow">Verification</p>
      ${view.verify ? `<h2 style="color:${view.verify.valid ? "#15803D" : "#B91C1C"}">${view.verify.valid ? "Chain valid" : "Chain INVALID"} · ${view.verify.blocks} blocks</h2>${checksList(view.verify)}`
        : `<p class="muted">Press "Verify the whole chain" to re-check every hash, link and signature from block 0.</p>`}</div>
    <div class="card card-pad"><p class="eyebrow">Tamper test (on a copy; the real chain is never changed)</p>
      ${!t ? `<p class="muted">Rewrites a usage record to make a part look younger, then tries to cover it up by recomputing every hash.</p>`
        : !t.ok ? `<p>${esc(t.message)}</p>` : `<h2>Block #${t.block}: ${esc(t.change)}</h2>
        <h3 style="margin-top:14px">1. After the edit</h3><div class="chips">${failed(t.after_edit)}</div>
        <h3 style="margin-top:14px">2. After recomputing every hash (the cover-up)</h3><div class="chips">${failed(t.after_cover_up)}</div>
        <p class="small" style="margin-top:12px">The hash checks pass again after the cover-up, but the signatures cannot be forged without the private keys.</p>`}</div>
  </div>
  <h2 style="margin:28px 0 12px">Blocks (newest first)</h2>
  ${view.blocks.map((b) => { const tx = b.transactions[0]; return `<div class="card block">
    <div class="row" style="justify-content:space-between"><h3>Block #${b.index} · ${esc(tx.action)}</h3><span class="small">${esc(b.timestamp)}</span></div>
    <dl class="kv"><dt>By</dt><dd>${esc(memberName(tx.member))}${tx.data.serial ? ` · <span class="mono">${esc(tx.data.serial)}</span>` : ""}</dd>
      <dt>Block hash</dt><dd class="mono">${esc(b.hash)}</dd><dt>Previous hash</dt><dd class="mono">${esc(b.previous_hash)}</dd>
      <dt>Merkle root</dt><dd class="mono">${esc(b.merkle_root)}</dd>
      <dt>Approvals</dt><dd>${tx.action === "GENESIS" ? "genesis block: members, public keys and the approval policy" : `${tx.approvals.length} of 5 peers`}</dd></dl></div>`; }).join("")}`;
}

// ------------------------------------------------------------------ rendering and events
function render() {
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === view.page));
  const pages = { overview: overviewPage, parts: partsPage, actions: actionsPage, documents: documentsPage, ledger: ledgerPage };
  $("#page").innerHTML = (pages[view.page] || overviewPage)();
  if (view.page === "actions") showFields();
}

function showFields() {
  const type = $("#act-type");
  if (view.lastAction) type.value = view.lastAction;
  $("#act-fields").innerHTML = fieldsFor(type.value);
  view.registerCertificate = null;
}

function collect(action) {
  const value = (id) => $(id)?.value ?? "";
  const int = (id) => (value(id) === "" ? null : parseInt(value(id), 10));
  const float = (id) => (value(id) === "" ? null : parseFloat(value(id)));
  if (action === "REGISTER") return { serial: value("#f-serial").trim().toUpperCase(), description: value("#f-description").trim(),
    max_cycles: int("#f-max-cycles"), max_hours: float("#f-max-hours"), certificate: view.registerCertificate };
  const data = { serial: value("#f-serial") };
  if (action === "TRANSFER") data.to = value("#f-to");
  if (action === "INSTALL") data.aircraft = value("#f-aircraft").trim().toUpperCase();
  if (action === "USAGE") { data.cycles = int("#f-cycles"); data.hours = float("#f-hours"); }
  return data;
}

async function submit(member, action, data) {
  view.result = await api("/api/action", { action, member, data });
  view.lastAction = action;
  await refresh();
}

document.addEventListener("click", async (event) => {
  const target = event.target.closest("button");
  if (!target) return;
  if (target.dataset.passport) {
    view.passport = target.dataset.passport;
    render();
    $("#passport")?.scrollIntoView({ behavior: "smooth" });
  } else if (target.dataset.scenario !== undefined) {
    const sc = SCENARIOS[Number(target.dataset.scenario)];
    $("#actor").value = sc.member;
    await submit(sc.member, sc.action, sc.data);
  } else if (target.id === "d-check") {
    view.docSerial = $("#d-serial").value;  // remember the chosen part, so redrawing the page keeps it selected
    view.docResult = await api("/api/check-document", { serial: view.docSerial, sha256: view.docFileHash });
    render();
  } else if (target.id === "l-verify") {
    view.verify = await api("/api/verify", {});
    render();
  } else if (target.id === "l-tamper") {
    view.tamper = await api("/api/tamper-test", {});
    render();
  } else if (target.id === "l-reset") {
    if (!confirm("Delete all demo data and start again from a fresh chain?")) return;
    await api("/api/reset", {});
    Object.assign(view, { result: null, verify: null, tamper: null, docResult: null, docFileHash: null, docSerial: null, passport: null });
    await refresh();
  }
});

document.addEventListener("submit", async (event) => {
  if (event.target.id !== "action-form") return;
  event.preventDefault();
  const action = $("#act-type").value;
  await submit(actor(), action, collect(action));
});

document.addEventListener("change", async (event) => {
  const id = event.target.id;
  if (id === "act-type") { view.lastAction = event.target.value; showFields(); }
  else if (id === "actor") {
    try { localStorage.setItem("aerotrace-simple-actor", actor()); } catch { /* storage may be blocked */ }
    render();
  } else if (id === "f-cert" && event.target.files[0]) {
    view.registerCertificate = await sha256OfFile(event.target.files[0]);
    $("#f-cert-hash").textContent = `SHA-256: ${view.registerCertificate}`;
  } else if (id === "d-file" && event.target.files[0]) {
    view.docFileHash = await sha256OfFile(event.target.files[0]);
    view.docResult = null;
    view.docSerial = $("#d-serial").value;
    render();
  } else if (id === "d-serial") {
    view.docSerial = event.target.value;
  }
});

window.addEventListener("hashchange", async () => {
  view.page = location.hash.slice(1) || "overview";
  if (view.page === "ledger") view.blocks = await api("/api/blocks");
  render();
  window.scrollTo(0, 0);
});

view.page = location.hash.slice(1) || "overview";
refresh().catch((error) => { $("#page").innerHTML = `<div class="result bad"><p class="title">Cannot reach the server</p><p>${esc(error.message)}</p></div>`; });
