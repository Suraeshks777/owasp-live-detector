const elTarget = document.getElementById("target");
const elSummary = document.getElementById("summary");
const elFindings = document.getElementById("findings");

document.getElementById("scan").addEventListener("click", scan);

function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

function originOf(urlStr) {
  try { return new URL(urlStr).origin; } catch { return ""; }
}

function protocolOf(urlStr) {
  try { return new URL(urlStr).protocol; } catch { return ""; }
}

function severityScore(sev) {
  return ({ Critical:4, High:3, Medium:2, Low:1, Info:0 })[sev] ?? 0;
}

function ruleFinding(f) {
  return f;
}

async function getActiveTabId() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs?.[0]?.id ?? null;
}

async function getTabState(tabId) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: "GET_TAB_STATE", tabId }, resp => {
      resolve(resp?.state || { requests: [], mainFrame: null });
    });
  });
}

async function runContentAudit(tabId) {
  return new Promise(resolve => {
    chrome.tabs.sendMessage(tabId, { type: "RUN_CONTENT_AUDIT" }, resp => {
      if (chrome.runtime.lastError) {
        resolve({ __error: chrome.runtime.lastError.message });
        return;
      }
      resolve(resp?.data || null);
    });
  });
}

function parseCsp(csp) {
  const out = {};
  (csp || "").split(";").map(x => x.trim()).filter(Boolean).forEach(part => {
    const [dir, ...vals] = part.split(/\s+/);
    out[(dir || "").toLowerCase()] = vals;
  });
  return out;
}

function analyzeHeaders(mainFrame) {
  const findings = [];
  if (!mainFrame?.headers) return findings;

  const h = mainFrame.headers;
  const url = mainFrame.url || "";
  const proto = protocolOf(url);

  if (proto === "http:") {
    findings.push(ruleFinding({
      id: "HTTP_IN_USE",
      title: "Site served over HTTP (no transport encryption)",
      severity: "High",
      owasp: "A02:2021 Cryptographic Failures",
      cwe: "CWE-319",
      evidence: `Main document URL uses HTTP: ${url}`,
      fix: "Serve the site over HTTPS and redirect HTTP to HTTPS."
    }));
  }

  if (proto === "https:" && !h["strict-transport-security"]) {
    findings.push(ruleFinding({
      id: "HSTS_MISSING",
      title: "HSTS missing",
      severity: "Medium",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-319",
      evidence: "Strict-Transport-Security header not present.",
      fix: "Add Strict-Transport-Security header."
    }));
  }

  const cspVal = h["content-security-policy"] || "";
  if (!cspVal) {
    findings.push(ruleFinding({
      id: "CSP_MISSING",
      title: "Content-Security-Policy missing",
      severity: "High",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-693",
      evidence: "No CSP header present.",
      fix: "Define a restrictive Content-Security-Policy."
    }));
  } else {
    const csp = parseCsp(cspVal);
    const scriptSrc = (csp["script-src"] || csp["default-src"] || []).join(" ");
    if (scriptSrc.includes("'unsafe-inline'") || scriptSrc.includes("'unsafe-eval'")) {
      findings.push(ruleFinding({
        id: "CSP_UNSAFE",
        title: "CSP allows unsafe-inline or unsafe-eval",
        severity: "High",
        owasp: "A05:2021 Security Misconfiguration",
        cwe: "CWE-693",
        evidence: cspVal,
        fix: "Remove unsafe-inline / unsafe-eval. Use nonces or hashes."
      }));
    }
  }

  if (!h["x-frame-options"] && !/frame-ancestors/i.test(cspVal)) {
    findings.push(ruleFinding({
      id: "CLICKJACKING_RISK",
      title: "No clickjacking protection",
      severity: "Medium",
      owasp: "A01:2021 Broken Access Control",
      cwe: "CWE-1021",
      evidence: "Missing X-Frame-Options and frame-ancestors.",
      fix: "Add frame-ancestors 'none' or X-Frame-Options: DENY."
    }));
  }

  if (!h["x-content-type-options"] || h["x-content-type-options"].toLowerCase() !== "nosniff") {
    findings.push(ruleFinding({
      id: "NOSNIFF_MISSING",
      title: "X-Content-Type-Options missing",
      severity: "Low",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-693",
      evidence: "x-content-type-options missing or incorrect.",
      fix: "Set X-Content-Type-Options: nosniff."
    }));
  }

  if (!h["referrer-policy"]) {
    findings.push(ruleFinding({
      id: "REFERRER_POLICY_MISSING",
      title: "Referrer-Policy missing",
      severity: "Low",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-200",
      evidence: "No Referrer-Policy header present.",
      fix: "Set Referrer-Policy: strict-origin-when-cross-origin."
    }));
  }

  if (!h["permissions-policy"]) {
    findings.push(ruleFinding({
      id: "PERMISSIONS_POLICY_MISSING",
      title: "Permissions-Policy missing",
      severity: "Low",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-693",
      evidence: "No Permissions-Policy header present.",
      fix: "Define a Permissions-Policy header."
    }));
  }

  return findings;
}

function analyzeContentAudit(contentAudit) {
  const findings = [];
  if (!contentAudit || contentAudit.__error) return findings;

  if ((contentAudit.formIssues || []).some(x => x.kind === "PASSWORD_AUTOCOMPLETE_MISSING")) {
    findings.push(ruleFinding({
      id: "PW_AUTOCOMPLETE",
      title: "Password input missing autocomplete",
      severity: "Info",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-16",
      evidence: "Password input has no autocomplete attribute.",
      fix: "Add autocomplete='current-password' or 'new-password'."
    }));
  }

  return findings;
}

function normalizeFindings(findings) {
  const byId = new Map();
  for (const f of findings) {
    const e = byId.get(f.id);
    if (!e || severityScore(f.severity) > severityScore(e.severity)) {
      byId.set(f.id, f);
    }
  }
  return Array.from(byId.values())
    .sort((a,b) => severityScore(b.severity) - severityScore(a.severity));
}

function renderSummary(findings) {
  const counts = { Critical:0, High:0, Medium:0, Low:0, Info:0 };
  for (const f of findings) counts[f.severity]++;

  elSummary.innerHTML = "";
  for (const k of ["Critical","High","Medium","Low","Info"]) {
    const div = document.createElement("div");
    div.className = "card";
    div.innerHTML = `<div class="k">${k}</div><div class="v">${counts[k] || 0}</div>`;
    elSummary.appendChild(div);
  }
}

function renderFindings(findings) {
  elFindings.innerHTML = "";

  if (!findings.length) {
    elFindings.innerHTML =
      `<div class="finding info">
        <div class="title">No findings 🎉</div>
      </div>`;
    return;
  }

  const order = ["Critical", "High", "Medium", "Low", "Info"];
  const groups = { Critical: [], High: [], Medium: [], Low: [], Info: [] };

  for (const f of findings) (groups[f.severity] || groups.Info).push(f);

  for (const sev of order) {
    const arr = groups[sev];
    if (!arr || !arr.length) continue;

    const sevClass = sev.toLowerCase();

    const section = document.createElement("div");
    section.className = "sevSection";
    section.innerHTML = `
      <div class="sevHeader ${sevClass}">
        <span class="sevDot ${sevClass}"></span>
        <span class="sevTitle">${escapeHtml(sev)}</span>
        <span class="sevCount">${arr.length}</span>
      </div>
      <div class="sevList"></div>
    `;

    const list = section.querySelector(".sevList");

    for (const f of arr) {
      const fClass = (f.severity || "Info").toLowerCase();
      const div = document.createElement("div");
      div.className = `finding ${fClass}`;

      div.innerHTML = `
        <div class="title">${escapeHtml(f.title)}
          <span class="badge ${fClass}">${escapeHtml(f.severity)}</span>
          <span class="badge">${escapeHtml(f.owasp)}</span>
        </div>
        <div class="meta"><b>ID:</b> ${escapeHtml(f.id)} • <b>CWE:</b> ${escapeHtml(f.cwe)}</div>
        <div class="meta"><b>Evidence</b></div>
        <pre>${escapeHtml(f.evidence || "")}</pre>
        <div class="meta"><b>Suggested fix</b></div>
        <pre>${escapeHtml(f.fix || "")}</pre>
      `;

      list.appendChild(div);
    }

    elFindings.appendChild(section);
  }
}

async function scan() {
  const tabId = await getActiveTabId();
  if (!tabId) return;

  const state = await getTabState(tabId);
  const contentAudit = await runContentAudit(tabId);

  const pageUrl = state.mainFrame?.url || contentAudit?.url || "";
  elTarget.textContent = originOf(pageUrl) || "(unknown)";

  let findings = [];
  findings = findings.concat(analyzeHeaders(state.mainFrame));
  findings = findings.concat(analyzeContentAudit(contentAudit));
  findings = normalizeFindings(findings);

  renderSummary(findings);
  renderFindings(findings);
}
