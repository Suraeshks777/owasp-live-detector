function cssPath(el) {
  if (!(el instanceof Element)) return "";
  const parts = [];
  while (el && parts.length < 5) {
    let part = el.nodeName.toLowerCase();
    if (el.id) { part += `#${el.id}`; parts.unshift(part); break; }
    const cls = (el.className || "").toString().trim().split(/\s+/).filter(Boolean);
    if (cls.length) part += "." + cls.slice(0, 2).join(".");
    parts.unshift(part);
    el = el.parentElement;
  }
  return parts.join(" > ");
}

function isHttpUrl(u) {
  try { return new URL(u).protocol === "http:"; } catch { return false; }
}

function collectMixedContent() {
  const issues = [];
  const isHttps = location.protocol === "https:";
  if (!isHttps) return issues;

  const selectors = [
    ["script[src]", "src"],
    ["img[src]", "src"],
    ["iframe[src]", "src"],
    ["link[rel='stylesheet'][href]", "href"],
    ["audio[src], video[src], source[src]", "src"]
  ];

  for (const [sel, attr] of selectors) {
    document.querySelectorAll(sel).forEach((el) => {
      const val = el.getAttribute(attr);
      if (!val) return;
      const abs = new URL(val, location.href).toString();
      if (isHttpUrl(abs)) {
        issues.push({
          kind: "MIXED_CONTENT",
          element: el.tagName.toLowerCase(),
          attr,
          url: abs,
          evidence: cssPath(el)
        });
      }
    });
  }
  return issues;
}

function collectFormIssues() {
  const issues = [];
  document.querySelectorAll("form").forEach((form) => {
    const action = form.getAttribute("action") || location.href;
    const abs = new URL(action, location.href).toString();
    const method = (form.getAttribute("method") || "get").toLowerCase();

    const hasPassword = !!form.querySelector("input[type='password']");
    const isHttpsPage = location.protocol === "https:";
    if (isHttpsPage && isHttpUrl(abs)) {
      issues.push({
        kind: "FORM_POSTS_TO_HTTP",
        url: abs,
        method,
        evidence: cssPath(form)
      });
    }
    if (hasPassword && method === "get") {
      issues.push({
        kind: "PASSWORD_SENT_VIA_GET",
        evidence: cssPath(form)
      });
    }
    const pw = form.querySelector("input[type='password']");
    if (pw) {
      const ac = pw.getAttribute("autocomplete");
      if (!ac) {
        issues.push({
          kind: "PASSWORD_AUTOCOMPLETE_MISSING",
          evidence: cssPath(pw)
        });
      }
    }
  });
  return issues;
}

function collectUrlLeakage() {
  const issues = [];
  const hay = (location.search || "") + "&" + (location.hash || "");
  const patterns = [
    /access_token=/i,
    /id_token=/i,
    /\btoken=/i,
    /\bjwt=/i,
    /\bapikey=/i,
    /\bapi_key=/i,
    /\bsession=/i
  ];
  for (const p of patterns) {
    if (p.test(hay)) {
      issues.push({
        kind: "TOKEN_IN_URL",
        evidence: `URL contains sensitive-looking parameter matching ${p}`
      });
      break;
    }
  }
  return issues;
}

function collectDomXssSourceToSink() {
  const sources = [
    "location", "location.href", "location.search", "location.hash",
    "document.cookie", "localStorage", "sessionStorage",
    "postMessage", "event.data"
  ];
  const sinks = [
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "eval(", "new Function"
  ];

  const issues = [];
  document.querySelectorAll("script:not([src])").forEach((s) => {
    const code = (s.textContent || "");
    const sink = sinks.find(k => code.includes(k));
    if (!sink) return;

    const source = sources.find(k => code.includes(k));
    if (!source) return;

    issues.push({
      kind: "DOM_XSS_SOURCE_TO_SINK_INLINE",
      source,
      sink,
      evidence: cssPath(s)
    });
  });
  return issues;
}

function collectTabnabbing() {
  const issues = [];
  document.querySelectorAll("a[target='_blank']").forEach(a => {
    const rel = (a.getAttribute("rel") || "").toLowerCase();
    if (!rel.includes("noopener") || !rel.includes("noreferrer")) {
      issues.push({
        kind: "TABNABBING_RISK",
        href: a.getAttribute("href") || "",
        evidence: cssPath(a)
      });
    }
  });
  return issues;
}
function collectInlineHandlers() {
  const issues = [];
  const attrs = ["onclick","onload","onerror","onmouseover","onfocus","oninput","onsubmit"];
  const selector = attrs.map(a => `[${a}]`).join(",");
  document.querySelectorAll(selector).forEach(el => {
    const found = attrs.find(a => el.hasAttribute(a));
    issues.push({
      kind: "INLINE_EVENT_HANDLER",
      attr: found,
      evidence: cssPath(el)
    });
  });
  return issues;
}

function runAll() {
  return {
    url: location.href,
    origin: location.origin,
    protocol: location.protocol,
    ts: Date.now(),
    mixedContent: collectMixedContent(),
    formIssues: collectFormIssues(),
    urlLeakage: collectUrlLeakage(),
    domXssInline: collectDomXssSourceToSink(),
    tabnabbing: collectTabnabbing(),
    inlineHandlers: collectInlineHandlers()
  };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "RUN_CONTENT_AUDIT") {
    sendResponse({ ok: true, data: runAll() });
    return true;
  }
});
