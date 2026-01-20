const tabState = new Map();

function ensureTab(tabId) {
  if (!tabState.has(tabId)) {
    tabState.set(tabId, { mainFrame: null, requests: [] });
  }
  return tabState.get(tabId);
}
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== "main_frame") return;
    if (details.tabId < 0) return;

    const st = ensureTab(details.tabId);
    const headers = {};
    for (const h of details.responseHeaders || []) {
      if (!h.name) continue;
      headers[h.name.toLowerCase()] = h.value || "";
    }

    st.mainFrame = {
      url: details.url,
      statusCode: details.statusCode,
      headers
    };
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const st = ensureTab(details.tabId);
    st.requests.push({ url: details.url, type: details.type });
    if (st.requests.length > 300) st.requests.shift();
  },
  { urls: ["<all_urls>"] }
);
chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId !== 0) return;
  tabState.set(d.tabId, { mainFrame: null, requests: [] });
});
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "GET_TAB_STATE") {
    sendResponse({
      ok: true,
      state: tabState.get(msg.tabId) || { mainFrame: null, requests: [] }
    });
    return true;
  }
});
