const BACKEND = 'http://127.0.0.1:5000'; // use 127.0.0.1 to avoid possible localhost/IPv6 issues
const PHISHING_THRESHOLD = 0.7;         // change threshold here

// helper for backend call
async function fetchPrediction(url) {
  console.log('[BG] fetchPrediction ->', url);
  try {
    const r = await fetch(`${BACKEND}/predict`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url})
    });
    console.log('[BG] fetch status', r.status);
    if (!r.ok) {
      const text = await r.text().catch(()=>null);
      console.error('[BG] backend error', r.status, text);
      return { error: 'backend error', status: r.status, body: text };
    }
    const json = await r.json();
    console.log('[BG] backend json', json);

    const score = (typeof json.score === 'number') ? json.score : null;
    json.is_phishing = score !== null ? (score >= PHISHING_THRESHOLD) : false;
    json.phishing_threshold_used = PHISHING_THRESHOLD;
    return json;
  } catch (err) {
    console.error('[BG] fetch exception', err);
    return { error: err.message };
  }
}

// message handler from popup / content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'check_url') {
    fetchPrediction(msg.url).then(resp => sendResponse(resp));
    return true; // will respond async
  }

  if (msg.action === 'add_url') {
    const key = msg.list === 'whitelist' ? 'whitelist' : 'blacklist';
    chrome.storage.local.get([key], (data) => {
      const arr = data[key] || [];
      if (!arr.includes(msg.url)) arr.push(msg.url);
      chrome.storage.local.set({[key]: arr}, () => {
        sendResponse({message: `${msg.url} added to ${key}`});
      });
    });
    return true;
  }

  return false;
});

// Optional: automatically check on tab update and show console log (can be extended to notifications)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // only run when URL completes load
  if (changeInfo.status === 'complete' && tab.active) {
    // you could call fetchPrediction(tab.url) and maybe show a browser notification
    // We'll not spam the user; leave commented for future use.
    // fetchPrediction(tab.url).then(resp => console.log('Auto-check', tab.url, resp));
  }
});
