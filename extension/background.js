const BACKEND = 'http://127.0.0.1:5000'; // use 127.0.0.1 to avoid possible localhost/IPv6 issues
const PHISHING_THRESHOLD = 0.7;         // change threshold here

function normalizeEntry(input) {
  const raw = (typeof input === 'string' ? input : '').trim();
  if (!raw) return '';

  // try to parse as URL and extract hostname
  try {
    const u = new URL(raw.includes('://') ? raw : `http://${raw}`);
    const host = (u.hostname || '').toLowerCase().trim();
    if (host) return host;
  } catch {}

  // fallback: normalize string
  return raw.toLowerCase();
}

function getHostname(url) {
  try {
    const u = new URL(url);
    return (u.hostname || '').toLowerCase().trim();
  } catch {
    // try best-effort parse for raw hosts
    try {
      const u = new URL(url.includes('://') ? url : `http://${url}`);
      return (u.hostname || '').toLowerCase().trim();
    } catch {
      return '';
    }
  }
}

// quick domain / substring based lists using extension storage
function checkLocalLists(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['whitelist', 'blacklist'], (data) => {
      const wl = (data.whitelist || []).map(normalizeEntry).filter(Boolean);
      const bl = (data.blacklist || []).map(normalizeEntry).filter(Boolean);

      const fullUrl = (typeof url === 'string' ? url : '').toLowerCase();
      const host = getHostname(fullUrl);

      // whitelist match: exact host or subdomain or raw substring
      if (
        wl.some((entry) => {
          if (!entry) return false;
          if (host && (host === entry || host.endsWith(`.${entry}`))) return true;
          return fullUrl.includes(entry);
        })
      ) {
        return resolve({ list: 'whitelist' });
      }

      // blacklist match: exact host or subdomain or raw substring
      if (
        bl.some((entry) => {
          if (!entry) return false;
          if (host && (host === entry || host.endsWith(`.${entry}`))) return true;
          return fullUrl.includes(entry);
        })
      ) {
        return resolve({ list: 'blacklist' });
      }

      resolve({ list: null });
    });
  });
}

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
    checkLocalLists(msg.url).then((res) => {
      if (res.list === 'whitelist') {
        // force-safe response
        return sendResponse({
          score: 0.0,
          is_phishing: false,
          from_list: 'whitelist',
          parameter_scores: {},
          model_uncertainty: 0.0,
        });
      }
      if (res.list === 'blacklist') {
        // force-danger response
        return sendResponse({
          score: 1.0,
          is_phishing: true,
          from_list: 'blacklist',
          parameter_scores: {},
          model_uncertainty: 0.0,
        });
      }
      // normal backend prediction
      fetchPrediction(msg.url).then((resp) => sendResponse(resp));
    });
    return true; // will respond async
  }

  if (msg.action === 'add_url') {
    const key = msg.list === 'whitelist' ? 'whitelist' : 'blacklist';
    const entry = normalizeEntry(msg.url);
    if (!entry) {
      sendResponse({ message: 'No URL/domain provided' });
      return false;
    }
    chrome.storage.local.get([key], (data) => {
      const arr = data[key] || [];
      if (!arr.includes(entry)) arr.push(entry);
      chrome.storage.local.set({[key]: arr}, () => {
        sendResponse({message: `${entry} added to ${key}`});
      });
    });
    return true;
  }

  return false;
});

// Automatically check active tab when it finishes loading and notify content script
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.active && tab.url) {
    checkLocalLists(tab.url).then((res) => {
      if (res.list === 'whitelist') {
        chrome.tabs.sendMessage(tabId, {
          action: 'page_detection',
          score: 0.0,
          is_phishing: false,
          from_list: 'whitelist',
          threshold: PHISHING_THRESHOLD,
        });
        return;
      }
      if (res.list === 'blacklist') {
        chrome.tabs.sendMessage(tabId, {
          action: 'page_detection',
          score: 1.0,
          is_phishing: true,
          from_list: 'blacklist',
          threshold: PHISHING_THRESHOLD,
        });
        return;
      }

      fetchPrediction(tab.url)
        .then((resp) => {
          if (!resp || typeof resp.score !== 'number') return;

          const isPhish = !!resp.is_phishing;

          chrome.tabs.sendMessage(tabId, {
            action: 'page_detection',
            score: resp.score,
            is_phishing: isPhish,
            threshold: resp.phishing_threshold_used,
          });

          // highlight extension icon
          chrome.action.setBadgeText({
            tabId,
            text: isPhish ? '!' : '',
          });
          chrome.action.setBadgeBackgroundColor({
            tabId,
            color: isPhish ? '#dc2626' : '#10b981',
          });

          // show system notification on phishing
          if (isPhish) {
            const percent = Math.round(resp.score * 100);
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'icons/icon48.png',
              title: 'SmartPhish Alert',
              message: `This site looks like a phishing page (risk ${percent}%).`,
            });
          }
        })
        .catch((err) => {
          console.error('[BG] auto-check error', err);
        });
    });
  }
});
