// popup.js
const THEME_KEY = 'smartphish_theme';
let lastCheckedUrl = '';

function applyTheme(theme) {
  const body = document.body;
  const label = document.getElementById('theme-label');
  const btn = document.getElementById('theme-toggle');

  const isDark = theme === 'dark';
  body.classList.toggle('theme-dark', isDark);

  if (label) label.textContent = isDark ? 'Dark' : 'Light';
  if (btn) btn.textContent = isDark ? 'Light' : 'Dark';
}

function initTheme() {
  try {
    chrome.storage.sync.get([THEME_KEY], (data) => {
      const stored = data[THEME_KEY];
      const theme = stored === 'dark' || stored === 'light' ? stored : 'light';
      applyTheme(theme);
    });
  } catch (e) {
    applyTheme('light');
  }

  const btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.addEventListener('click', () => {
      const isDark = document.body.classList.contains('theme-dark');
      const next = isDark ? 'light' : 'dark';
      applyTheme(next);
      try {
        chrome.storage.sync.set({ [THEME_KEY]: next });
      } catch {}
    });
  }
}

function renderOverall(score) {
  const mainScore = document.getElementById('main-score');
  const status = document.getElementById('status-label');
  const percent = document.getElementById('score-percent');

  const safeScore = typeof score === 'number' ? score : 0;

  mainScore.textContent = safeScore.toFixed(2);
  percent.textContent = Math.round(safeScore * 100) + '%';

  if (safeScore > 0.6) {
    status.textContent = 'High Risk';
    status.className = 'status-label status-high';
  } else if (safeScore > 0.3) {
    status.textContent = 'Medium Risk';
    status.className = 'status-label status-medium';
  } else {
    status.textContent = 'Low Risk';
    status.className = 'status-label status-low';
  }
}

function renderBreakdown(scores = {}, uncertainty = 0) {
  const container = document.getElementById('parameter-breakdown');
  container.innerHTML = '';

  const featureNames = {
    url_length: 'URL Length',
    num_dots: 'Number of Dots',
    num_hyphens: 'Number of Hyphens',
    num_slashes: 'Number of Slashes',
    num_digits: 'Digits in URL',
    num_subdomains: 'Subdomains',
    contains_suspicious_words: 'Suspicious Words',
    entropy: 'Lexical Entropy',
    contains_cyrillic: 'Cyrillic Characters',
    contains_hidden_chars: 'Hidden Characters',
    is_punycode: 'Punycode Host',
    contains_ip: 'IP as Host',
    contains_common_tld: 'Uncommon TLD',
    uses_https: 'No HTTPS',
  };

  const keys = scores && typeof scores === 'object' ? Object.keys(scores) : [];

  if (!keys.length) {
    container.innerHTML = '<div class="small">No feature explanation available.</div>';
  } else {
    keys.forEach((k) => {
      const v = Number(scores[k]) || 0;
      const risk = Math.max(0, Math.min(1, v));
      const barColor =
        risk > 0.6 ? '#ef4444' : risk > 0.3 ? '#f59e0b' : '#10b981';

      const item = document.createElement('div');
      item.className = 'parameter-item';
      item.innerHTML = `
        <div style="width:140px">${featureNames[k] || k}</div>
        <div class="param-bar-container">
          <div class="param-bar" style="width:${Math.round(
            risk * 100
          )}%; background:${barColor}"></div>
        </div>
        <div style="width:40px;text-align:right;font-weight:700">${Math.round(
          risk * 100
        )}%</div>
      `;
      container.appendChild(item);
    });
  }

  const unc = Math.max(0, Math.min(1, Number(uncertainty) || 0));
  document.getElementById('uncertainty-value').textContent =
    Math.round(unc * 100) + '%';
}

function requestCheck(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'check_url', url }, (resp) => {
      resolve(resp);
    });
  });
}

async function init() {
  document.getElementById('current-url').textContent = 'Checking active tab...';
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url) {
      document.getElementById('current-url').textContent =
        'Cannot get active tab URL.';
      return;
    }
    lastCheckedUrl = tab.url;
    document.getElementById('current-url').textContent = 'URL: ' + tab.url;
    const resp = await requestCheck(tab.url);
    if (resp && typeof resp.score === 'number') {
      renderOverall(resp.score);
      renderBreakdown(resp.parameter_scores, resp.model_uncertainty);
    } else {
      document.getElementById('main-score').textContent = 'ERR';
      document.getElementById('status-label').textContent = 'Failed';
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  init();
});

document.getElementById('check-btn').addEventListener('click', async () => {
  const url = document.getElementById('manual-url').value.trim();
  if (!url) return alert('Enter URL');
  lastCheckedUrl = url;
  const resp = await requestCheck(url);
  if (resp && typeof resp.score === 'number') {
    renderOverall(resp.score);
    renderBreakdown(resp.parameter_scores, resp.model_uncertainty);
    document.getElementById('current-url').textContent = 'Manual URL: ' + url;
  } else {
    alert('Prediction failed.');
  }
});

document.getElementById('add-whitelist').addEventListener('click', () => {
  const input = document.getElementById('manual-url');
  let url = input.value.trim();
  if (!url) url = lastCheckedUrl || '';
  if (!url) return alert('No URL: open a page or type one.');
  chrome.runtime.sendMessage(
    { action: 'add_url', list: 'whitelist', url },
    (resp) => {
      alert(resp?.message || 'Done');
      // refresh UI immediately (will now be overridden by whitelist)
      requestCheck(lastCheckedUrl || url).then((r) => {
        if (r && typeof r.score === 'number') {
          renderOverall(r.score);
          renderBreakdown(r.parameter_scores, r.model_uncertainty);
        }
      });
    }
  );
});

document.getElementById('add-blacklist').addEventListener('click', () => {
  const input = document.getElementById('manual-url');
  let url = input.value.trim();
  if (!url) url = lastCheckedUrl || '';
  if (!url) return alert('No URL: open a page or type one.');
  chrome.runtime.sendMessage(
    { action: 'add_url', list: 'blacklist', url },
    (resp) => {
      alert(resp?.message || 'Done');
      // refresh UI immediately (will now be overridden by blacklist)
      requestCheck(lastCheckedUrl || url).then((r) => {
        if (r && typeof r.score === 'number') {
          renderOverall(r.score);
          renderBreakdown(r.parameter_scores, r.model_uncertainty);
        }
      });
    }
  );
});
