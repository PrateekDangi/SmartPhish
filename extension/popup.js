// popup.js
function renderOverall(score) {
  const mainScore = document.getElementById('main-score');
  const status = document.getElementById('status-label');
  const percent = document.getElementById('score-percent');

  mainScore.textContent = score.toFixed(2);
  percent.textContent = Math.round(score*100) + '%';

  if (score > 0.6) { status.textContent = 'High Risk'; status.className='status-label status-high'; }
  else if (score > 0.3) { status.textContent = 'Medium Risk'; status.className='status-label status-medium'; }
  else { status.textContent = 'Low Risk'; status.className='status-label status-low'; }
}

function renderBreakdown(scores, uncertainty) {
  const container = document.getElementById('parameter-breakdown');
  container.innerHTML = '';
  const featureNames = {
    lexical_entropy:'Lexical Entropy',
    domain_age:'Domain Age',
    ssl_cert_presence:'SSL Cert',
    whois_abnormality:'WHOIS Abnormality',
    redirect_count:'Redirect Count',
    ip_as_host:'IP as Host',
    suspicious_tld:'Suspicious TLD',
    url_length:'URL Length',
    brand_similarity_score:'Brand Similarity',
    uncommon_ports:'Uncommon Ports',
    obfuscation_tokens:'Obfuscation Tokens',
    presence_of_encoded_characters:'Encoded Chars'
  };

  for (const k in scores) {
    const v = scores[k];
    let badness = v;
    if (k==='domain_age' || k==='ssl_cert_presence') badness = 1 - v;
    const barColor = badness>0.6? '#ef4444' : (badness>0.3? '#f59e0b' : '#10b981');

    const item = document.createElement('div');
    item.className = 'parameter-item';
    item.innerHTML = `
      <div style="width:120px">${featureNames[k]||k}</div>
      <div class="param-bar-container"><div class="param-bar" style="width:${Math.round(badness*100)}%; background:${barColor}"></div></div>
      <div style="width:36px;text-align:right;font-weight:700">${Math.round(v*100)}%</div>
    `;
    container.appendChild(item);
  }
  document.getElementById('uncertainty-value').textContent = Math.round(uncertainty*100)+'%';
}

function requestCheck(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({action:'check_url', url}, (resp) => {
      resolve(resp);
    });
  });
}

async function init() {
  document.getElementById('current-url').textContent = 'Checking active tab...';
  chrome.tabs.query({active:true, currentWindow:true}, async (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url) {
      document.getElementById('current-url').textContent = 'Cannot get active tab URL.';
      return;
    }
    document.getElementById('current-url').textContent = 'URL: ' + tab.url;
    const resp = await requestCheck(tab.url);
    if (resp && resp.score !== undefined) {
      renderOverall(resp.score);
      renderBreakdown(resp.parameter_scores, resp.model_uncertainty);
    } else {
      document.getElementById('main-score').textContent = 'ERR';
      document.getElementById('status-label').textContent = 'Failed';
    }
  });
}

document.addEventListener('DOMContentLoaded', init);

document.getElementById('check-btn').addEventListener('click', async () => {
  const url = document.getElementById('manual-url').value.trim();
  if (!url) return alert('Enter URL');
  const resp = await requestCheck(url);
  if (resp && resp.score !== undefined) {
    renderOverall(resp.score);
    renderBreakdown(resp.parameter_scores, resp.model_uncertainty);
    document.getElementById('current-url').textContent = 'Manual URL: ' + url;
  } else {
    alert('Prediction failed.');
  }
});

document.getElementById('add-whitelist').addEventListener('click', () => {
  const url = document.getElementById('manual-url').value.trim();
  if (!url) return alert('Enter URL to whitelist');
  chrome.runtime.sendMessage({action:'add_url', list:'whitelist', url}, (resp)=>{ alert(resp?.message || 'Done'); });
});
document.getElementById('add-blacklist').addEventListener('click', () => {
  const url = document.getElementById('manual-url').value.trim();
  if (!url) return alert('Enter URL to blacklist');
  chrome.runtime.sendMessage({action:'add_url', list:'blacklist', url}, (resp)=>{ alert(resp?.message || 'Done'); });
});
