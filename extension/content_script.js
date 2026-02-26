// content_script.js
function injectBanner(score) {
  const existing = document.getElementById('phishguard-banner');
  if (existing) return;

  const div = document.createElement('div');
  div.id = 'phishguard-banner';
  div.style.position = 'fixed';
  div.style.left = '0';
  div.style.right = '0';
  div.style.top = '0';
  div.style.background = 'linear-gradient(90deg,#fca5a5,#fb7185)';
  div.style.color = '#111';
  div.style.padding = '10px';
  div.style.zIndex = '999999';
  div.style.textAlign = 'center';
  div.style.fontFamily = 'system-ui, -apple-system, "Segoe UI", sans-serif';
  div.textContent = `PhishGuard Alert: This page looks suspicious (score ${Math.round(
    score * 100
  )}%).`;
  document.body.appendChild(div);

  // Push page content down slightly so banner does not fully cover top UI
  const body = document.body;
  if (!body.style.marginTop) {
    body.style.marginTop = '40px';
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === 'page_detection' && typeof msg.score === 'number') {
    const threshold =
      typeof msg.threshold === 'number' ? msg.threshold : 0.7;
    const shouldWarn =
      typeof msg.is_phishing === 'boolean'
        ? msg.is_phishing
        : msg.score >= threshold;

    if (shouldWarn) {
      injectBanner(msg.score);
    }
  }
});
