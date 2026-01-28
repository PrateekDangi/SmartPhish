// content_script.js
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'page_detection' && msg.score !== undefined) {
    if (msg.score > 0.7) {
      // Simple banner injection
      const div = document.createElement('div');
      div.style.position='fixed'; div.style.left='0'; div.style.right='0'; div.style.top='0';
      div.style.background='linear-gradient(90deg,#fca5a5,#fb7185)'; div.style.color='#111';
      div.style.padding='10px'; div.style.zIndex=999999; div.style.textAlign='center';
      div.textContent = `PhishGuard Alert: This page looks suspicious (score ${Math.round(msg.score*100)}%).`;
      document.body.appendChild(div);
    }
  }
});
