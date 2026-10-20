const $ = id => document.getElementById(id);
const say = m => { $('msg').textContent = m; setTimeout(() => ($('msg').textContent = ''), 2500); };

chrome.storage.local.get('token').then(s => { if (s.token) $('token').value = s.token; });

$('save').onclick = async () => {
  const t = $('token').value.trim();
  if (t && !/^(github_pat_|ghp_|gho_)[A-Za-z0-9_]{20,}$/.test(t)) return say('That does not look like a GitHub token.');
  await chrome.storage.local.set({ token: t });
  say(t ? 'Saved. New scans use your token.' : 'Token removed.');
};

$('clear').onclick = async () => {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter(k => k.startsWith('ax:'));
  await chrome.storage.local.remove(keys);
  say(`Cleared ${keys.length} cached grade${keys.length === 1 ? '' : 's'}.`);
};
