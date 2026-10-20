// Copies the shared engine into the extension so "Load unpacked" works from a plain download.
// Run after changing anything in src/:  npm run build:ext
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';

mkdirSync('extension/lib', { recursive: true });
for (const f of ['engine.js', 'github.js']) copyFileSync(`src/${f}`, `extension/lib/${f}`);

const { version } = JSON.parse(readFileSync('package.json', 'utf8'));
const manifest = JSON.parse(readFileSync('extension/manifest.json', 'utf8'));
manifest.version = version;
writeFileSync('extension/manifest.json', JSON.stringify(manifest, null, 2) + '\n');
// zip for one-click download from the website
import { execSync } from 'node:child_process';
execSync('rm -f agentxray-extension.zip && cd extension && zip -qr ../agentxray-extension.zip . -x "*.DS_Store"');
console.log(`extension built (v${version}) + agentxray-extension.zip`);
