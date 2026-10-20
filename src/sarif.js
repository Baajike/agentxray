// SARIF 2.1.0 so findings show up in GitHub → Security → Code scanning.
import { VERSION } from './engine.js';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SCORE = { critical: '9.5', high: '7.5', medium: '5.0', low: '2.0', info: '0.0' };

export function toSarif(result) {
  const rules = new Map();
  for (const f of result.findings) {
    if (!rules.has(f.rule)) rules.set(f.rule, {
      id: f.rule, name: f.rule.replace(/-/g, ''),
      shortDescription: { text: f.title.replace(/"[^"]*"/g, '…').slice(0, 120) },
      fullDescription: { text: f.why },
      help: { text: f.fix, markdown: `**Why it matters:** ${f.why}\n\n**Fix:** ${f.fix}` },
      properties: { tags: ['security', 'ai-agent', f.phase], 'security-severity': SCORE[f.severity] },
    });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'AgentXray', version: VERSION, informationUri: 'https://github.com/Baajike/agentxray', rules: [...rules.values()] } },
      results: result.findings.map(f => ({
        ruleId: f.rule, level: LEVEL[f.severity],
        message: { text: `${f.title}${f.decoded ? ` — decoded: ${f.decoded.slice(0, 200)}` : ''}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: Math.max(1, f.line || 1) } } }],
        properties: { severity: f.severity, phase: f.phase, tags: f.tags || [] },
      })),
    }],
  };
}
