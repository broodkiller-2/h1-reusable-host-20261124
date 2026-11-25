const zlib = require('node:zlib');

const owner = 'broodkiller-2';
const repo = 'h1-reusable-host-20261124';
const token = process.env.GITHUB_TOKEN;
const pr = process.env.PR_NUMBER;
if (!token || !/^\d+$/.test(pr || '') || process.env.GITHUB_EVENT_NAME !== 'pull_request') {
  throw new Error('Unexpected owned fork PR context');
}

const api = `https://api.github.com/repos/${owner}/${repo}`;
const headers = {
  Accept: 'application/vnd.github+json',
  Authorization: `Bearer ${token}`,
  'X-GitHub-Api-Version': '2026-03-10',
  'User-Agent': 'OwnedSarifRefBoundaryProbe',
};

const sarif = {
  version: '2.1.0',
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
  runs: [{
    tool: { driver: { name: 'h1-synthetic-ref-boundary', rules: [{
      id: 'H1-SYNTHETIC-REF',
      shortDescription: { text: 'Synthetic ref boundary marker' },
    }] } },
    results: [{
      ruleId: 'H1-SYNTHETIC-REF',
      message: { text: 'Synthetic test marker; no vulnerability.' },
      locations: [{ physicalLocation: {
        artifactLocation: { uri: 'probe/45404947954-host.txt' },
        region: { startLine: 1 },
      } }],
    }],
  }],
};
const encoded = zlib.gzipSync(Buffer.from(JSON.stringify(sarif))).toString('base64');

async function upload(ref, sha, label) {
  const response = await fetch(`${api}/code-scanning/sarifs`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ commit_sha: sha, ref, sarif: encoded }),
  });
  const body = await response.json().catch(() => ({}));
  console.log(JSON.stringify({ label, ref, status: response.status, sarifIdPresent: typeof body.id === 'string', requestId: response.headers.get('x-github-request-id') || null }));
}

(async () => {
  const main = await fetch(`${api}/commits/main`, { headers });
  if (!main.ok) throw new Error(`main-control-status-${main.status}`);
  const mainSha = (await main.json()).sha;
  if (!/^[0-9a-f]{40}$/.test(mainSha) || !/^[0-9a-f]{40}$/.test(process.env.GITHUB_SHA || '')) throw new Error('unexpected-commit-sha');
  await upload(`refs/pull/${pr}/merge`, process.env.GITHUB_SHA, 'allowed_pr_ref');
  await upload('refs/heads/main', mainSha, 'forbidden_main_ref');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
