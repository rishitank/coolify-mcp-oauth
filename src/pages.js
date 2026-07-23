// Tiny dependency-free HTML rendering — no template engine needed for
// three small pages. Kept separate from interactions.js so the routing
// logic is easy to read on its own.

const layout = (title, body) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1115; color: #e6e6e6; display: flex; min-height: 100vh; align-items: center; justify-content: center; margin: 0; }
  .card { background: #1a1d24; border: 1px solid #2a2e37; border-radius: 12px; padding: 32px; max-width: 420px; width: 90%; }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p { color: #9aa0ab; line-height: 1.5; font-size: 14px; }
  label { display: block; margin: 16px 0 6px; font-size: 13px; color: #cfd3da; }
  input { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid #2a2e37; background: #0f1115; color: #e6e6e6; font-size: 14px; }
  button { margin-top: 20px; width: 100%; padding: 12px; border-radius: 8px; border: none; background: #5b8def; color: white; font-size: 15px; cursor: pointer; }
  button.secondary { background: transparent; border: 1px solid #2a2e37; color: #cfd3da; margin-top: 8px; }
  .error { background: #3a1d1d; border: 1px solid #5c2b2b; color: #f3a9a9; padding: 10px 12px; border-radius: 8px; font-size: 13px; margin-top: 12px; }
  code { background: #0f1115; padding: 2px 6px; border-radius: 4px; }
  .client { color: #e6e6e6; font-weight: 600; }
</style>
</head>
<body>
  <div class="card">${body}</div>
</body>
</html>`;

export function renderCoolifySetupPage({ actionUrl, error, values = {} }) {
  return layout('Connect your Coolify instance', `
    <h1>Connect your Coolify instance</h1>
    <p>Enter the Coolify instance this connector should manage. Find your API token under
    <strong>Coolify &rarr; Keys &amp; Tokens &rarr; API tokens</strong>.</p>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    <form method="POST" action="${actionUrl}">
      <label for="baseUrl">Coolify base URL</label>
      <input id="baseUrl" name="baseUrl" type="url" placeholder="https://coolify.example.com" value="${escapeHtml(values.baseUrl ?? '')}" required>
      <label for="accessToken">Coolify API token</label>
      <input id="accessToken" name="accessToken" type="password" placeholder="Paste your API token" required>
      <button type="submit">Save and continue</button>
    </form>
  `);
}

export function renderConsentPage({ actionUrl, abortUrl, clientName, resource }) {
  return layout('Authorize access', `
    <h1>Authorize access</h1>
    <p><span class="client">${escapeHtml(clientName)}</span> wants to manage your Coolify
    instance (<code>${escapeHtml(resource)}</code>) through this connector.</p>
    <form method="POST" action="${actionUrl}">
      <button type="submit">Allow</button>
    </form>
    <form method="GET" action="${abortUrl}">
      <button type="submit" class="secondary">Deny</button>
    </form>
  `);
}

export function renderMessagePage({ title, message }) {
  return layout(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
