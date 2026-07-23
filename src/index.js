// Production entrypoint. Everything here is thin wiring — the actual
// logic lives in the modules under src/ and is covered by the test suite
// in test/. This file's only job is: load real config, open real
// (persistent) storage, and listen.

import { join } from 'node:path';
import { loadEnv } from './env.js';
import { openDb } from './db.js';
import { loadOrCreateJwks } from './jwks.js';
import { createApp } from './app.js';

const env = loadEnv();
const db = openDb(join(env.dataDir, 'coolify-mcp-oauth.sqlite3'));
const jwks = await loadOrCreateJwks(join(env.dataDir, 'jwks.json'));

const { app } = createApp({
  env,
  db,
  jwks,
  spawnOptions: { command: env.coolifyMcpCommand, args: env.coolifyMcpArgs },
});

app.listen(env.port, () => {
  console.log(`coolify-mcp-oauth listening on :${env.port}`);
  console.log(`  Issuer / public URL: ${env.publicUrl}`);
  console.log(`  MCP resource:        ${env.mcpResourceUrl}`);
  console.log(`  Data dir:            ${env.dataDir}`);
  console.log(`  Google login:        /account (or via any registered OAuth client)`);
  if (env.allowedGoogleEmails.length > 0) {
    console.log(`  Restricted to:       ${env.allowedGoogleEmails.join(', ')}`);
  } else {
    console.log('  Restricted to:       (no allowlist configured — any Google account may sign in)');
  }
});
