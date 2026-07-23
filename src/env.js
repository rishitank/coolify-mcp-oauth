// Central env var loading + validation. Fails fast and loudly at boot
// rather than deep inside a request handler.

function required(name, { allowInTest = false } = {}) {
  const value = process.env[name];
  if (value) return value;
  if (allowInTest && process.env.NODE_ENV === 'test') return undefined;
  throw new Error(`Missing required environment variable: ${name}`);
}

export function loadEnv(source = process.env) {
  const env = source;
  const isTest = env.NODE_ENV === 'test';

  const publicUrl = (env.PUBLIC_URL || (isTest ? 'http://localhost:3000' : required('PUBLIC_URL'))).replace(/\/+$/, '');

  return {
    isTest,
    port: Number(env.PORT) || 3000,
    publicUrl,
    mcpResourceUrl: `${publicUrl}/mcp`,
    googleClientId: env.GOOGLE_CLIENT_ID || (isTest ? 'test-google-client-id' : required('GOOGLE_CLIENT_ID')),
    googleClientSecret: env.GOOGLE_CLIENT_SECRET || (isTest ? 'test-google-client-secret' : required('GOOGLE_CLIENT_SECRET')),
    credentialEncryptionKey: env.CREDENTIAL_ENCRYPTION_KEY || (isTest ? 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=' : required('CREDENTIAL_ENCRYPTION_KEY')),
    cookieSecret: env.COOKIE_SECRET || (isTest ? 'test-cookie-secret-test-cookie-secret' : required('COOKIE_SECRET')),
    dataDir: env.DATA_DIR || './data',
    allowedGoogleEmails: (env.ALLOWED_GOOGLE_EMAILS || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
    // How to launch the Coolify MCP server per session. Defaults to
    // fetching the published package fresh via npx (convenient for local,
    // non-Docker use). The Docker image overrides this to invoke a
    // globally pre-installed, pinned binary instead — faster per-session
    // startup and no runtime dependency on npm's registry being reachable.
    coolifyMcpCommand: env.COOLIFY_MCP_COMMAND || 'npx',
    // Distinguish "not set" (undefined -> use the npx default) from
    // "explicitly set to empty" (COOLIFY_MCP_ARGS= -> no extra args at
    // all, e.g. a bare pre-installed binary) — an empty string is falsy
    // in JS, so a truthy-check here would wrongly fall back to the default.
    coolifyMcpArgs: env.COOLIFY_MCP_ARGS === undefined
      ? ['-y', '@masonator/coolify-mcp@latest']
      : env.COOLIFY_MCP_ARGS.split(',').filter(Boolean),
  };
}
