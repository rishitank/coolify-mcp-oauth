import { describe, it, expect } from 'vitest';
import { loadEnv } from '../../src/env.js';

describe('loadEnv', () => {
  it('strips a trailing slash from PUBLIC_URL and derives mcpResourceUrl', () => {
    const env = loadEnv({ NODE_ENV: 'test', PUBLIC_URL: 'https://example.com/' });
    expect(env.publicUrl).toBe('https://example.com');
    expect(env.mcpResourceUrl).toBe('https://example.com/mcp');
  });

  it('defaults coolifyMcpCommand to npx with the published package', () => {
    const env = loadEnv({ NODE_ENV: 'test' });
    expect(env.coolifyMcpCommand).toBe('npx');
    expect(env.coolifyMcpArgs).toEqual(['-y', '@masonator/coolify-mcp@latest']);
  });

  it('lets COOLIFY_MCP_COMMAND/ARGS override the launch command', () => {
    const env = loadEnv({ NODE_ENV: 'test', COOLIFY_MCP_COMMAND: 'coolify-mcp', COOLIFY_MCP_ARGS: '' });
    expect(env.coolifyMcpCommand).toBe('coolify-mcp');
    expect(env.coolifyMcpArgs).toEqual([]);
  });

  it('parses ALLOWED_GOOGLE_EMAILS into a lowercased, trimmed list', () => {
    const env = loadEnv({ NODE_ENV: 'test', ALLOWED_GOOGLE_EMAILS: ' Rishi@Example.com, other@example.com ,' });
    expect(env.allowedGoogleEmails).toEqual(['rishi@example.com', 'other@example.com']);
  });

  it('defaults ALLOWED_GOOGLE_EMAILS to an empty (unrestricted) list', () => {
    const env = loadEnv({ NODE_ENV: 'test' });
    expect(env.allowedGoogleEmails).toEqual([]);
  });

  it('throws on missing required vars outside test mode', () => {
    expect(() => loadEnv({ NODE_ENV: 'production' })).toThrow(/PUBLIC_URL/);
  });

  it('does not throw on missing required vars in test mode (fills in safe defaults)', () => {
    expect(() => loadEnv({ NODE_ENV: 'test' })).not.toThrow();
  });
});
