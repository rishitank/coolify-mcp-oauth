#!/usr/bin/env node
// A stand-in for `npx @masonator/coolify-mcp`, used only in tests so the
// mcpProxy spawning/forwarding logic can be exercised without depending on
// network access to npm or a real Coolify instance. Speaks real MCP over
// stdio (via the same SDK the proxy uses), and echoes back the
// COOLIFY_BASE_URL/COOLIFY_ACCESS_TOKEN it was launched with — which is
// exactly what the tests assert on, to prove each session's child process
// really did get *that session's* credentials and not some other user's.

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name: 'fake-coolify-mcp', version: '0.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'whoami',
      description: 'Returns the Coolify connection this fake server was launched with.',
      inputSchema: { type: 'object', properties: {} },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== 'whoami') {
    throw new Error(`Unknown tool: ${request.params.name}`);
  }
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        baseUrl: process.env.COOLIFY_BASE_URL ?? null,
        accessToken: process.env.COOLIFY_ACCESS_TOKEN ?? null,
      }),
    }],
  };
});

await server.connect(new StdioServerTransport());
