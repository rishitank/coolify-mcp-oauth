// Single source of truth for the OAuth scope this deployment's MCP
// resource requires.
//
// Previously this string was duplicated independently in two places —
// oidcProvider.js's resourceIndicators.getResourceServerInfo() and
// mcpRoute.js's /.well-known/oauth-protected-resource handler — and a
// *third*, different list (the Authorization Server's own top-level
// `scopes`) governed what Dynamic Client Registration would accept.
// Nothing kept these in sync, so the protected-resource metadata was
// telling clients "request scope=coolify" while the registration
// endpoint was rejecting exactly that scope as unsupported. Any
// spec-compliant client (Claude/Cowork included) that read our own
// metadata and echoed it back during DCR got invalid_client_metadata.
// See test/integration/dcr.test.js for the regression test.
export const MCP_SCOPE = 'coolify';
