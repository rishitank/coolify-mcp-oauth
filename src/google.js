// Federates end-user login to Google. This is the only identity provider
// this project talks to directly — oidc-provider (oidcProvider.js) never
// sees a password or a Google credential, only the local user id we
// resolve *after* verifying Google's id_token here.
//
// discoveryUrl is injectable so tests point this at a local mock server
// instead of https://accounts.google.com (see test/helpers/mockGoogle.js).

import { jwtVerify, createRemoteJWKSet } from 'jose';

const GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration';
const SCOPE = 'openid email profile';

export function createGoogleAuth({
  clientId,
  clientSecret,
  redirectUri,
  discoveryUrl = GOOGLE_DISCOVERY_URL,
}) {
  let discoveryPromise;
  let jwks;

  async function discover() {
    if (!discoveryPromise) {
      discoveryPromise = fetch(discoveryUrl).then((res) => {
        if (!res.ok) throw new Error(`Failed to fetch Google discovery document: ${res.status}`);
        return res.json();
      });
    }
    return discoveryPromise;
  }

  async function getJwks(jwksUri) {
    if (!jwks) {
      jwks = createRemoteJWKSet(new URL(jwksUri));
    }
    return jwks;
  }

  return {
    async getAuthorizationUrl({ state }) {
      const { authorization_endpoint: authorizationEndpoint } = await discover();
      const url = new URL(authorizationEndpoint);
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', SCOPE);
      url.searchParams.set('state', state);
      return url.toString();
    },

    async exchangeCode(code) {
      const { token_endpoint: tokenEndpoint } = await discover();
      const res = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code',
        }),
      });

      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        throw new Error(`Google token exchange failed (${res.status}): ${detail}`);
      }

      const body = await res.json();
      return { idToken: body.id_token, accessToken: body.access_token };
    },

    async verifyIdToken(idToken) {
      const { issuer, jwks_uri: jwksUri } = await discover();
      const keySet = await getJwks(jwksUri);
      const { payload } = await jwtVerify(idToken, keySet, {
        issuer,
        audience: clientId,
      });

      if (payload.email_verified !== true) {
        throw new Error('Google account email is not verified.');
      }

      return {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
      };
    },
  };
}
