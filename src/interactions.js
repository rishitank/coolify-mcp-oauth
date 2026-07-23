// Everything oidc-provider delegates to us: deciding *how* a user proves
// who they are (federate to Google — no local password), gating first-time
// users on entering their Coolify credentials, and rendering the consent
// screen. oidc-provider itself only ever sees the outcome (an accountId)
// via provider.interactionFinished.
//
// Pending-login bookkeeping (mapping "we just verified this Google
// identity" to "the browser hasn't submitted the Coolify-setup form yet")
// lives in an in-memory Map keyed by a random, server-generated token —
// deliberately never a client-suppliable value, so a tampered form field
// can't make us attach credentials to, or log in as, an account the
// browser didn't actually authenticate as. It's process-local by design
// (see docs/SCOPE.md — single-instance deployment for now); worst case on
// a restart mid-login is the user repeats the (few-second) login step.

import { Router, urlencoded } from 'express';
import { randomUUID } from 'node:crypto';
import { errors } from 'oidc-provider';
import { signState, verifyState } from './signedState.js';
import { upsertUserFromGoogle, getCoolifyCredentials, saveCoolifyCredentials } from './users.js';
import { renderCoolifySetupPage, renderConsentPage, renderMessagePage } from './pages.js';

const { SessionNotFound } = errors;
const PENDING_LOGIN_TTL_MS = 10 * 60 * 1000;

export function createInteractionsRouter({ provider, googleAuth, db, encryptionKey, cookieSecret, allowedGoogleEmails, mcpResourceUrl }) {
  const router = Router();
  const pendingLogins = new Map(); // token -> { userId, expiresAt }

  function rememberPendingLogin(userId) {
    sweepExpiredPendingLogins();
    const token = randomUUID();
    pendingLogins.set(token, { userId, expiresAt: Date.now() + PENDING_LOGIN_TTL_MS });
    return token;
  }

  function takePendingLogin(token) {
    const entry = pendingLogins.get(token);
    if (!entry) return undefined;
    pendingLogins.delete(token);
    if (entry.expiresAt < Date.now()) return undefined;
    return entry;
  }

  function sweepExpiredPendingLogins() {
    const now = Date.now();
    for (const [token, entry] of pendingLogins) {
      if (entry.expiresAt < now) pendingLogins.delete(token);
    }
  }

  // Scoped to just the routes that need it (not router.use(...) — this
  // router sits in front of provider.callback() for *every* request, and
  // oidc-provider parses its own POST bodies (e.g. /token); pre-parsing
  // those here just produces a harmless but noisy warning from it).
  const parseForm = urlencoded({ extended: false });

  // --- OAuth-client-initiated flow (oidc-provider sends the browser here) ---

  router.get('/interaction/:uid', async (req, res, next) => {
    try {
      const { uid, prompt, params } = await provider.interactionDetails(req, res);

      if (prompt.name === 'login') {
        const state = signState({ purpose: 'interaction', uid }, cookieSecret);
        const googleUrl = await googleAuth.getAuthorizationUrl({ state });
        return res.redirect(googleUrl);
      }

      if (prompt.name === 'consent') {
        const client = await provider.Client.find(params.client_id);
        return res.send(renderConsentPage({
          actionUrl: `/interaction/${uid}/confirm`,
          abortUrl: `/interaction/${uid}/abort`,
          clientName: client?.clientName || params.client_id,
          resource: mcpResourceUrl,
        }));
      }

      return res.status(400).send(renderMessagePage({ title: 'Unsupported request', message: `Unsupported interaction prompt: ${prompt.name}` }));
    } catch (err) {
      next(err);
    }
  });

  router.post('/interaction/:uid/confirm', parseForm, async (req, res, next) => {
    try {
      const interactionDetails = await provider.interactionDetails(req, res);
      const { prompt: { name, details }, params, session } = interactionDetails;
      if (name !== 'consent') {
        return res.status(400).send(renderMessagePage({ title: 'Unexpected request', message: 'This interaction is not awaiting consent.' }));
      }

      let { grantId } = interactionDetails;
      const grant = grantId
        ? await provider.Grant.find(grantId)
        : new provider.Grant({ accountId: session.accountId, clientId: params.client_id });

      if (details.missingOIDCScope) grant.addOIDCScope(details.missingOIDCScope.join(' '));
      if (details.missingOIDCClaims) grant.addOIDCClaims(details.missingOIDCClaims);
      if (details.missingResourceScopes) {
        for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
          grant.addResourceScope(indicator, scopes.join(' '));
        }
      }

      grantId = await grant.save();
      const consent = interactionDetails.grantId ? {} : { grantId };
      await provider.interactionFinished(req, res, { consent }, { mergeWithLastSubmission: true });
    } catch (err) {
      next(err);
    }
  });

  router.get('/interaction/:uid/abort', async (req, res, next) => {
    try {
      await provider.interactionFinished(
        req,
        res,
        { error: 'access_denied', error_description: 'End-User aborted interaction' },
        { mergeWithLastSubmission: false },
      );
    } catch (err) {
      next(err);
    }
  });

  router.post('/interaction/:uid/coolify-setup', parseForm, async (req, res, next) => {
    try {
      // Throws SessionNotFound if this browser doesn't hold a valid
      // interaction cookie for :uid — the real trust boundary here.
      await provider.interactionDetails(req, res);

      const pending = takePendingLogin(req.query.t);
      if (!pending) {
        return res.status(400).send(renderMessagePage({ title: 'Session expired', message: 'Your sign-in session expired. Please start over.' }));
      }

      const validationError = validateCoolifyForm(req.body);
      if (validationError) {
        // put it back so they can retry without re-doing Google login
        const retryToken = rememberPendingLogin(pending.userId);
        return res.status(400).send(renderCoolifySetupPage({
          actionUrl: `${req.path}?t=${retryToken}`,
          error: validationError,
          values: req.body,
        }));
      }

      saveCoolifyCredentials(db, pending.userId, {
        baseUrl: req.body.baseUrl.replace(/\/+$/, ''),
        accessToken: req.body.accessToken,
      }, encryptionKey);

      await provider.interactionFinished(req, res, { login: { accountId: pending.userId } }, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  // --- Standalone account management (rotate credentials any time, not
  // tied to any particular OAuth client's authorization request) ---

  router.get('/account', async (req, res, next) => {
    try {
      const state = signState({ purpose: 'account' }, cookieSecret);
      const googleUrl = await googleAuth.getAuthorizationUrl({ state });
      res.redirect(googleUrl);
    } catch (err) {
      next(err);
    }
  });

  router.post('/account/coolify-setup', parseForm, async (req, res, next) => {
    try {
      const pending = takePendingLogin(req.query.t);
      if (!pending) {
        return res.status(400).send(renderMessagePage({ title: 'Session expired', message: 'Your sign-in session expired. Please visit /account again.' }));
      }

      const validationError = validateCoolifyForm(req.body);
      if (validationError) {
        const retryToken = rememberPendingLogin(pending.userId);
        return res.status(400).send(renderCoolifySetupPage({
          actionUrl: `${req.path}?t=${retryToken}`,
          error: validationError,
          values: req.body,
        }));
      }

      saveCoolifyCredentials(db, pending.userId, {
        baseUrl: req.body.baseUrl.replace(/\/+$/, ''),
        accessToken: req.body.accessToken,
      }, encryptionKey);

      res.send(renderMessagePage({ title: 'Saved', message: 'Your Coolify credentials were saved. You can close this tab.' }));
    } catch (err) {
      next(err);
    }
  });

  // --- Shared Google callback for both flows above ---

  router.get('/callback/google', async (req, res, next) => {
    try {
      const { code, state, error, error_description: errorDescription } = req.query;
      if (error) {
        return res.status(400).send(renderMessagePage({ title: 'Google sign-in failed', message: errorDescription || error }));
      }

      let statePayload;
      try {
        statePayload = verifyState(state, cookieSecret);
      } catch {
        return res.status(400).send(renderMessagePage({ title: 'Invalid request', message: 'This sign-in link is invalid or expired. Please start over.' }));
      }

      const { idToken } = await googleAuth.exchangeCode(code);
      const identity = await googleAuth.verifyIdToken(idToken);

      if (allowedGoogleEmails.length > 0 && !allowedGoogleEmails.includes(identity.email.toLowerCase())) {
        return res.status(403).send(renderMessagePage({ title: 'Not allowed', message: 'This Google account is not permitted to use this deployment.' }));
      }

      const user = upsertUserFromGoogle(db, { googleSub: identity.sub, email: identity.email, name: identity.name });

      if (statePayload.purpose === 'account') {
        const token = rememberPendingLogin(user.id);
        const existing = getCoolifyCredentials(db, user.id, encryptionKey);
        return res.send(renderCoolifySetupPage({
          actionUrl: `/account/coolify-setup?t=${token}`,
          error: null,
          values: existing ? { baseUrl: existing.baseUrl } : {},
        }));
      }

      // purpose === 'interaction'
      const { uid } = statePayload;
      const existingCreds = getCoolifyCredentials(db, user.id, encryptionKey);
      if (!existingCreds) {
        const token = rememberPendingLogin(user.id);
        return res.send(renderCoolifySetupPage({
          actionUrl: `/interaction/${uid}/coolify-setup?t=${token}`,
          error: null,
        }));
      }

      await provider.interactionFinished(req, res, { login: { accountId: user.id } }, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  router.use((err, req, res, next) => {
    if (err instanceof SessionNotFound) {
      return res.status(400).send(renderMessagePage({ title: 'Session expired', message: 'Your sign-in session expired or was already used. Please start over from your MCP client.' }));
    }
    next(err);
  });

  return router;
}

function validateCoolifyForm(body) {
  if (!body?.baseUrl || !body?.accessToken) {
    return 'Both the Coolify base URL and API token are required.';
  }
  let parsed;
  try {
    parsed = new URL(body.baseUrl);
  } catch {
    return 'Enter a valid URL, e.g. https://coolify.example.com';
  }
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost') {
    return 'Use an https:// URL for your Coolify instance.';
  }
  return null;
}
