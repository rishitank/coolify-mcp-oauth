import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { registrationCors } from '../../src/registrationCors.js';

describe('registrationCors', () => {
  function buildApp() {
    const app = express();
    app.use('/reg', registrationCors);
    app.post('/reg', (req, res) => res.status(201).json({ ok: true }));
    app.get('/reg/:clientId', (req, res) => res.status(200).json({ ok: true }));
    return app;
  }

  it('answers a cross-origin preflight (OPTIONS) with 204 and the CORS headers a browser requires', async () => {
    const res = await request(buildApp())
      .options('/reg')
      .set('Origin', 'https://claude.ai')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type');

    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('*');
    expect(res.headers['access-control-allow-methods']).toContain('POST');
    expect(res.headers['access-control-allow-headers']).toMatch(/content-type/i);
  });

  it('also sets Access-Control-Allow-Origin on the real POST response, not just the preflight', async () => {
    const res = await request(buildApp())
      .post('/reg')
      .set('Origin', 'https://claude.ai')
      .send({});

    expect(res.status).toBe(201);
    expect(res.headers['access-control-allow-origin']).toBe('*');
  });

  it('covers registration_access_token-authenticated GET /reg/:clientId too', async () => {
    const res = await request(buildApp())
      .get('/reg/some-client-id')
      .set('Origin', 'https://claude.ai')
      .set('Authorization', 'Bearer reg-access-token');

    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('*');
  });

  it('does not interfere with same-origin requests (no Origin header at all)', async () => {
    const res = await request(buildApp()).post('/reg').send({});
    expect(res.status).toBe(201);
  });
});
