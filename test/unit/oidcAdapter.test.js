import { describe, it, expect, beforeEach } from 'vitest';
import { openDb } from '../../src/db.js';
import { createAdapter } from '../../src/oidcAdapter.js';

// Exercises the adapter directly against the interface oidc-provider
// documents at https://github.com/panva/node-oidc-provider/blob/main/example/my_adapter.js
// so we don't need a running Provider instance just to prove the storage
// layer is correct.

describe('SQLite Adapter for oidc-provider', () => {
  let db;
  let Adapter;

  beforeEach(() => {
    db = openDb(':memory:');
    Adapter = createAdapter(db);
  });

  it('upsert then find returns the stored payload', async () => {
    const adapter = new Adapter('AccessToken');
    await adapter.upsert('token-1', { accountId: 'acc-1', clientId: 'client-1' }, 3600);
    const found = await adapter.find('token-1');
    expect(found).toMatchObject({ accountId: 'acc-1', clientId: 'client-1' });
  });

  it('find returns a falsy value for an unknown id', async () => {
    const adapter = new Adapter('AccessToken');
    expect(await adapter.find('does-not-exist')).toBeFalsy();
  });

  it('models are isolated from each other by name, even with colliding ids', async () => {
    const tokens = new Adapter('AccessToken');
    const clients = new Adapter('Client');
    await tokens.upsert('shared-id', { kind: 'AccessToken' }, 3600);
    await clients.upsert('shared-id', { kind: 'Client' });

    expect(await tokens.find('shared-id')).toMatchObject({ kind: 'AccessToken' });
    expect(await clients.find('shared-id')).toMatchObject({ kind: 'Client' });
  });

  it('a record with no expiresIn never expires', async () => {
    const adapter = new Adapter('Client');
    await adapter.upsert('client-1', { client_id: 'client-1' });
    expect(await adapter.find('client-1')).toMatchObject({ client_id: 'client-1' });
  });

  it('a record with a past expiry is treated as not found', async () => {
    const adapter = new Adapter('AccessToken');
    await adapter.upsert('token-1', { accountId: 'acc-1' }, -1); // expired 1s ago
    expect(await adapter.find('token-1')).toBeFalsy();
  });

  it('findByUid locates a record by its uid field, scoped to the model', async () => {
    const interactions = new Adapter('Interaction');
    await interactions.upsert('interaction-1', { uid: 'uid-abc', params: {} }, 3600);
    const found = await interactions.findByUid('uid-abc');
    expect(found).toMatchObject({ uid: 'uid-abc' });
  });

  it('findByUserCode locates a record by its userCode field, scoped to the model', async () => {
    const deviceCodes = new Adapter('DeviceCode');
    await deviceCodes.upsert('dc-1', { userCode: 'ABCD-EFGH' }, 3600);
    const found = await deviceCodes.findByUserCode('ABCD-EFGH');
    expect(found).toMatchObject({ userCode: 'ABCD-EFGH' });
  });

  it('consume marks the record as consumed without deleting it', async () => {
    const adapter = new Adapter('AuthorizationCode');
    await adapter.upsert('code-1', { accountId: 'acc-1' }, 600);
    await adapter.consume('code-1');
    const found = await adapter.find('code-1');
    expect(found.accountId).toBe('acc-1');
    expect(found.consumed).toBeTruthy();
  });

  it('destroy removes the record entirely', async () => {
    const adapter = new Adapter('RefreshToken');
    await adapter.upsert('rt-1', { accountId: 'acc-1' }, 3600);
    await adapter.destroy('rt-1');
    expect(await adapter.find('rt-1')).toBeFalsy();
  });

  it('revokeByGrantId removes every record sharing that grantId, across models', async () => {
    const accessTokens = new Adapter('AccessToken');
    const refreshTokens = new Adapter('RefreshToken');
    await accessTokens.upsert('at-1', { accountId: 'acc-1', grantId: 'grant-1' }, 3600);
    await refreshTokens.upsert('rt-1', { accountId: 'acc-1', grantId: 'grant-1' }, 3600);
    await accessTokens.upsert('at-2', { accountId: 'acc-1', grantId: 'grant-2' }, 3600);

    await accessTokens.revokeByGrantId('grant-1');

    expect(await accessTokens.find('at-1')).toBeFalsy();
    expect(await refreshTokens.find('rt-1')).toBeFalsy();
    expect(await accessTokens.find('at-2')).toBeTruthy(); // different grant, untouched
  });

  it('upsert overwrites an existing record for the same model+id and resets consumed state', async () => {
    const adapter = new Adapter('AuthorizationCode');
    await adapter.upsert('code-1', { accountId: 'acc-1' }, 600);
    await adapter.consume('code-1');
    await adapter.upsert('code-1', { accountId: 'acc-2' }, 600);

    const found = await adapter.find('code-1');
    expect(found.accountId).toBe('acc-2');
    expect(found.consumed).toBeFalsy();
  });
});
