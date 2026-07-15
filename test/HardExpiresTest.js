'use strict';

/**
 * Verifies the x-include-refresh-token-hard-expires-in header behavior:
 *  - Header is OMITTED by default (opt-in only).
 *  - Header is sent with value 'true' when the client is constructed with
 *    `includeRefreshTokenHardExpiresIn: true`.
 *  - Setting `includeRefreshTokenHardExpiresIn: false` is equivalent to the
 *    default and omits the header.
 *  - When the platform returns x_refresh_token_hard_expires_in, the value is
 *    parsed onto the Token model.
 */

const { describe, it, beforeEach, afterEach } = require('mocha');
const nock = require('nock');
const chai = require('chai');

const OAuthClient = require('../src/OAuthClient');

const { expect } = chai;

const HARD_EXPIRES_HEADER = 'x-include-refresh-token-hard-expires-in';

const sampleResponse = {
  access_token: 'eyJhbGciOiJkaXIi..sample',
  token_type: 'bearer',
  expires_in: 3600,
  refresh_token: 'RT1-39-H3-1785429816rcysb9dns1ofreknypnm',
  x_refresh_token_expires_in: 8726400,
  x_refresh_token_hard_expires_in: 156032154,
};

function newClient(overrides) {
  return new OAuthClient(Object.assign({
    clientId: 'clientId',
    clientSecret: 'clientSecret',
    environment: 'sandbox',
    redirectUri: 'http://localhost:8000/callback',
    token: {
      access_token: 'seed_access_token',
      refresh_token: 'seed_refresh_token',
      token_type: 'bearer',
      expires_in: 3600,
      x_refresh_token_expires_in: 8726400,
    },
  }, overrides || {}));
}

function interceptTokenCall() {
  const captured = {};
  nock('https://oauth.platform.intuit.com')
    .post('/oauth2/v1/tokens/bearer')
    .reply(function reply() {
      captured.header = this.req.headers[HARD_EXPIRES_HEADER];
      return [200, sampleResponse, { 'content-type': 'application/json' }];
    });
  return captured;
}

describe('x-include-refresh-token-hard-expires-in header (opt-in)', () => {
  beforeEach(() => {
    nock.disableNetConnect();
  });

  afterEach(() => {
    nock.cleanAll();
    nock.enableNetConnect();
  });

  describe('default behavior (flag not provided)', () => {
    it('omits the header on createToken()', async () => {
      const oauthClient = newClient();
      const captured = interceptTokenCall();

      await oauthClient.createToken(
        'http://localhost:8000/callback?code=authcode&state=s&realmId=1',
      );
      expect(captured.header).to.equal(undefined);
    });

    it('omits the header on refresh()', async () => {
      const oauthClient = newClient();
      const captured = interceptTokenCall();
      await oauthClient.refresh();
      expect(captured.header).to.equal(undefined);
    });

    it('omits the header on refreshUsingToken()', async () => {
      const oauthClient = newClient();
      const captured = interceptTokenCall();
      await oauthClient.refreshUsingToken('explicit_refresh_token');
      expect(captured.header).to.equal(undefined);
    });
  });

  describe('includeRefreshTokenHardExpiresIn: true', () => {
    it('sends the header on createToken() and parses the new field', async () => {
      const oauthClient = newClient({ includeRefreshTokenHardExpiresIn: true });
      const captured = interceptTokenCall();

      await oauthClient.createToken(
        'http://localhost:8000/callback?code=authcode&state=s&realmId=1',
      );

      expect(captured.header).to.equal('true');
      const token = oauthClient.getToken();
      expect(token.x_refresh_token_hard_expires_in).to.equal(156032154);
    });

    it('sends the header on refresh()', async () => {
      const oauthClient = newClient({ includeRefreshTokenHardExpiresIn: true });
      const captured = interceptTokenCall();
      await oauthClient.refresh();
      expect(captured.header).to.equal('true');
      expect(oauthClient.getToken().x_refresh_token_hard_expires_in)
        .to.equal(156032154);
    });

    it('sends the header on refreshUsingToken()', async () => {
      const oauthClient = newClient({ includeRefreshTokenHardExpiresIn: true });
      const captured = interceptTokenCall();
      await oauthClient.refreshUsingToken('explicit_refresh_token');
      expect(captured.header).to.equal('true');
      expect(oauthClient.getToken().x_refresh_token_hard_expires_in)
        .to.equal(156032154);
    });
  });

  describe('includeRefreshTokenHardExpiresIn: false (explicit opt-out)', () => {
    it('omits the header', async () => {
      const oauthClient = newClient({ includeRefreshTokenHardExpiresIn: false });
      const captured = interceptTokenCall();
      await oauthClient.refresh();
      expect(captured.header).to.equal(undefined);
    });
  });

  describe('response parsing', () => {
    it('defaults x_refresh_token_hard_expires_in to 0 when platform omits it', async () => {
      const oauthClient = newClient({ includeRefreshTokenHardExpiresIn: true });
      const legacyResponse = Object.assign({}, sampleResponse);
      delete legacyResponse.x_refresh_token_hard_expires_in;

      nock('https://oauth.platform.intuit.com')
        .post('/oauth2/v1/tokens/bearer')
        .reply(200, legacyResponse, { 'content-type': 'application/json' });

      await oauthClient.refresh();
      expect(oauthClient.getToken().x_refresh_token_hard_expires_in).to.equal(0);
    });
  });
});
