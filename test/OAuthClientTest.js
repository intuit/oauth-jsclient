'use strict';

const { describe, it, before, beforeEach, afterEach } = require('mocha');
const nock = require('nock');
const sinon = require('sinon');
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const btoa = require('btoa');
const jwt = require('jsonwebtoken');
const getPem = require('rsa-pem-from-mod-exp');
const os = require('os');
const version = require('../package.json');

const OAuthError = require('../src/errors/OAuthError');
const TokenError = require('../src/errors/TokenError');
const ValidationError = require('../src/errors/ValidationError');
const OAuthClient = require('../src/OAuthClient');
const AuthResponse = require('../src/response/AuthResponse');

const expectedAccessToken = require('./mocks/bearer-token.json');
const expectedTokenResponse = require('./mocks/tokenResponse.json');
const expectedUserInfo = require('./mocks/userInfo.json');
const expectedMakeAPICall = require('./mocks/makeAPICallResponse.json');
const expectedjwkResponseCall = require('./mocks/jwkResponse.json');
const expectedOpenIDToken = require('./mocks/openID-token.json');
const expectedMigrationResponse = require('./mocks/authResponse.json');

require.cache[require.resolve('rsa-pem-from-mod-exp')] = {
  exports: sinon.stub().returns(3),
};

let oauthClient;
let sandbox;

const { expect } = chai;
chai.use(chaiAsPromised);

describe('Tests for OAuthClient', () => {
  beforeEach(() => {
    sandbox = sinon.createSandbox();
    oauthClient = new OAuthClient({
      clientId: 'clientId',
      clientSecret: 'clientSecret',
      environment: 'sandbox',
      redirectUri: 'http://localhost:8000/callback',
      token: {
        access_token: 'sample_access_token',
        refresh_token: 'sample_refresh_token',
        token_type: 'bearer',
        expires_in: 3600,
        x_refresh_token_expires_in: 8726400,
        id_token: 'sample_id_token',
      },
    });

    // Configure nock
    nock.disableNetConnect();
    nock.enableNetConnect('127.0.0.1');
  });

  afterEach(() => {
    sandbox.restore();
    nock.cleanAll();
    nock.enableNetConnect();
  });

  it('Creates a new access token instance', () => {
    const accessToken = oauthClient.getToken();
    expect(accessToken).to.have.property('realmId');
    expect(accessToken).to.have.property('token_type');
    expect(accessToken).to.have.property('refresh_token');
    expect(accessToken).to.have.property('expires_in');
    expect(accessToken).to.have.property('x_refresh_token_expires_in');
    expect(accessToken).to.have.property('id_token');
    expect(accessToken).to.have.property('latency');
  });

  describe('Get the authorizationURI', () => {
    it('When Scope is passed', () => {
      const actualAuthUri = oauthClient.authorizeUri({ scope: 'testScope', state: 'testState' });
      const expectedAuthUri =
        'https://appcenter.intuit.com/connect/oauth2?client_id=clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&response_type=code&scope=testScope&state=testState';
      expect(actualAuthUri).to.be.equal(expectedAuthUri);
    });

    it('When NO Scope is passed', () => {
      try {
        oauthClient.authorizeUri();
      } catch (e) {
        expect(e.message).to.equal('Provide the scopes');
      }
    });

    it('When Scope is passed as an array', () => {
      const actualAuthUri = oauthClient.authorizeUri({
        scope: [
          OAuthClient.scopes.Accounting,
          OAuthClient.scopes.Payment,
          OAuthClient.scopes.OpenId,
        ],
        state: 'testState',
      });
      const expectedAuthUri =
        'https://appcenter.intuit.com/connect/oauth2?client_id=clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&response_type=code&scope=com.intuit.quickbooks.accounting%20com.intuit.quickbooks.payment%20openid&state=testState';
      expect(actualAuthUri).to.be.equal(expectedAuthUri);
    });
  });

  // Create bearer tokens
  describe('Create Bearer Token', () => {
    beforeEach(() => {
      nock('https://oauth.platform.intuit.com')
        .persist()
        .post('/oauth2/v1/tokens/bearer')
        .reply(200, expectedTokenResponse, {
          'content-type': 'application/json',
          'content-length': '1636',
          connection: 'close',
          server: 'nginx',
          intuit_tid: '12345-123-1234-12345',
          'cache-control': 'no-cache, no-store',
          pragma: 'no-cache',
        });
    });

    afterEach(() => {
      nock.cleanAll();
    });

    it('Provide the uri to get the tokens', () => {
      const parseRedirect =
        'http://localhost:8000/callback?state=testState&code=Q011535008931rqveFweqmueq0GlOHhLPAFMp3NI2KJm5gbMMx';
      return oauthClient.createToken(parseRedirect).then((authResponse) => {
        expect(authResponse.getToken().access_token).to.be.equal(
          expectedAccessToken.access_token
        );
      });
    });

    it('When NO uri is provided', () =>
      oauthClient
        .createToken()
        .then((authResponse) => {
          expect(authResponse.getToken().access_token).to.be.equal(
            expectedAccessToken.access_token,
          );
        })
        .catch((e) => {
          expect(e.message).to.equal('Provide the Uri');
        }));

    it('handles when code is NOT in the URL', async () => {
      const parseRedirect = 'http://localhost:8000/callback?state=testState';
      const authResponse = await oauthClient.createToken(parseRedirect);
      expect(authResponse.getToken().access_token).to.be.equal(expectedAccessToken.access_token);
    });

    it('handles a realm id in the url', async () => {
      const parseRedirect = 'http://localhost:8000/callback?state=testState&realmId=12345';
      const authResponse = await oauthClient.createToken(parseRedirect);
      expect(authResponse.getToken().access_token).to.be.equal(expectedAccessToken.access_token);
    });
  });

  // Refresh bearer tokens
  describe('Refresh Bearer Token', () => {
    beforeEach(() => {
      nock('https://oauth.platform.intuit.com')
        .persist()
        .post('/oauth2/v1/tokens/bearer')
        .reply(200, expectedTokenResponse, {
          'content-type': 'application/json',
          'content-length': '1636',
          connection: 'close',
          server: 'nginx',
          intuit_tid: '12345-123-1234-12345',
          'cache-control': 'no-cache, no-store',
          pragma: 'no-cache',
        });
    });

    afterEach(() => {
      nock.cleanAll();
    });

    it('Refresh the existing tokens', () =>
      oauthClient.refresh().then((authResponse) => {
        expect(authResponse.getToken().refresh_token).to.be.equal(
          expectedAccessToken.refresh_token
        );
      }));

    it('Refresh : refresh token is missing', () => {
      oauthClient.getToken().refresh_token = null;
      return oauthClient.refresh().catch((e) => {
        expect(e.message).to.equal('The Refresh token is missing');
      });
    });

    it('Refresh : refresh token is invalid', () => {
      oauthClient.getToken().refresh_token = 'sample_refresh_token';
      oauthClient.getToken().x_refresh_token_expires_in = '300';
      return oauthClient.refresh().catch((e) => {
        expect(e.message).to.equal('The Refresh token is invalid, please Authorize again.');
      });
    });

    it('Refresh Using token', async () => {
      const refreshToken = expectedAccessToken.refresh_token;
      await oauthClient.refreshUsingToken(refreshToken);
      expect(oauthClient.getToken().refresh_token).to.be.equal(refreshToken);
    });

    it('Handle refresh using token with empty token', async () => {
      await expect(oauthClient.refreshUsingToken(null)).to.be.rejectedWith(Error);
    });
  });

  // Revoke bearer tokens
  describe('Revoke Bearer Token', () => {
    beforeEach(() => {
      nock('https://developer.api.intuit.com')
        .persist()
        .post('/v2/oauth2/tokens/revoke')
        .reply(200, '', {
          'content-type': 'application/json',
          'content-length': '1636',
          connection: 'close',
          server: 'nginx',
          intuit_tid: '12345-123-1234-12345',
          'cache-control': 'no-cache, no-store',
          pragma: 'no-cache',
        });
    });

    afterEach(() => {
      nock.cleanAll();
    });

    it('Revoke the existing tokens', () => {
      oauthClient.getToken().x_refresh_token_expires_in = '4535995551112';
      return oauthClient.revoke().then((authResponse) => {
        expect(authResponse.getToken().refresh_token).to.be.equal('');
      });
    });

    it('Revoke : refresh token is missing', () => {
      oauthClient.getToken().refresh_token = null;
      return oauthClient.revoke().catch((e) => {
        expect(e.message).to.equal('The Refresh token is missing');
      });
    });

    it('Revoke : refresh token is invalid', () => {
      oauthClient.getToken().refresh_token = 'sample_refresh_token';
      oauthClient.getToken().x_refresh_token_expires_in = '300';
      return oauthClient.revoke().catch((e) => {
        expect(e.message).to.equal('The Refresh token is invalid, please Authorize again.');
      });
    });
  });

  // Get User Info ( OpenID )
  describe('Get User Info ( OpenID )', () => {
    before(() => {
      nock('https://sandbox-accounts.platform.intuit.com')
        .persist()
        .get('/v1/openid_connect/userinfo')
        .reply(200, expectedUserInfo, {
          'content-type': 'application/json',
          'content-length': '1636',
          connection: 'close',
          server: 'nginx',
          intuit_tid: '12345-123-1234-12345',
          'cache-control': 'no-cache, no-store',
          pragma: 'no-cache',
        });
    });

    it('Get User Info in Sandbox', () =>
      oauthClient.getUserInfo().then((authResponse) => {
        expect(JSON.stringify(authResponse.json)).to.be.equal(
          JSON.stringify(expectedUserInfo)
        );
      }));
  });

  describe('Get User Info In Production', () => {
    before(() => {
      nock('https://accounts.platform.intuit.com')
        .persist()
        .get('/v1/openid_connect/userinfo')
        .reply(200, expectedUserInfo, {
          'content-type': 'application/json',
          'content-length': '1636',
          connection: 'close',
          server: 'nginx',
          intuit_tid: '12345-123-1234-12345',
          'cache-control': 'no-cache, no-store',
          pragma: 'no-cache',
        });
    });

    it('Get User Info in Production', () => {
      oauthClient.environment = 'production';
      return oauthClient.getUserInfo().then((authResponse) => {
        expect(JSON.stringify(authResponse.json)).to.be.equal(
          JSON.stringify(expectedUserInfo)
        );
      });
    });
  });

  // make API Call
  describe('Make API Call', () => {
    beforeEach(() => {
      nock('https://sandbox-quickbooks.api.intuit.com')
        .persist()
        .get('/v3/company/12345/companyinfo/12345')
        .reply(200, expectedMakeAPICall, {
          'content-type': 'application/json',
          'content-length': '1636',
          connection: 'close',
          server: 'nginx',
          intuit_tid: '12345-123-1234-12345',
          'cache-control': 'no-cache, no-store',
          pragma: 'no-cache',
        });
    });

    afterEach(() => {
      nock.cleanAll();
    });

    it('Make API Call in Sandbox Environment', () => {
      oauthClient.getToken().realmId = '12345';
      return oauthClient
        .makeApiCall({
          url:
            'https://sandbox-quickbooks.api.intuit.com/v3/company/' +
            '12345' +
            '/companyinfo/' +
            '12345'
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall)
          );
        });
    });

    it('Make API Call in Sandbox Environment with headers as parameters', () => {
      oauthClient.getToken().realmId = '12345';
      return oauthClient
        .makeApiCall({
          url: `https://sandbox-quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345`,
          headers: {
            Accept: 'application/json'
          }
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall)
          );
        });
    });

    it.skip('loadResponseFromJWKsURI', () => {
      const request = {
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345'
      };
      return oauthClient.loadResponseFromJWKsURI(request).then((authResponse) => {
        expect(authResponse.body).to.be.equal(JSON.stringify(expectedMakeAPICall));
      });
    });
  });

  describe('Make API call in Production', () => {
    before(() => {
      nock('https://quickbooks.api.intuit.com')
        .persist()
        .get('/v3/company/12345/companyinfo/12345')
        .reply(200, expectedMakeAPICall, {
          'content-type': 'application/json',
          'content-length': '1636',
          connection: 'close',
          server: 'nginx',
          intuit_tid: '12345-123-1234-12345',
          'cache-control': 'no-cache, no-store',
          pragma: 'no-cache',
        });
    });
    it('Make API Call in Production Environment', () => {
      oauthClient.environment = 'production';
      oauthClient.getToken().realmId = '12345';
      return oauthClient
        .makeApiCall({
          url: 'https://quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345'
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall)
          );
        });
    });
  });

  describe('getPublicKey', () => {
    it('should return the correct public key', () => {
      const pem = oauthClient.getPublicKey(3, 4);
      expect(pem).to.be.equal(3);
    });
  });
});

describe.skip('Validate that token request can handle a failure', () => {
  before(() => {
    nock('https://sandbox-quickbooks.api.intuit.com')
      .persist()
      .get('/v3/company/6789/companyinfo/6789')
      .reply(416, expectedMakeAPICall, {
        'content-type': 'application/json',
        'content-length': '1636',
        connection: 'close',
        server: 'nginx',
        intuit_tid: '12345-123-1234-12345',
        'cache-control': 'no-cache, no-store',
        pragma: 'no-cache',
      });
  });

  it('Validate token request can handle a failure', async () => {
    oauthClient.getToken().setToken(expectedOpenIDToken);
    await expect(
      oauthClient.getTokenRequest({
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/6789/companyinfo/6789'
      })
    ).to.be.rejectedWith(Error);
  });
});

// Validate Id Token
describe.skip('Validate Id Token ', () => {
  before(() => {
    nock('https://oauth.platform.intuit.com')
      .persist()
      .get('/op/v1/jwks')
      .reply(200, expectedjwkResponseCall.body, {
        'content-type': 'application/json;charset=UTF-8',
        'content-length': '264',
        connection: 'close',
        server: 'nginx',
        'strict-transport-security': 'max-age=15552000',
        intuit_tid: '1234-1234-1234-123',
        'cache-control': 'no-cache, no-store',
        pragma: 'no-cache',
      });
    sinon.stub(jwt, 'verify').returns(true);
  });

  const mockIdTokenPayload = {
    sub: 'b053d994-07d5-468d-b7ee-22e349d2e739',
    aud: ['clientID'],
    realmid: '1108033471',
    auth_time: 1462554475,
    iss: 'https://oauth.platform.intuit.com/op/v1',
    exp: Date.now() + 60000,
    iat: 1462557728,
  };

  const tokenParts = expectedOpenIDToken.id_token.split('.');
  const encodedMockIdTokenPayload = tokenParts[0].concat(
    '.',
    btoa(JSON.stringify(mockIdTokenPayload))
  );
  const mockToken = Object.assign({}, expectedOpenIDToken, { id_token: encodedMockIdTokenPayload });

  it('validate id token returns error if id_token missing', async () => {
    delete oauthClient.getToken().id_token;
    await expect(oauthClient.validateIdToken()).to.be.rejectedWith(Error);
  });

  it('Validate Id Token', () => {
    oauthClient.getToken().setToken(mockToken);
    oauthClient.validateIdToken().then((response) => {
      expect(response).to.be.equal(true);
    });
  });

  it('Validate Id Token alternative', () => {
    oauthClient.setToken(mockToken);
    oauthClient.validateIdToken().then((response) => {
      expect(response).to.be.equal(true);
    });
  });
});

// Validate Refresh Token
describe('Validate Refresh Token', () => {
  it('Validate should handle expired token', () => {
    const newToken = JSON.parse(JSON.stringify(expectedOpenIDToken));
    newToken.createdAt = new Date(1970, 1, 1);
    oauthClient.setToken(newToken);
    expect(() => oauthClient.validateToken()).to.throw(Error);
  });
});

// Check Access Token Validity
describe('Check Access-Token Validity', () => {
  before(() => {
    // Reset token
    oauthClient.setToken(expectedAccessToken);
  });
  it('access-token is valid', () => {
    const validity = oauthClient.isAccessTokenValid();
    // eslint-disable-next-line no-unused-expressions
    expect(validity).to.be.true;
  });
  it('access-token is not valid', () => {
    oauthClient.getToken().expires_in = null;
    const validity = oauthClient.isAccessTokenValid();
    // eslint-disable-next-line no-unused-expressions
    expect(validity).to.be.false;
  });
});

// Get Token
describe('Get Token', () => {
  it('get token instance', () => {
    const token = oauthClient.getToken();
    expect(token).to.be.a('Object');
  });
  it('accesstoken is not valid', () => {
    oauthClient.getToken().expires_in = null;
    const validity = oauthClient.isAccessTokenValid();
    // eslint-disable-next-line no-unused-expressions
    expect(validity).to.be.false;
  });
});

// Get Auth Header
describe('Get Auth Header', () => {
  it('Auth Header is valid', () => {
    let authHeader = oauthClient.authHeader();
    expect(authHeader).to.be.equal('Y2xpZW50SWQ6Y2xpZW50U2VjcmV0');

    // Test with global btoa
    const originalBtoa = global.btoa;
    global.btoa = () => 'abc';
    authHeader = oauthClient.authHeader();
    expect(authHeader).to.be.equal('abc');
    global.btoa = originalBtoa;
  });

  it('accesstoken is not valid', () => {
    oauthClient.getToken().expires_in = null;
    const validity = oauthClient.isAccessTokenValid();
    expect(validity).to.be.false;
  });
});

// Load Responses
describe('load responses', () => {
  before(() => {
    nock('https://sandbox-quickbooks.api.intuit.com')
      .persist()
      .get('/v3/company/12345/companyinfo/12345')
      .reply(200, expectedMakeAPICall, {
        'content-type': 'application/json',
        'content-length': '1636',
        connection: 'close',
        server: 'nginx',
        intuit_tid: '12345-123-1234-12345',
        'cache-control': 'no-cache, no-store',
        pragma: 'no-cache',
      });
  });
});

describe('Test Create Error Wrapper', () => {
  let authResponse;
  let expectedAuthResponse;
  let getStub;

  beforeEach(() => {
    expectedAuthResponse = JSON.parse(JSON.stringify(expectedMigrationResponse.response));
    getStub = sinon.stub().returns('application/json;charset=UTF-8');
    expectedAuthResponse.get = getStub;
    authResponse = new AuthResponse({ token: oauthClient.getToken() });
    authResponse.processResponse(expectedAuthResponse);
  });

  afterEach(() => {
    getStub.reset();
  });

  it('Should handle an empty error and empty authResponse', () => {
    const wrappedE = oauthClient.createError(new Error(), null);
    expect(wrappedE.error).to.be.equal('');
    expect(wrappedE.authResponse).to.be.equal('');
    expect(wrappedE.intuit_tid).to.be.equal('');
    expect(wrappedE.originalMessage).to.be.equal('');
    expect(wrappedE.error_description).to.be.equal('');
  });

  it('Should handle an error with text and empty authResponse', () => {
    const errorMessage = 'error foo';
    const wrappedE = oauthClient.createError(new Error(errorMessage), null);
    expect(wrappedE.error).to.be.equal(errorMessage);
    expect(wrappedE.authResponse).to.be.equal('');
    expect(wrappedE.intuit_tid).to.be.equal('');
    expect(wrappedE.originalMessage).to.be.equal(errorMessage);
    expect(wrappedE.error_description).to.be.equal('');
  });

  it('should handle an authResponse with no body', () => {
    authResponse.body = '';
    const wrappedE = oauthClient.createError(new Error(), authResponse);
    expect(wrappedE.error).to.be.equal(authResponse.response.statusText);
    expect(JSON.stringify(wrappedE.authResponse)).to.be.equal(JSON.stringify(authResponse));
    expect(wrappedE.intuit_tid).to.be.equal(authResponse.response.headers.intuit_tid);
    expect(wrappedE.originalMessage).to.be.equal('');
    expect(wrappedE.error_description).to.be.equal(authResponse.response.statusText);
  });

  it('should handle an authResponse', () => {
    const errorMessage = 'error foo';
    authResponse.body = '';
    const wrappedE = oauthClient.createError(new Error(errorMessage), authResponse);
    expect(wrappedE.error).to.be.equal(authResponse.response.statusText);
    expect(JSON.stringify(wrappedE.authResponse)).to.be.equal(JSON.stringify(authResponse));
    expect(wrappedE.intuit_tid).to.be.equal(authResponse.response.headers.intuit_tid);
    expect(wrappedE.originalMessage).to.be.equal(errorMessage);
    expect(wrappedE.error_description).to.be.equal(authResponse.response.statusText);
  });

  it('should handle an authResponse with a body that contains error info', () => {
    const originalErrorMessage = 'error foobar';
    const errorMessage = 'error foo';
    const errorDescription = 'error bar';
    const errorJson = {
      error: errorMessage,
      error_description: errorDescription,
    };
    authResponse.json = errorJson;
    authResponse.body = errorJson;

    let wrappedE = oauthClient.createError(new Error(originalErrorMessage), authResponse);
    expect(wrappedE.error).to.be.equal(errorMessage);
    expect(JSON.stringify(wrappedE.authResponse)).to.be.equal(JSON.stringify(authResponse));
    expect(wrappedE.intuit_tid).to.be.equal(authResponse.response.headers.intuit_tid);
    expect(wrappedE.originalMessage).to.be.equal(originalErrorMessage);
    expect(wrappedE.error_description).to.be.equal(errorDescription);

    delete errorJson.error;
    authResponse.json = errorJson;
    authResponse.body = errorJson;
    delete authResponse.response.statusText;
    wrappedE = oauthClient.createError(new Error(originalErrorMessage), authResponse);
    expect(wrappedE.error).to.be.equal(originalErrorMessage);

    wrappedE = oauthClient.createError(new Error(), authResponse);
    expect(wrappedE.error).to.be.equal('');
  });
});

describe('Test Logging', () => {
  it('Should handle a log', () => {
    oauthClient.logger = {
      log: sinon.spy(),
    };
    oauthClient.logging = true;
    const level = 'DEBUG';
    const message = 'Message';
    const messageData = 'Data';

    oauthClient.log(level, message, messageData);

    expect(oauthClient.logger.log.firstCall.args[0]).to.be.equal(level);
    expect(oauthClient.logger.log.firstCall.args[1]).to.be.equal(message + messageData);
  });
});

describe('Test OAuthError', () => {
  const OAuthError = require('../src/errors/OAuthError');

  it('should create an error with minimal parameters', () => {
    const error = new OAuthError('Test error');
    expect(error.name).to.equal('OAuthError');
    expect(error.message).to.equal('Test error');
    expect(error.code).to.equal('OAUTH_ERROR');
    expect(error.description).to.equal('Test error');
    expect(error.intuitTid).to.equal('');
  });

  it('should create an error with all parameters', () => {
    const error = new OAuthError('Test error', 'TEST_CODE', 'Test description', '1234-5678');
    expect(error.name).to.equal('OAuthError');
    expect(error.message).to.equal('Test error');
    expect(error.code).to.equal('TEST_CODE');
    expect(error.description).to.equal('Test description');
    expect(error.intuitTid).to.equal('1234-5678');
  });

  it('should throw TypeError for non-string message', () => {
    expect(() => new OAuthError(null)).to.throw(TypeError, 'Error message must be a string');
    expect(() => new OAuthError(123)).to.throw(TypeError, 'Error message must be a string');
    expect(() => new OAuthError({})).to.throw(TypeError, 'Error message must be a string');
  });

  it('should format error string correctly', () => {
    const error = new OAuthError('Test error', 'TEST_CODE', 'Test description', '1234-5678');
    expect(error.toString()).to.equal('OAuthError: Test error (TEST_CODE) - Test description [TID: 1234-5678]');
  });

  it('should format error string with minimal info', () => {
    const error = new OAuthError('Test error');
    expect(error.toString()).to.equal('OAuthError: Test error (OAUTH_ERROR)');
  });

  it('should convert to JSON correctly', () => {
    const error = new OAuthError('Test error', 'TEST_CODE', 'Test description', '1234-5678');
    const json = error.toJSON();
    expect(json).to.have.property('name', 'OAuthError');
    expect(json).to.have.property('message', 'Test error');
    expect(json).to.have.property('code', 'TEST_CODE');
    expect(json).to.have.property('description', 'Test description');
    expect(json).to.have.property('intuitTid', '1234-5678');
    expect(json).to.have.property('stack');
  });

  it('should be instanceof Error', () => {
    const error = new OAuthError('Test error');
    expect(error).to.be.instanceof(Error);
    expect(error).to.be.instanceof(OAuthError);
  });
});

describe('Test TokenError', () => {
  const TokenError = require('../src/errors/TokenError');

  it('should create a token error with minimal parameters', () => {
    const error = new TokenError('Test error');
    expect(error.name).to.equal('TokenError');
    expect(error.message).to.equal('Test error');
    expect(error.code).to.equal('TOKEN_ERROR');
    expect(error.description).to.equal('Test error');
    expect(error.intuitTid).to.equal('');
  });

  it('should create a token error with all parameters', () => {
    const error = new TokenError('Test error', 'TEST_CODE', 'Test description', '1234-5678');
    expect(error.name).to.equal('TokenError');
    expect(error.message).to.equal('Test error');
    expect(error.code).to.equal('TEST_CODE');
    expect(error.description).to.equal('Test description');
    expect(error.intuitTid).to.equal('1234-5678');
  });

  it('should be instanceof Error and OAuthError', () => {
    const error = new TokenError('Test error');
    expect(error).to.be.instanceof(Error);
    expect(error).to.be.instanceof(TokenError);
  });
});

describe('Test ValidationError', () => {
  const ValidationError = require('../src/errors/ValidationError');

  it('should create a validation error with minimal parameters', () => {
    const error = new ValidationError('Test error');
    expect(error.name).to.equal('ValidationError');
    expect(error.message).to.equal('Test error');
    expect(error.code).to.equal('VALIDATION_ERROR');
    expect(error.description).to.equal('Test error');
    expect(error.intuitTid).to.equal('');
  });

  it('should create a validation error with all parameters', () => {
    const error = new ValidationError('Test error', 'TEST_CODE', 'Test description', '1234-5678');
    expect(error.name).to.equal('ValidationError');
    expect(error.message).to.equal('Test error');
    expect(error.code).to.equal('TEST_CODE');
    expect(error.description).to.equal('Test description');
    expect(error.intuitTid).to.equal('1234-5678');
  });

  it('should be instanceof Error and OAuthError', () => {
    const error = new ValidationError('Test error');
    expect(error).to.be.instanceof(Error);
    expect(error).to.be.instanceof(ValidationError);
  });
});

describe('Test OAuthClient Error Handling', () => {
  beforeEach(function() {
    this.timeout(5000);
    nock.cleanAll();
    nock.enableNetConnect();
    nock.disableNetConnect();
    nock.enableNetConnect('127.0.0.1');

    // Reset the token before each test
    oauthClient.setToken({
      access_token: 'sample_access_token',
      refresh_token: 'sample_refresh_token',
      token_type: 'bearer',
      expires_in: 3600,
      x_refresh_token_expires_in: 8726400,
      id_token: 'sample_id_token',
    });
  });

  afterEach(() => {
    nock.cleanAll();
    nock.enableNetConnect();
  });

  it('should handle API call errors', async function() {
    const errorResponse = {
      error: 'Internal Server Error',
      error_description: 'Something went wrong',
    };

    const scope = nock('https://sandbox-quickbooks.api.intuit.com')
      .get('/v3/company/12345/companyinfo/12345')
      .reply(500, errorResponse, {
        'Content-Type': 'application/json',
      });

    try {
      await oauthClient.makeApiCall({
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345',
        method: 'GET',
      });
      expect.fail('Should have thrown an error');
    } catch (error) {
      expect(error).to.be.instanceof(OAuthError);
      expect(error.code).to.equal('INTERNAL_SERVER_ERROR');
      expect(error.message).to.equal('Internal Server Error');
      expect(error.description).to.equal('Something went wrong');
    }
    scope.done();
  });

  it('should handle network errors', async function() {
    const scope = nock('https://sandbox-quickbooks.api.intuit.com')
      .get('/v3/company/12345/companyinfo/12345')
      .replyWithError({ code: 'ECONNRESET', message: 'Connection reset by peer' });

    try {
      await oauthClient.makeApiCall({
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345',
        method: 'GET',
      });
      expect.fail('Should have thrown an error');
    } catch (error) {
      expect(error).to.be.instanceof(OAuthError);
      expect(error.code).to.equal('NETWORK_ERROR');
      expect(error.message).to.equal('Connection reset by peer');
      expect(error.description).to.equal('A network error occurred while making the request');
    }
    scope.done();
  });

  it('should handle timeout errors', async function() {
    const scope = nock('https://sandbox-quickbooks.api.intuit.com')
      .get('/v3/company/12345/companyinfo/12345')
      .delayConnection(1000)
      .reply(200);

    try {
      await oauthClient.makeApiCall({
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345',
        method: 'GET',
        timeout: 500,
      });
      expect.fail('Should have thrown an error');
    } catch (error) {
      expect(error).to.be.instanceof(OAuthError);
      expect(error.code).to.equal('TIMEOUT_ERROR');
      expect(error.message).to.equal('Request timeout of 500ms exceeded');
      expect(error.description).to.equal('The request took too long to complete');
    }
    scope.done();
  });

  it('should handle validation errors', async function() {
    try {
      await oauthClient.makeApiCall({
        method: 'GET',
      });
      expect.fail('Should have thrown an error');
    } catch (error) {
      expect(error).to.be.instanceof(ValidationError);
      expect(error.message).to.equal('URL is required for API call');
    }
  });

  it('should handle rate limit errors', async function() {
    const scope = nock('https://sandbox-quickbooks.api.intuit.com')
      .get('/v3/company/12345/companyinfo/12345')
      .reply(429, {
        error: 'Rate limit exceeded',
        error_description: 'Too many requests',
      }, {
        'Content-Type': 'application/json',
      });

    try {
      await oauthClient.makeApiCall({
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345',
        method: 'GET',
      });
      expect.fail('Should have thrown an error');
    } catch (error) {
      expect(error).to.be.instanceof(OAuthError);
      expect(error.code).to.equal('RATE_LIMIT_EXCEEDED');
      expect(error.message).to.equal('Rate limit exceeded');
      expect(error.description).to.equal('Too many requests, please try again later');
    }
    scope.done();
  });
});

describe('Test 400 Error Handling with Fault Object', () => {
  beforeEach(() => {
    nock.cleanAll();
    nock.enableNetConnect();
    nock.disableNetConnect();
    nock.enableNetConnect('127.0.0.1');
  });

  afterEach(() => {
    nock.cleanAll();
    nock.enableNetConnect();
  });

  it('should handle 400 response with Fault object correctly', async () => {
    const faultResponse = {
      Fault: {
        Error: [
          {
            Message: "Unsupported Operation",
            Detail: "Operation No resource method found for POST, return 405 with Allow header is not supported.",
            code: "500"
          }
        ],
        type: "ValidationFault"
      },
      time: "2025-05-28T23:25:54.056-07:00"
    };

    const scope = nock('https://sandbox-quickbooks.api.intuit.com')
      .post('/v3/company/12345/customer')
      .reply(400, faultResponse, {
        'content-type': 'application/json',
        'intuit_tid': '1234-1234-1234-123'
      });

    try {
      await oauthClient.makeApiCall({
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/12345/customer',
        method: 'POST',
        body: { /* test data */ }
      });
      expect.fail('Should have thrown an error');
    } catch (error) {
      expect(error).to.be.instanceof(OAuthError);
      expect(error.message).to.equal('Unsupported Operation');
      expect(error.code).to.equal('500');
      expect(error.description).to.equal('Operation No resource method found for POST, return 405 with Allow header is not supported.');
      expect(error.fault).to.deep.include({
        type: 'ValidationFault',
        time: '2025-05-28T23:25:54.056-07:00'
      });
      expect(error.fault.errors).to.deep.equal([
        {
          message: 'Unsupported Operation',
          detail: 'Operation No resource method found for POST, return 405 with Allow header is not supported.',
          code: '500'
        }
      ]);
    }

    scope.done();
  });
});

describe('Ensure 400 does not throw AxiosError', () => {
  beforeEach(() => {
    nock.cleanAll();
    nock.enableNetConnect();
    nock.disableNetConnect();
    nock.enableNetConnect('127.0.0.1');
  });

  afterEach(() => {
    nock.cleanAll();
    nock.enableNetConnect();
  });

  it('should not throw AxiosError for 400 response', async () => {
    const faultResponse = {
      Fault: {
        Error: [
          {
            Message: 'Test 400 error',
            Detail: 'This is a test 400 error',
            code: '400',
          },
        ],
        type: 'ValidationFault',
      },
      time: '2025-05-28T23:25:54.056-07:00',
    };

    nock('https://sandbox-quickbooks.api.intuit.com')
      .post('/v3/company/12345/customer')
      .reply(400, faultResponse, {
        'content-type': 'application/json',
        'intuit_tid': 'test-tid-400',
      });

    try {
      await oauthClient.makeApiCall({
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/12345/customer',
        method: 'POST',
        body: { /* test data */ },
      });
      expect.fail('Should have thrown an error');
    } catch (error) {
      // Should NOT be an AxiosError
      expect(error.isAxiosError).to.not.be.true;
      expect(error.name).to.not.equal('AxiosError');
      // Should be an OAuthError
      expect(error).to.be.instanceof(OAuthError);
      expect(error.message).to.equal('Test 400 error');
      expect(error.code).to.equal('400');
      expect(error.fault.type).to.equal('ValidationFault');
    }
  });
});

