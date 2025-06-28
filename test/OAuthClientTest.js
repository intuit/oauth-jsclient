'use strict';

const { describe, it, before, beforeEach, afterEach } = require('mocha');
const nock = require('nock');
const sinon = require('sinon');
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const btoa = require('btoa');
const jwt = require('jsonwebtoken');

// eslint-disable-next-line no-unused-vars
const getPem = require('rsa-pem-from-mod-exp');

const AuthResponse = require('../src/response/AuthResponse');
const OAuthClientTest = require('../src/OAuthClient');
// var AuthResponse = require('../src/response/AuthResponse');
const expectedAccessToken = require('./mocks/bearer-token.json');
const expectedTokenResponse = require('./mocks/tokenResponse.json');
const expectedUserInfo = require('./mocks/userInfo.json');
const expectedMakeAPICall = require('./mocks/makeAPICallResponse.json');
const expectedjwkResponseCall = require('./mocks/jwkResponse.json');
const expectedOpenIDToken = require('./mocks/openID-token.json');
// var expectedErrorResponse = require('./mocks/errorResponse.json');
const expectedMigrationResponse = require('./mocks/authResponse.json');

require.cache[require.resolve('rsa-pem-from-mod-exp')] = {
  exports: sinon.stub().returns(3),
};

const oauthClient = new OAuthClientTest({
  clientId: 'clientID',
  clientSecret: 'clientSecret',
  environment: 'sandbox',
  redirectUri: 'http://localhost:8000/callback',
  logging: true,
});

const { expect } = chai;
chai.use(chaiAsPromised);

describe('Tests for OAuthClient', () => {
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
        'https://appcenter.intuit.com/connect/oauth2?client_id=clientID&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&response_type=code&scope=testScope&state=testState';
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
          OAuthClientTest.scopes.Accounting,
          OAuthClientTest.scopes.Payment,
          OAuthClientTest.scopes.OpenId,
        ],
        state: 'testState',
      });
      const expectedAuthUri =
        'https://appcenter.intuit.com/connect/oauth2?client_id=clientID&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&response_type=code&scope=com.intuit.quickbooks.accounting%20com.intuit.quickbooks.payment%20openid&state=testState';
      expect(actualAuthUri).to.be.equal(expectedAuthUri);
    });
  });

  // Create bearer tokens
  describe('Create Bearer Token', () => {
    before(() => {
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

    it('Provide the uri to get the tokens', () => {
      const parseRedirect =
        'http://localhost:8000/callback?state=testState&code=Q011535008931rqveFweqmueq0GlOHhLPAFMp3NI2KJm5gbMMx';
      return oauthClient.createToken(parseRedirect).then((authResponse) => {
        expect(authResponse.getToken().access_token).to.be.equal(expectedAccessToken.access_token);
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

    it('Handles when code is NOT in the URL', async () => {
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
    before(() => {
      // eslint-disable-next-line global-require
      const refreshAccessToken = require('./mocks/refreshResponse.json');
      nock('https://oauth.platform.intuit.com')
        .persist()
        .post('/oauth2/v1/tokens/bearer')
        .reply(200, refreshAccessToken, {
          'content-type': 'application/json',
          'content-length': '1636',
          connection: 'close',
          server: 'nginx',
          intuit_tid: '12345-123-1234-12345',
          'cache-control': 'no-cache, no-store',
          pragma: 'no-cache',
        });
    });

    it('Refresh the existing tokens', () =>
      oauthClient.refresh().then((authResponse) => {
        expect(authResponse.getToken().refresh_token).to.be.equal(
          expectedAccessToken.refresh_token,
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
    before(() => {
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
          JSON.stringify(expectedUserInfo),
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
          JSON.stringify(expectedUserInfo),
        );
      });
    });
  });

  // make API Call
  describe('Make API Call', () => {
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
    it('Make API Call in Sandbox Environment', () => {
      oauthClient.getToken().realmId = '12345';
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url:
            'https://sandbox-quickbooks.api.intuit.com/v3/company/' +
            '12345' +
            '/companyinfo/' +
            '12345',
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
    it('Make API Call in Sandbox Environment using relative endpoint - starting slash', () => {
      oauthClient.environment = 'sandbox';
      oauthClient.getToken().realmId = '12345';
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url:
            '/v3/company/' + '12345' + '/companyinfo/' + '12345',
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
    it('Make API Call in Sandbox Environment using relative endpoint - no starting slash', () => {
      oauthClient.environment = 'sandbox';
      oauthClient.getToken().realmId = '12345';
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url:
            'v3/company/' + '12345' + '/companyinfo/' + '12345',
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
    it('Make API Call in Sandbox Environment with headers as parameters', () => {
      oauthClient.getToken().realmId = '12345';
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url: `https://sandbox-quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345`,
          headers: {
            Accept: 'application/json',
          },
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
    it('Make API Call in Sandbox Environment with headers as parameters, relative endpoint path - starting slash', () => {
      oauthClient.getToken().realmId = '12345';
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url: `/v3/company/12345/companyinfo/12345`,
          headers: {
            Accept: 'application/json',
          },
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
    it('Make API Call in Sandbox Environment with headers as parameters, relative endpoint path - no starting slash', () => {
      oauthClient.getToken().realmId = '12345';
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url: `v3/company/12345/companyinfo/12345`,
          headers: {
            Accept: 'application/json',
          },
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
    xit('loadResponseFromJWKsURI', () => {
      const request = {
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/12345/companyinfo/12345',
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
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url:
            'https://quickbooks.api.intuit.com/v3/company/' + '12345' + '/companyinfo/' + '12345',
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
    it('Make API Call in Production Environment with relative endpoint path - starting slash', () => {
      oauthClient.environment = 'production';
      oauthClient.getToken().realmId = '12345';
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url:
            '/v3/company/' + '12345' + '/companyinfo/' + '12345',
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
    it('Make API Call in Production Environment with relative endpoing path - no starting slash', () => {
      oauthClient.environment = 'production';
      oauthClient.getToken().realmId = '12345';
      // eslint-disable-next-line no-useless-concat
      return oauthClient
        .makeApiCall({
          url:
            'v3/company/' + '12345' + '/companyinfo/' + '12345',
        })
        .then((authResponse) => {
          expect(JSON.stringify(authResponse.json)).to.be.equal(
            JSON.stringify(expectedMakeAPICall),
          );
        });
    });
  });
});

describe('getPublicKey', () => {
  const pem = oauthClient.getPublicKey(3, 4);
  expect(pem).to.be.equal(3);
});

describe('Validate that token request can handle a failure', () => {
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
        url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/6789/companyinfo/6789',
      }),
    ).to.be.rejectedWith(Error);
  });
});

// Validate Id Token
describe('Validate Id Token ', () => {
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
    btoa(JSON.stringify(mockIdTokenPayload)),
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
    expect(authHeader).to.be.equal('Y2xpZW50SUQ6Y2xpZW50U2VjcmV0');

    global.btoa = sinon.stub().returns('abc');
    authHeader = oauthClient.authHeader();
    expect(authHeader).to.be.equal('abc');
    delete global.btoa;
  });
  it('accesstoken is not valid', () => {
    oauthClient.getToken().expires_in = null;
    const validity = oauthClient.isAccessTokenValid();
    // eslint-disable-next-line no-unused-expressions
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

describe('Tests whether the correct environment urls is returned', () => {
  describe('tests sandbox environment', () => {
    it('returns the sandbox environment URL when environment is not set', () => {
      oauthClient.environment = null;
      const environmentURL = oauthClient.getEnvironmentURL();
      expect(environmentURL).to.be.equal(OAuthClientTest.environment.sandbox);
    });
    it('returns the sandbox environment URL when environment is sandbox', () => {
      oauthClient.environment = 'sandbox';
      const environmentURL = oauthClient.getEnvironmentURL();
      expect(environmentURL).to.be.equal(OAuthClientTest.environment.sandbox);
    });
    it('returns the sandbox environment URL when sandbox environment is misspelt', () => {
      oauthClient.environment = 'sandoboxo';
      const environmentURL = oauthClient.getEnvironmentURL();
      expect(environmentURL).to.be.equal(OAuthClientTest.environment.sandbox);
    });

  });
  describe('tests production environment', () => {
    it('returns the production environment URL when environment is production', () => {
      oauthClient.environment = 'production';
      const environmentURL = oauthClient.getEnvironmentURL();
      expect(environmentURL).to.be.equal(OAuthClientTest.environment.production);
    });
    it('returns the sandbox environment URL when production environment is misspelt', () => {
      oauthClient.environment = 'productio';
      const environmentURL = oauthClient.getEnvironmentURL();
      expect(environmentURL).to.be.equal(OAuthClientTest.environment.sandbox);
    });
  });
});


// must be last test as it changes the endpoints
describe('Tests for OAuthClient to set custom Authorization URIs', () => {
  describe('set the authorizationURIs', () => {
    it('throws an error when no params provided', () => {
      expect(() => { oauthClient.setAuthorizeURLs() }).to.throw("Provide the custom authorize URL's");
    });
    it('throws an error when no params provided', () => {
      expect(() => { oauthClient.setAuthorizeURLs(null) }).to.throw("Provide the custom authorize URL's");
    });
    it('sets the Authorise urls to custom ones - sandbox', async (done) => {
      const customURLs = {
        authorizeEndpoint: "https://custom.Authorize.Endpoint",
        tokenEndpoint: "https://custom.Token.Endpoint",
        revokeEndpoint: "https://custom.Revoke.Endpoint",
        userInfoEndpoint: "https://custom.User.Info.Endpoint",
      }

      oauthClient.environment = 'sandbox';
      oauthClient.setAuthorizeURLs(customURLs);
      done();
      expect(OAuthClientTest.authorizeEndpoint).to.be.equal('https://custom.Authorize.Endpoint');
      expect(OAuthClientTest.tokenEndpoint).to.be.equal('https://custom.Token.Endpoint');
      expect(OAuthClientTest.revokeEndpoint).to.be.equal('https://custom.Revoke.Endpoint');
      expect(OAuthClientTest.userinfo_endpoint_sandbox).to.be.equal('https://custom.User.Info.Endpoint');
      expect(OAuthClientTest.userinfo_endpoint_production).to.be.equal('https://accounts.platform.intuit.com/v1/openid_connect/userinfo');

    });
    it('sets the Authorise urls to custom ones - production', async (done) => {
      const customURLs = {
        authorizeEndpoint: "https://custom.Authorize.Endpoint",
        tokenEndpoint: "https://custom.Token.Endpoint",
        revokeEndpoint: "https://custom.Revoke.Endpoint",
        userInfoEndpoint: "https://custom.User.Info.Endpoint",
      }

      oauthClient.environment = 'production';
      oauthClient.setAuthorizeURLs(customURLs);
      done();
      expect(OAuthClientTest.authorizeEndpoint).to.be.equal('https://custom.Authorize.Endpoint');
      expect(OAuthClientTest.tokenEndpoint).to.be.equal('https://custom.Token.Endpoint');
      expect(OAuthClientTest.revokeEndpoint).to.be.equal('https://custom.Revoke.Endpoint');
      expect(OAuthClientTest.userinfo_endpoint_sandbox).to.be.equal('https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo');
      expect(OAuthClientTest.userinfo_endpoint_production).to.be.equal('https://custom.User.Info.Endpoint');

    });
  });

});
