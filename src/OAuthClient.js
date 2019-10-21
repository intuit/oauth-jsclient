/* eslint-disable no-undef */
/* eslint-disable camelcase */
/**

 Copyright (c) 2018 Intuit
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #  http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.

 */


/**
 * @namespace OAuthClient
 */

'use strict';

const atob = require('atob');
const oauthSignature = require('oauth-signature');
const objectAssign = require('object-assign');
const csrf = require('csrf');
const queryString = require('query-string');
const popsicle = require('popsicle');
const os = require('os');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const AuthResponse = require('./response/AuthResponse');
const version = require('../package.json');
const Token = require('./access-token/Token');


/**
 * @constructor
 * @param {string} config.environment
 * @param {string} config.appSecret
 * @param {string} config.appKey
 * @param {string} [config.cachePrefix]
 */
function OAuthClient(config) {
  this.environment = config.environment;
  this.clientId = config.clientId;
  this.clientSecret = config.clientSecret;
  this.redirectUri = config.redirectUri;
  this.autoRefresh = config.autoRefresh || false;
  // If autoRefreshIntervalInSeconds is not choosen by user, defaults to 3300 seconds (55 minutes) since tokens expire after 60 minutes.
  this.autoRefreshIntervalInSeconds = config.autoRefreshIntervalInSeconds || 3300;
  this.token = new Token(config.token);
  this.logging = !!(Object.prototype.hasOwnProperty.call(config, 'logging') && config.logging === true);
  this.logger = null;
  this.state = new csrf(); // eslint-disable-line new-cap

  if (this.logging) {
    const dir = './logs';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
      ),
      transports: [new winston.transports.File({ filename: path.join(dir, 'oAuthClient-log.log') })],
    });
  }
}


OAuthClient.cacheId = 'cacheID';
OAuthClient.authorizeEndpoint = 'https://appcenter.intuit.com/connect/oauth2';
OAuthClient.tokenEndpoint = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
OAuthClient.revokeEndpoint = 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke';
OAuthClient.userinfo_endpoint_production = 'https://accounts.platform.intuit.com/v1/openid_connect/userinfo';
OAuthClient.userinfo_endpoint_sandbox = 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo';
OAuthClient.migrate_sandbox = 'https://developer-sandbox.api.intuit.com/v2/oauth2/tokens/migrate';
OAuthClient.migrate_production = 'https://developer.api.intuit.com/v2/oauth2/tokens/migrate';
OAuthClient.environment = { sandbox: 'https://sandbox-quickbooks.api.intuit.com/', production: 'https://quickbooks.api.intuit.com/' };
OAuthClient.jwks_uri = 'https://oauth.platform.intuit.com/op/v1/jwks';
OAuthClient.scopes = {
  Accounting: 'com.intuit.quickbooks.accounting',
  Payment: 'com.intuit.quickbooks.payment',
  Payroll: 'com.intuit.quickbooks.payroll',
  TimeTracking: 'com.intuit.quickbooks.payroll.timetracking',
  Benefits: 'com.intuit.quickbooks.payroll.benefits',
  Profile: 'profile',
  Email: 'email',
  Phone: 'phone',
  Address: 'address',
  OpenId: 'openid',
  Intuit_name: 'intuit_name',
};
OAuthClient.user_agent = `Intuit-OAuthClient-JS_${version}_${os.type()}_${os.release()}_${os.platform()}`;


/**
 * Redirect  User to Authorization Page
 * @param params
 * @returns {string} authorize Uri
 */
OAuthClient.prototype.authorizeUri = function authorizeUri(params) {
  params = params || {};

  // check if the scopes is provided
  if (!params.scope) throw new Error('Provide the scopes');

  const authUri = `${OAuthClient.authorizeEndpoint}?${queryString.stringify({
    response_type: 'code',
    redirect_uri: this.redirectUri,
    client_id: this.clientId,
    scope: (Array.isArray(params.scope)) ? params.scope.join(' ') : params.scope,
    state: params.state || this.state.create(this.state.secretSync()),
  })}`;

  this.log('info', 'The Authorize Uri is :', authUri);
  return authUri;
};


/**
 * Create Token { exchange code for bearer_token }
 * @param options
 * @returns {Promise<any>}
 */
OAuthClient.prototype.createToken = function createToken(uri) {
  return (new Promise(((resolve) => {
    if (!uri) throw new Error('Provide the Uri');
    const params = queryString.parse(uri.split('?').reverse()[0]);
    this.getToken().realmId = (params.realmId ? params.realmId : '');

    const body = {};
    if (params.code) {
      body.grant_type = 'authorization_code';
      body.code = params.code;
      body.redirect_uri = params.redirectUri || this.redirectUri;
    }

    const request = {
      url: OAuthClient.tokenEndpoint,
      body,
      method: 'POST',
      headers: {
        Authorization: `Basic ${this.authHeader()}`,
        'Content-Type': AuthResponse._urlencodedContentType,
        Accept: AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    resolve(this.getTokenRequest(request));
  }))).then((res) => {
    const authResponse = res.json ? res : null;
    const json = (authResponse && authResponse.getJson()) || res;
    this.token.setToken(json);
    if (this.autoRefresh) {
      this.log('info', 'Setting AutoRefresh of tokens every: ', this.autoRefreshIntervalInSeconds + ' seconds');
      // Set auto refresh call
      this.autoRefreshHandle = setInterval(() => this.refresh(), this.autoRefreshIntervalInSeconds * 1000);
    }
    this.log('info', 'Create Token response is : ', JSON.stringify(authResponse, null, 2));
    return authResponse;
  }).catch((e) => {
    this.log('error', 'Create Token () threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};


/**
 * Refresh Token { Refresh access_token }
 * @param {Object} params.refresh_token (optional)
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.refresh = function refresh() {
  return (new Promise(((resolve) => {
    /**
     * Check if the tokens exist and are valid
     */
    this.validateToken();

    const body = {};

    body.grant_type = 'refresh_token';
    body.refresh_token = this.getToken().refresh_token;

    const request = {
      url: OAuthClient.tokenEndpoint,
      body,
      method: 'POST',
      headers: {
        Authorization: `Basic ${this.authHeader()}`,
        'Content-Type': AuthResponse._urlencodedContentType,
        Accept: AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    resolve(this.getTokenRequest(request));
  }))).then((res) => {
    const authResponse = res.json ? res : null;
    const json = (authResponse && authResponse.getJson()) || res;
    this.token.setToken(json);
    this.log('info', 'Refresh Token () response is : ', JSON.stringify(authResponse, null, 2));
    return authResponse;
  }).catch((e) => {
    this.log('error', 'Refresh Token () threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};


/**
 * Refresh Tokens by passing refresh_token parameter explicitly
 * { Refresh access_token by passing refresh_token }
 * @param {Object} params.refresh_token (refresh_token)
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.refreshUsingToken = function refreshUsingToken(refresh_token) {
  return (new Promise(((resolve) => {
    /**
     * Check if the tokens exist
     */

    if (!refresh_token) throw new Error('The Refresh token is missing');

    const body = {};

    body.grant_type = 'refresh_token';
    body.refresh_token = refresh_token;

    const request = {
      url: OAuthClient.tokenEndpoint,
      body,
      method: 'POST',
      headers: {
        Authorization: `Basic ${this.authHeader()}`,
        'Content-Type': AuthResponse._urlencodedContentType,
        Accept: AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    resolve(this.getTokenRequest(request));
  }))).then((res) => {
    const authResponse = res.json ? res : null;

    // New changes that are added
    const json = (authResponse && authResponse.getJson()) || res;
    this.token.setToken(json);
    this.log('info', 'Refresh usingToken () response is : ', JSON.stringify(authResponse, null, 2));
    return authResponse;
  }).catch((e) => {
    this.log('error', 'Refresh Token () threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Revoke Token { revoke access/refresh_token }
 * @param {Object} params.access_token (optional)
 * @param {Object} params.refresh_token (optional)
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.revoke = function revoke(params) {
  return (new Promise(((resolve) => {
    params = params || {};

    const body = {};

    body.token = params.access_token || params.refresh_token ||
      (this.getToken().isAccessTokenValid()
        ? this.getToken().access_token
        : this.getToken().refresh_token);

    const request = {
      url: OAuthClient.revokeEndpoint,
      body,
      method: 'POST',
      headers: {
        Authorization: `Basic ${this.authHeader()}`,
        Accept: AuthResponse._jsonContentType,
        'Content-Type': AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    resolve(this.getTokenRequest(request));
  }))).then((authResponse) => {
    this.token.clearToken();
    this.log('info', 'Revoke Token () response is : ', JSON.stringify(authResponse, null, 2));
    return authResponse;
  }).catch((e) => {
    this.log('error', 'Revoke Token () threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get User Info  { Get User Info }
 * @param {Object} params
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.getUserInfo = function getUserInfo(params) {
  return (new Promise(((resolve) => {
    params = params || {};

    const request = {
      url: this.environment === 'sandbox' ? OAuthClient.userinfo_endpoint_sandbox : OAuthClient.userinfo_endpoint_production,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.token.access_token}`,
        Accept: AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    resolve(this.getTokenRequest(request));
  }))).then((res) => {
    const authResponse = res.json ? res : null;
    this.log('info', 'The Get User Info () response is : ', JSON.stringify(authResponse, null, 2));
    return authResponse;
  }).catch((e) => {
    this.log('error', 'Get User Info ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Make API call : Make API Call
 * @param params
 * @returns {Promise<any>}
 */
OAuthClient.prototype.makeApiCall = function makeApiCall(params) {
  return (new Promise(((resolve) => {
    params = params || {};

    const request = {
      url: params.url,
      method: params.method || 'GET',
      headers: {
        Authorization: `Bearer ${this.getToken().access_token}`,
        Accept: AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    if (params.headers && typeof params.headers === 'object') {
      for (const header in params.headers) {
        request.headers[header] = params.headers[header];
      }
    }

    params.body && (request.body = params.body);

    resolve(this.getTokenRequest(request));
  }))).then((authResponse) => {
    this.log('info', 'The makeAPICall () response is : ', JSON.stringify(authResponse, null, 2));
    return authResponse;
  }).catch((e) => {
    this.log('error', 'Get makeAPICall ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Migrate OAuth1.0 apps to support OAuth2.0
 * @param params
 * @returns {Promise<any>}
 */
OAuthClient.prototype.migrate = function migrate(params) {
  return (new Promise(((resolve) => {
    params = params || {};

    const uri = this.environment.toLowerCase() === 'sandbox' ? OAuthClient.migrate_sandbox : OAuthClient.migrate_production;

    const authHeader = this.generateOauth1Sign(objectAssign({}, { method: 'POST', uri }, params));

    const body = {
      scope: (Array.isArray(params.scope)) ? params.scope.join(' ') : params.scope,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      client_secret: this.clientSecret,
    };

    const request = {
      url: uri,
      method: 'POST',
      body,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `OAuth ${authHeader}`,
        Accept: AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    resolve(this.getTokenRequest(request));
  }))).then((res) => {
    const authResponse = res.json ? res : null;
    const json = (authResponse && authResponse.getJson()) || res;
    this.token.setToken(json);
    this.log('info', 'The migrate () response is : ', JSON.stringify(authResponse, null, 2));
    return authResponse;
  }).catch((e) => {
    this.log('error', 'The migrate () threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Generate oAuth1 Sign : Helper Method to Migrate OAuth1.0 apps to OAuth2.0
 * @param params
 * @returns {string}
 */
OAuthClient.prototype.generateOauth1Sign = function generateOauth1Sign(params) {
  const timestamp = Math.round(new Date().getTime() / 1000);

  const parameters = {
    oauth_consumer_key: params.oauth_consumer_key,
    oauth_token: params.access_token,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: timestamp,
    oauth_nonce: 'nonce',
    oauth_version: '1.0',
  };

  const encodedSignature = oauthSignature.generate(
    params.method,
    params.uri,
    parameters,
    params.oauth_consumer_secret,
    params.access_secret
  );

  parameters.oauth_signature = encodedSignature;

  const authHeader = Object.entries(parameters).reduce((header, [key, val], idx, array) => {
    // Add this for Accounting API minorversion url query parameter
    if (key === 'minorversion') {
      return header;
    }
    if (idx === array.length - 1) {
      return `${header}${key}="${val}"`;
    }
    return `${header}${key}="${val}",`;
  }, '');

  return authHeader;
};

/**
 * Validate id_token
 * @param params
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.validateIdToken = function validateIdToken(params = {}) {
  return (new Promise(((resolve) => {
    if (!this.getToken().id_token) throw new Error('The bearer token does not have id_token');

    const id_token = this.getToken().id_token || params.id_token;

    // Decode ID Token
    const token_parts = id_token.split('.');
    const id_token_header = JSON.parse(atob(token_parts[0]));
    const id_token_payload = JSON.parse(atob(token_parts[1]));

    // Step 1 : First check if the issuer is as mentioned in "issuer"
    if (id_token_payload.iss !== 'https://oauth.platform.intuit.com/op/v1') return false;

    // Step 2 : check if the aud field in idToken is same as application's clientId
    if (id_token_payload.aud !== this.clientId) return false;

    // Step 3 : ensure the timestamp has not elapsed
    if (id_token_payload.exp < Date.now() / 1000) return false;

    const request = {
      url: OAuthClient.jwks_uri,
      method: 'GET',
      headers: {
        Accept: AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    return resolve(this.getKeyFromJWKsURI(id_token, id_token_header.kid, request));
  }))).then((res) => {
    this.log('info', 'The validateIdToken () response is : ', JSON.stringify(res, null, 2));
    if (res) return true;
    return false;
  }).catch((e) => {
    this.log('error', 'The validateIdToken () threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 *
 * @param id_token
 * @param kid
 * @param request
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.getKeyFromJWKsURI = function getKeyFromJWKsURI(id_token, kid, request) {
  return (new Promise(((resolve) => {
    resolve(this.loadResponse(request));
  }))).then((response) => {
    if (response.status !== '200') throw new Error('Could not reach JWK endpoint');

    // Find the key by KID
    const responseBody = JSON.parse(response.body);
    const key = responseBody.keys.find(el => (el.kid === kid));
    const cert = this.getPublicKey(key.n, key.e);

    return jwt.verify(id_token, cert);
  }).catch((e) => {
    e = this.createError(e);
    this.log('error', 'The getKeyFromJWKsURI () threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * get Public Key
 * @param modulus
 * @param exponent
 */
OAuthClient.prototype.getPublicKey = function getPublicKey(modulus, exponent) {
  // eslint-disable-next-line global-require
  const getPem = require('rsa-pem-from-mod-exp');
  const pem = getPem(modulus, exponent);
  return pem;
};

/**
 * Get Token Request
 * @param {Object} request
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.getTokenRequest = function getTokenRequest(request) {
  const authResponse = new AuthResponse({ token: this.token });

  return (new Promise(((resolve) => {
    resolve(this.loadResponse(request));
  }))).then((response) => {
    authResponse.processResponse(response);

    if (!authResponse.valid()) throw new Error('Response has an Error');

    return authResponse;
  }).catch((e) => {
    if (!e.authResponse) e = this.createError(e, authResponse);
    throw e;
  });
};

/**
 * Token Validation
 */
OAuthClient.prototype.validateToken = function validateToken() {
  if (!this.token.refreshToken()) throw new Error('The Refresh token is missing');
  if (!this.token.isRefreshTokenValid()) throw new Error('The Refresh token is invalid, please Authorize again.');
};


/**
 * Make HTTP Request using Popsicle Client
 * @param request
 * @returns response
 */
OAuthClient.prototype.loadResponse = function loadResponse(request) {
  return popsicle.get(request).then(response => response);
};

/**
 * Load response from JWK URI
 * @param request
 * @returns response
 */
OAuthClient.prototype.loadResponseFromJWKsURI = function loadResponseFromJWKsURI(request) {
  return popsicle.get(request).then(response => response);
};

/**
 * Wrap the exception with more information
 * @param {Error|IApiError} e
 * @param {AuthResponse} authResponse
 * @return {Error|IApiError}
 */
OAuthClient.prototype.createError = function createError(e, authResponse) {
  if (!authResponse || authResponse.body === '') {
    e.error = (authResponse && authResponse.response.statusText) || e.message || '';
    e.authResponse = authResponse || '';
    e.intuit_tid = (authResponse && authResponse.headers().intuit_tid) || '';
    e.originalMessage = e.message || '';
    e.error_description = (authResponse && authResponse.response.statusText) || '';
    return e;
  }

  e.authResponse = authResponse;
  e.originalMessage = e.message;

  e.error = '';
  if ('error' in authResponse.getJson()) {
    e.error = authResponse.getJson().error;
  } else if (authResponse.response.statusText) {
    e.error = authResponse.response.statusText;
  } else if (e.message) {
    e.error = e.message;
  }

  e.error_description = '';
  if ('error_description' in authResponse.getJson()) {
    e.error_description = authResponse.getJson().error_description;
  } else if (authResponse.response.statusText) {
    e.error_description = authResponse.response.statusText;
  }
  e.intuit_tid = authResponse.headers().intuit_tid;

  return e;
};

/**
 * isAccessToken Valid () { TTL of access_token }
 * @returns {boolean}
 * @private
 */
OAuthClient.prototype.isAccessTokenValid = function isAccessTokenValid() {
  return this.token.isAccessTokenValid();
};

/**
 * GetToken
 * @returns {Token}
 */
OAuthClient.prototype.getToken = function getToken() {
  return this.token;
};


/**
 * Set Token
 * @param {Object}
 * @returns {Token}
 */
OAuthClient.prototype.setToken = function setToken(params) {
  this.token = new Token(params);
  return this.token;
};

/**
 * Stops auto refresh of tokens
 */
OAuthClient.prototype.stopAutoRefresh = function () {
  if (this.autoRefreshHandle) {
    clearInterval(this.autoRefreshHandle);
  } else {
    this.log('info', 'AutoRefresh is not set so it cannot be cleared');
  }
};


/**
 * Get AuthHeader
 * @returns {string} authHeader
 */
OAuthClient.prototype.authHeader = function authHeader() {
  const apiKey = `${this.clientId}:${this.clientSecret}`;
  return (typeof btoa === 'function') ? btoa(apiKey) : Buffer.from(apiKey).toString('base64');
};

OAuthClient.prototype.log = function log(level, message, messageData) {
  if (this.logging) {
    this.logger.log(level, message + messageData);
  }
};

module.exports = OAuthClient;
