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
const Csrf = require('csrf');
const queryString = require('query-string');
const popsicle = require('popsicle');
const os = require('os');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const https = require('https');
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
  this.realmId = config.realmId;
  this.token = new Token(config.token);
  this.logging = !!(
    Object.prototype.hasOwnProperty.call(config, 'logging') && config.logging === true
  );
  this.logger = null;
  this.state = new Csrf();

  if (this.logging) {
    const dir = './logs';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf((info) => `${info.timestamp} ${info.level}: ${info.message}`),
      ),
      transports: [
        new winston.transports.File({
          filename: path.join(dir, 'oAuthClient-log.log'),
        }),
      ],
    });
  }
}

OAuthClient.cacheId = 'cacheID';
OAuthClient.authorizeEndpoint = 'https://appcenter.intuit.com/connect/oauth2';
OAuthClient.tokenEndpoint = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
OAuthClient.revokeEndpoint = 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke';
OAuthClient.userinfo_endpoint_production =
  'https://accounts.platform.intuit.com/v1/openid_connect/userinfo';
OAuthClient.userinfo_endpoint_sandbox =
  'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo';
OAuthClient.migrate_sandbox = 'https://developer-sandbox.api.intuit.com/v2/oauth2/tokens/migrate';
OAuthClient.migrate_production = 'https://developer.api.intuit.com/v2/oauth2/tokens/migrate';
OAuthClient.environment = {
  sandbox: 'https://sandbox-quickbooks.api.intuit.com/',
  production: 'https://quickbooks.api.intuit.com/',
};
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
OAuthClient.user_agent = `Intuit-OAuthClient-JS_${
  version.version
}_${os.type()}_${os.release()}_${os.platform()}`;

OAuthClient.prototype.setAuthorizeURLs = function setAuthorizeURLs(params) {
  // check if the customURL's are passed correctly
  if (!params) {
    throw new Error("Provide the custom authorize URL's");
  }
  OAuthClient.authorizeEndpoint = params.authorizeEndpoint;
  OAuthClient.tokenEndpoint = params.tokenEndpoint;
  OAuthClient.revokeEndpoint = params.revokeEndpoint;
  this.environment === 'sandbox'
    ? (OAuthClient.userinfo_endpoint_sandbox = params.userInfoEndpoint)
    : (OAuthClient.userinfo_endpoint_production = params.userInfoEndpoint);

  return this;
};

/**
 * Redirect  User to Authorization Page
 * *
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
    scope: Array.isArray(params.scope) ? params.scope.join(' ') : params.scope,
    state: params.state || this.state.create(this.state.secretSync()),
  })}`;

  this.log('info', 'The Authorize Uri is :', authUri);
  return authUri;
};

/**
 * Create Token { exchange authorization code for bearer_token }
 * *
 * @param {string|Object} uri
 * @returns {Promise}
 */
OAuthClient.prototype.createToken = function createToken(uri) {
  return new Promise((resolve) => {
    if (!uri) throw new Error('Provide the Uri');
    const params = queryString.parse(uri.split('?').reverse()[0]);
    this.getToken().realmId = params.realmId ? params.realmId : '';
    if (this.getToken().realmId) this.realmId = this.getToken().realmId;
    else if (this.realmId && typeof(this.realmId)==="string") this.getToken().realmId = this.realmId;
    if ('state' in params) this.getToken().state = params.state;

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
  })
    .then((res) => {
      const authResponse = res.json ? res : null;
      const json = (authResponse && authResponse.getJson()) || res;
      this.token.setToken(json);
      this.log('info', 'Create Token response is : ', JSON.stringify(authResponse, null, 2));
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Create Token () threw an exception : ', JSON.stringify(e, null, 2));
      throw e;
    });
};

/**
 * Refresh the access_token
 * *
 * @returns {Promise}
 */
OAuthClient.prototype.refresh = function refresh() {
  return new Promise((resolve) => {
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
  })
    .then((res) => {
      const authResponse = res.json ? res : null;
      const json = (authResponse && authResponse.getJson()) || res;
      this.token.setToken(json);
      if (!this.getToken().realmId && this.realmId && typeof(this.realmId)==="string") {
        this.getToken().realmId = this.realmId;
      }
      this.log('info', 'Refresh Token () response is : ', JSON.stringify(authResponse, null, 2));
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Refresh Token () threw an exception : ', JSON.stringify(e, null, 2));
      throw e;
    });
};

/**
 * Refresh Tokens by passing refresh_token parameter explicitly
 * *
 * @param {string} refresh_token
 * @returns {Promise}
 */
OAuthClient.prototype.refreshUsingToken = function refreshUsingToken(refresh_token) {
  return new Promise((resolve) => {
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
  })
    .then((res) => {
      const authResponse = res.json ? res : null;
      const json = (authResponse && authResponse.getJson()) || res;
      this.token.setToken(json);
      if (!this.getToken().realmId && this.realmId && typeof(this.realmId)==="string") {
        this.getToken().realmId = this.realmId;
      }
      this.log(
        'info',
        'Refresh usingToken () response is : ',
        JSON.stringify(authResponse, null, 2),
      );
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Refresh Token () threw an exception : ', JSON.stringify(e, null, 2));
      throw e;
    });
};

/**
 * Revoke access_token/refresh_token
 * *
 * @param {Object} params.access_token (optional)
 * @param {Object} params.refresh_token (optional)
 * @returns {Promise}
 */
OAuthClient.prototype.revoke = function revoke(params) {
  return new Promise((resolve) => {
    params = params || {};

    const body = {};

    body.token =
      params.access_token ||
      params.refresh_token ||
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
  })
    .then((authResponse) => {
      this.token.clearToken();
      this.log('info', 'Revoke Token () response is : ', JSON.stringify(authResponse, null, 2));
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Revoke Token () threw an exception : ', JSON.stringify(e, null, 2));
      throw e;
    });
};

/**
 * Get User Info  { Get User Info }
 * *
 * @returns {Promise}
 */
OAuthClient.prototype.getUserInfo = function getUserInfo() {
  return new Promise((resolve) => {
    const request = {
      url:
        this.environment === 'sandbox'
          ? OAuthClient.userinfo_endpoint_sandbox
          : OAuthClient.userinfo_endpoint_production,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.token.access_token}`,
        Accept: AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent,
      },
    };

    resolve(this.getTokenRequest(request));
  })
    .then((res) => {
      const authResponse = res.json ? res : null;
      this.log(
        'info',
        'The Get User Info () response is : ',
        JSON.stringify(authResponse, null, 2),
      );
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Get User Info ()  threw an exception : ', JSON.stringify(e, null, 2));
      throw e;
    });
};

/**
 * Make API call. Pass the url,method,headers using `params` object
 * *
 * @param {Object} params
 * @returns {Promise}
 */
OAuthClient.prototype.makeApiCall = function makeApiCall(params) {
  return new Promise((resolve) => {
    params = params || {};

    const headers =
      params.headers && typeof params.headers === 'object'
        ? Object.assign(
            {},
            {
              Authorization: `Bearer ${this.getToken().access_token}`,
              Accept: AuthResponse._jsonContentType,
              'User-Agent': OAuthClient.user_agent,
            },
            params.headers,
          )
        : Object.assign(
            {},
            {
              Authorization: `Bearer ${this.getToken().access_token}`,
              Accept: AuthResponse._jsonContentType,
              'User-Agent': OAuthClient.user_agent,
            },
          );

    const request = {
      url: params.url,
      method: params.method || 'GET',
      headers,
    };

    params.body && (request.body = params.body);

    resolve(this.getTokenRequest(request));
  })
    .then((authResponse) => {
      this.log('info', 'The makeAPICall () response is : ', JSON.stringify(authResponse, null, 2));
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Get makeAPICall ()  threw an exception : ', JSON.stringify(e, null, 2));
      throw e;
    });
};

/**
 * Validate id_token
 * *
 * @param {Object} params(optional)
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.validateIdToken = function validateIdToken(params = {}) {
  return new Promise((resolve) => {
    if (!this.getToken().id_token) throw new Error('The bearer token does not have id_token');

    const id_token = this.getToken().id_token || params.id_token;

    // Decode ID Token
    const token_parts = id_token.split('.');
    const id_token_header = JSON.parse(atob(token_parts[0]));
    const id_token_payload = JSON.parse(atob(token_parts[1]));

    // Step 1 : First check if the issuer is as mentioned in "issuer"
    if (id_token_payload.iss !== 'https://oauth.platform.intuit.com/op/v1') return false;

    // Step 2 : check if the aud field in idToken contains application's clientId
    if (!id_token_payload.aud.find((audience) => audience === this.clientId)) return false;

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
  })
    .then((res) => {
      this.log('info', 'The validateIdToken () response is : ', JSON.stringify(res, null, 2));
      if (res) return true;
      return false;
    })
    .catch((e) => {
      this.log('error', 'The validateIdToken () threw an exception : ', JSON.stringify(e, null, 2));
      throw e;
    });
};

/**
 * Get Key from JWKURI
 * *
 * @param {string} id_token
 * @param {string} kid
 * @param {Object} request
 * @returns {Promise}
 */
OAuthClient.prototype.getKeyFromJWKsURI = function getKeyFromJWKsURI(id_token, kid, request) {
  return new Promise((resolve) => {
    resolve(this.loadResponse(request));
  })
    .then((response) => {
      if (Number(response.status) !== 200) throw new Error('Could not reach JWK endpoint');
      // Find the key by KID
      const responseBody = JSON.parse(response.body);
      const key = responseBody.keys.find((el) => el.kid === kid);
      const cert = this.getPublicKey(key.n, key.e);

      return jwt.verify(id_token, cert);
    })
    .catch((e) => {
      e = this.createError(e);
      this.log(
        'error',
        'The getKeyFromJWKsURI () threw an exception : ',
        JSON.stringify(e, null, 2),
      );
      throw e;
    });
};

/**
 * Get Public Key
 * *
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
 * *
 * @param {Object} request
 * @returns {Promise}
 */
OAuthClient.prototype.getTokenRequest = function getTokenRequest(request) {
  const authResponse = new AuthResponse({
    token: this.token,
  });

  return new Promise((resolve) => {
    resolve(this.loadResponse(request));
  })
    .then((response) => {
      authResponse.processResponse(response);

      if (!authResponse.valid()) throw new Error('Response has an Error');

      return authResponse;
    })
    .catch((e) => {
      if (!e.authResponse) e = this.createError(e, authResponse);
      throw e;
    });
};

/**
 * Validate Token
 * *
 * @returns {boolean}
 */
OAuthClient.prototype.validateToken = function validateToken() {
  if (!this.token.refreshToken()) throw new Error('The Refresh token is missing');
  if (!this.token.isRefreshTokenValid())
    throw new Error('The Refresh token is invalid, please Authorize again.');
};

/**
 * Make HTTP Request using Popsicle Client
 * @param request
 * @returns response
 */
OAuthClient.prototype.loadResponse = function loadResponse(request) {
  return popsicle.get(request).then((response) => response);
};

/**
 * Load response from JWK URI
 * @param request
 * @returns response
 */
OAuthClient.prototype.loadResponseFromJWKsURI = function loadResponseFromJWKsURI(request) {
  return popsicle.get(request).then((response) => response);
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
    e.intuit_tid =
      (authResponse && authResponse.headers() && authResponse.headers().intuit_tid) || '';
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
 * Get AuthHeader
 * @returns {string} authHeader
 */
OAuthClient.prototype.authHeader = function authHeader() {
  const apiKey = `${this.clientId}:${this.clientSecret}`;
  return typeof btoa === 'function' ? btoa(apiKey) : Buffer.from(apiKey).toString('base64');
};

OAuthClient.prototype.log = function log(level, message, messageData) {
  if (this.logging) {
    this.logger.log(level, message + messageData);
  }
};

/**
 * This is a generic method for performing API call
 * We also have makeAPICall() but here we are first checking whether token is valid, realm Id is there
 * @param {object} options0 - Fetch API call options, defaults to GET method
 * @param {string} entity0 - QuickBooks Entity name e.g. CompanyInfo (Important: Case sensitive)
 * @param {string|number} [id0] - If GET method, specify Id of Entity (wherever required)
 * @returns {Promise} - Quickbooks Entity Object or Response of API
 */

OAuthClient.prototype.fetchAPI = function fetchAPI(options0, entity0, id0) {
  let name0;
  return new Promise((resolve) => {
    if (!entity0 || typeof(entity0)!=='string' || !entity0.slice(0,50).trim()) throw new Error('Invalid Quickbooks Entity!');
    entity0 = entity0.slice(0,50).trim();
    name0 = entity0[0].toUpperCase() + entity0.slice(1);
    entity0 = entity0.toLowerCase();
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const entity_id = parseInt(id0, 10);
    if (id0 && Number.isNaN(entity_id)) throw new Error(`Invalid ${name0} Id! Must be a number or number as a string!`);
    const companyID = this.getToken().realmId;
    if (!companyID) throw new Error('Realm Id missing! Please create a new token using OAuth and try again.');
    const url0 = this.environment === 'sandbox'
      ? OAuthClient.environment.sandbox
      : OAuthClient.environment.production;
    const headers0 = {
      Authorization: `Bearer ${this.getToken().access_token}`,
      Accept: AuthResponse._jsonContentType,
      'User-Agent': OAuthClient.user_agent,
    };
    let extendURL = entity0;
    if (id0) {
      extendURL += `/${entity_id}`;
    }
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/${extendURL}`,
      headers: headers0,
    };
    if (options0 && typeof(options0)==='object' && typeof(options0.method)==='string') {
      request.method = options0.method;
      if (options0.method.toUpperCase()!=='GET') {
        request.body = options0.body;
      }
      if (options0.headers && typeof(options0.headers)==='object') {
        Object.assign(request.headers, options0.headers);
      }
    }
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', `The fetch on ${entity0} () response is : `, JSON.stringify(authResponse, null, 2));
    let myEntity;
    if (authResponse.headers()['content-type'].indexOf('json')>-1) {
      myEntity = JSON.parse(authResponse.text())[name0];
    }
    else {
      myEntity = authResponse.text();
    }
    return myEntity;
  })
  .catch((e) => {
    this.log('error', `The fetch on ${entity0} ()  threw an exception : `, JSON.stringify(e, null, 2));
    throw e;
  });
}

/**
 * This is a method for getting a PDF
 * @param {string} entity0 - QuickBooks Entity name e.g. Invoice (Important: Case sensitive)
 * @param {string|number} id0 - Specify Id of Entity (required)
 * @returns {Promise} - PDF response (It is a buffer in the form of PDF)
 */

 OAuthClient.prototype.fetchPDF = function fetchPDF(entity0, id0) {
  let name0;
  return new Promise((resolve) => {
    if (!entity0 || typeof(entity0)!=='string' || !entity0.slice(0,50).trim()) throw new Error('Invalid Quickbooks Entity!');
    entity0 = entity0.slice(0,50).trim();
    name0 = entity0[0].toUpperCase() + entity0.slice(1);
    entity0 = entity0.toLowerCase();
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const entity_id = parseInt(id0, 10);
    if (Number.isNaN(entity_id)) throw new Error(`Invalid ${name0} Id! Must be a number or number as a string!`);
    const companyID = this.getToken().realmId;
    if (!companyID) throw new Error('Realm Id missing! Please create a new token using OAuth and try again.');
    const url0 = this.environment === 'sandbox'
      ? OAuthClient.environment.sandbox
      : OAuthClient.environment.production;
    const headers0 = {
      Authorization: `Bearer ${this.getToken().access_token}`,
      Accept: AuthResponse._pdfContentType,
      'User-Agent': OAuthClient.user_agent,
    };
    const extendURL = `${entity0}/${entity_id}/pdf`;
    const req_options = {
      method: 'GET',
      headers: headers0,
    };
    const get_url = `${url0}v3/company/${companyID}/${extendURL}`;
    const request = https.get(get_url, req_options, (resp) => {
      let myPDFBuffer = [];
      resp.on('data', (chunk) => {
        myPDFBuffer.push(chunk);
      });
      resp.on('end', () => {
        resolve(Buffer.concat(myPDFBuffer));
      });
    });
    request.on('error', (er) => {
      throw er;
    });
    request.end();
  })
  .then((authResponse) => {
    this.log('info', `The get${entity0}PDF () response is : `, authResponse ? authResponse.toString() : "EMPTY");
    return authResponse;
  })
  .catch((e) => {
    this.log('error', `Get ${entity0} PDF ()  threw an exception : `, JSON.stringify(e, null, 2));
    throw e;
  });
}

/* CREATE ENTITIES */

/**
 * Create quickbooks Account
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/account#create-an-account
 * 
 * Refer to above link for exact fields and description
 * @param {object} accountObj - Object to create: Account
 * @param {string} accountObj.Name - Unique name for Account
 * @param {string} accountObj.AccountType - Account Type Enum i.e. must be one of the Account types, default 'Accounts Receivable'
 * @returns {Promise} QuickBooks Account created
 */

 OAuthClient.prototype.createAccount = function createAccount(accountObj) {
  if (!accountObj || typeof(accountObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(accountObj),
  }, 'Account');
};

/**
 * Create quickbooks Bill
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/bill#create-a-bill
 * 
 * Refer to above link for exact fields and description
 * @param {object} billObj - Object to create: Bill
 * @param {object} billObj.Line - Line must be a JSON for Bill
 * @param {string} billObj.Line.DetailType - Set to 'AccountBasedExpenseLineDetail'
 * @param {number} billObj.Line.Amount - Amount payable for this Bill
 * @param {object} billObj.Line.AccountBasedExpenseLineDetail - Account details
 * @param {object} billObj.Line.AccountBasedExpenseLineDetail.AccountRef - Account associated with this Bill
 * @param {string} billObj.Line.AccountBasedExpenseLineDetail.AccountRef.value - String Id of Account
 * @param {object} billObj.VendorRef - Vendor associated with this Bill
 * @param {string} billObj.VendorRef.value - String Id of Vendor associated with this Bill
 * @param {object} billObj.CurrencyRef - Currency Ref string
 * @param {string} billObj.CurrencyRef.value - E.g. 'USD'
 * @returns {Promise} QuickBooks Bill created
 */

OAuthClient.prototype.createBill = function createBill(billObj) {
  if (!billObj || typeof(billObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(billObj),
  }, 'Bill');
};

/**
 * Create quickbooks Customer
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/customer#create-a-customer
 * 
 * DisplayName OR at least one of Title, GivenName, MiddleName, FamilyName, or Suffix must be present
 * The equivalent Name must be UNIQUE
 * Refer to above link for exact fields and description
 * @param {object} customerObj - Object to create: Customer
 * @returns {Promise} QuickBooks Customer created
 */

OAuthClient.prototype.createCustomer = function createCustomer(customerObj) {
  if (!customerObj || typeof(customerObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(customerObj),
  }, 'Customer');
};

/**
 * Create quickbooks Employee
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/employee#create-an-employee
 * 
 * Refer to above link for exact fields and description
 * @param {object} employeeObj - Object to create: Employee
 * @returns {Promise} QuickBooks Employee created
 */

OAuthClient.prototype.createEmployee = function createEmployee(employeeObj) {
  if (!employeeObj || typeof(employeeObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(employeeObj),
  }, 'Employee');
};

/**
 * Create quickbooks Estimate
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/estimate#create-an-estimate
 * 
 * Refer to above link for exact fields and description
 * @param {object} estimateObj - Object to create: Estimate
 * @param {object} estimateObj.Line - Line details
 * @param {string} estimateObj.Line.DetailType - Type of Line
 * @param {object} estimateObj.CustomerRef - Customer associated with this Estimate
 * @param {string} estimateObj.CustomerRef.value - String Id of Customer associated with this Estimate
 * @param {object} estimateObj.CurrencyRef - Currency Ref string
 * @param {string} estimateObj.CurrencyRef.value - E.g. 'USD'
 * @returns {Promise} QuickBooks Estimate created
 */

OAuthClient.prototype.createEstimate = function createEstimate(estimateObj) {
  if (!estimateObj || typeof(estimateObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(estimateObj),
  }, 'Estimate');
};

/**
 * Create quickbooks Invoice
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/invoice#create-an-invoice
 * 
 * Refer to above link for exact fields and description
 * @param {object} invoiceObj - Object to create: Invoice
 * @param {object} invoiceObj.Line - Line details
 * @param {string} invoiceObj.Line.DetailType - Type of Line
 * @param {object} invoiceObj.CustomerRef - Customer associated with this Invoice
 * @param {string} invoiceObj.CustomerRef.value - String Id of Customer associated with this Invoice
 * @param {object} invoiceObj.CurrencyRef - Currency Ref string
 * @param {string} invoiceObj.CurrencyRef.value - E.g. 'USD'
 * @returns {Promise} QuickBooks Invoice created
 */

OAuthClient.prototype.createInvoice = function createInvoice(invoiceObj) {
  if (!invoiceObj || typeof(invoiceObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(invoiceObj),
  }, 'Invoice');
};

/**
 * Create quickbooks Item
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/item#create-an-item
 * 
 * Refer to above link for exact fields and description
 * @param {object} itemObj - Object to create: Item
 * @returns {Promise} QuickBooks Item created
 */

OAuthClient.prototype.createItem = function createItem(itemObj) {
  if (!itemObj || typeof(itemObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(itemObj),
  }, 'Item');
};

/**
 * Create quickbooks Payment
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/payment#create-a-payment
 * 
 * Refer to above link for exact fields and description
 * @param {object} paymentObj - Object to create: Payment
 * @param {number} paymentObj.TotalAmt - Total amount of Payment
 * @param {object} paymentObj.CustomerRef - Customer associated with this Payment
 * @param {string} paymentObj.CustomerRef.value - String Id of Customer associated with this Payment
 * @param {object} paymentObj.CurrencyRef - Currency Ref string
 * @param {string} paymentObj.CurrencyRef.value - E.g. 'USD'
 * @returns {Promise} QuickBooks Payment created
 */

OAuthClient.prototype.createPayment = function createPayment(paymentObj) {
  if (!paymentObj || typeof(paymentObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(paymentObj),
  }, 'Payment');
};

/**
 * Create quickbooks TaxAgency
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/taxagency#create-a-taxagency
 * 
 * Refer to above link for exact fields and description
 * @param {object} tax_agencyObj - Object to create: TaxAgency
 * @param {string} tax_agencyObj.DisplayName - Name of TaxAgency
 * @returns {Promise} QuickBooks TaxAgency created
 */

OAuthClient.prototype.createTaxAgency = function createTaxAgency(tax_agencyObj) { // check
  if (!tax_agencyObj || typeof(tax_agencyObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(tax_agencyObj),
  }, 'TaxAgency');
};

/**
 * Create quickbooks Vendor
 * https://developer.intuit.com/app/developer/qbo/docs/api/accounting/most-commonly-used/vendor#create-a-vendor
 * 
 * DisplayName OR at least one of Title, GivenName, MiddleName, FamilyName, or Suffix must be present
 * The equivalent Name must be UNIQUE
 * Refer to above link for exact fields and description
 * @param {object} vendorObj - Object to create: Vendor
 * @returns {Promise} QuickBooks Vendor created
 */

 OAuthClient.prototype.createVendor = function createVendor(vendorObj) {
  if (!vendorObj || typeof(vendorObj)!=='object') return new Error('Cannot create empty object!');
  return this.fetchAPI({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(vendorObj),
  }, 'Vendor');
};

/* END CREATE ENTITIES */

/* DELETE ENTITIES */

/* END DELETE ENTITIES */

/* GET ENTITIES */

/**
 * Get details of a quickbooks Account
 * @param {string|number} acc_id - Id reference of Account
 * @returns {Promise} QuickBooks Account
 */

OAuthClient.prototype.getAccount = function getAccount(acc_id) {
  return this.fetchAPI(null, 'Account', acc_id);
};

/**
 * Get details of a quickbooks Bill
 * @param {string|number} bill_id - Id reference of Bill
 * @returns {Promise} QuickBooks Bill
 */

OAuthClient.prototype.getBill = function getBill(bill_id) {
  return this.fetchAPI(null, 'Bill', bill_id);
};

/**
 * Get details of a quickbooks companyInfo based on realmId
 * @returns {Promise} QuickBooks CompanyInfo
 */

OAuthClient.prototype.getCompanyInfo = function getCompanyInfo() { // check
  return this.fetchAPI(null, 'CompanyInfo', this.getToken().realmId);
};

/**
 * Get details of a quickbooks Customer
 * @param {string|number} customer_id - Id reference of Customer
 * @returns {Promise} QuickBooks Customer
 */

OAuthClient.prototype.getCustomer = function getCustomer(customer_id) {
  return this.fetchAPI(null, 'Customer', customer_id);
};

/**
 * Get details of a quickbooks Employee
 * @param {string|number} employee_id - Id reference of Employee
 * @returns {Promise} QuickBooks Employee
 */

OAuthClient.prototype.getEmployee = function getEmployee(employee_id) {
  return this.fetchAPI(null, 'Employee', employee_id);
};

/**
 * Get details of a quickbooks Estimate
 * @param {string|number} estimate_id - Id reference of Estimate
 * @returns {Promise} QuickBooks Estimate
 */

OAuthClient.prototype.getEstimate = function getEstimate(estimate_id) {
  return this.fetchAPI(null, 'Estimate', estimate_id);
};

/**
 * Get PDF of a quickbooks Estimate
 * @param {string|number} estimate_id - Id reference of EstimatePDF
 * @returns {Promise} QuickBooks EstimatePDF
 */

 OAuthClient.prototype.getEstimatePDF = function getEstimatePDF(estimate_id) {
  return this.fetchPDF('Estimate', estimate_id);
};

/**
 * Get details of a quickbooks Invoice
 * @param {string|number} invoice_id - Id reference of Invoice
 * @returns {Promise} QuickBooks Invoice
 */

OAuthClient.prototype.getInvoice = function getInvoice(invoice_id) {
  return this.fetchAPI(null, 'Invoice', invoice_id);
};

/**
 * Get PDF of a quickbooks Invoice
 * @param {string|number} invoice_id - Id reference of InvoicePDF
 * @returns {Promise} QuickBooks InvoicePDF
 */

OAuthClient.prototype.getInvoicePDF = function getInvoicePDF(invoice_id) {
  return this.fetchPDF('Invoice', invoice_id);
};

/**
 * Get details of a quickbooks Item
 * @param {string|number} item_id - Id reference of Item
 * @returns {Promise} QuickBooks Item
 */

OAuthClient.prototype.getItem = function getItem(item_id) {
  return this.fetchAPI(null, 'Item', item_id);
};

/**
 * Get details of a quickbooks Payment
 * @param {string|number} payment_id - Id reference of Payment
 * @returns {Promise} QuickBooks Payment
 */

OAuthClient.prototype.getPayment = function getPayment(payment_id) {
  return this.fetchAPI(null, 'Payment', payment_id);
};

/**
 * Get quickbooks Preferences for default company ID i.e. realmId
 * @returns {Promise} QuickBooks Preferences
 */

OAuthClient.prototype.getPreferences = function getPreferences() {
  return this.fetchAPI(null, 'Preferences');
};

/**
 * Get details of a quickbooks TaxAgency
 * @param {string|number} tax_agency_id - Id reference of TaxAgency
 * @returns {Promise} QuickBooks TaxAgency
 */

OAuthClient.prototype.getTaxAgency = function getTaxAgency(tax_agency_id) { // check
  return this.fetchAPI(null, 'TaxAgency', tax_agency_id);
};

/**
 * Get details of a quickbooks Vendor
 * @param {string|number} vendor_id - Id reference of Vendor
 * @returns {Promise} QuickBooks Vendor
 */

 OAuthClient.prototype.getVendor = function getVendor(vendor_id) {
  return this.fetchAPI(null, 'Vendor', vendor_id);
};

/* END GET ENTITIES */

module.exports = OAuthClient;
