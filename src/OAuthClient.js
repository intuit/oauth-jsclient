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
const AuthResponse = require('./response/AuthResponse');
const version = require('../package.json');
const Token = require('./access-token/Token');
const https = require('https');

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
 * Get details of a quickbooks Account
 * @param {string|number} acc_id - Id reference of Account
 * @returns {Promise} QuickBooks Account
 */

OAuthClient.prototype.getAccount = function getAccount(acc_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const acc = parseInt(acc_id, 10);
    if (Number.isNaN(acc)) throw new Error('Invalid Account Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/account/${acc}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getAccount () response is : ', JSON.stringify(authResponse, null, 2));
    const myAccount = JSON.parse(authResponse.text());
    return myAccount.Account;
  })
  .catch((e) => {
    this.log('error', 'Get getAccount ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks Bill
 * @param {string|number} bill_id - Id reference of Bill
 * @returns {Promise} QuickBooks Bill
 */

OAuthClient.prototype.getBill = function getBill(bill_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const bill0 = parseInt(bill_id, 10);
    if (Number.isNaN(bill0)) throw new Error('Invalid Bill Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/bill/${bill0}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getBill () response is : ', JSON.stringify(authResponse, null, 2));
    const myBill = JSON.parse(authResponse.text());
    return myBill.Bill;
  })
  .catch((e) => {
    this.log('error', 'Get getBill ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks companyInfo based on realmId
 * @returns {Promise} QuickBooks CompanyInfo
 */

OAuthClient.prototype.getCompanyInfo = function getCompanyInfo() {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const companyID = this.getToken().realmId;
    if (!companyID) throw new Error('Realm Id / CompanyInfo Id missing! Please create a new token using OAuth and try again.');
    const url0 = this.environment === 'sandbox'
      ? OAuthClient.environment.sandbox
      : OAuthClient.environment.production;
    const headers0 = {
      Authorization: `Bearer ${this.getToken().access_token}`,
      Accept: AuthResponse._jsonContentType,
      'User-Agent': OAuthClient.user_agent,
    };
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/companyinfo/${companyID}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getCompanyInfo () response is : ', JSON.stringify(authResponse, null, 2));
    const myCompanyInfo = JSON.parse(authResponse.text());
    return myCompanyInfo.CompanyInfo;
  })
  .catch((e) => {
    this.log('error', 'Get getCompanyInfo ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks Customer
 * @param {string|number} customer_id - Id reference of Customer
 * @returns {Promise} QuickBooks Customer
 */

OAuthClient.prototype.getCustomer = function getCustomer(customer_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const cus = parseInt(customer_id, 10);
    if (Number.isNaN(cus)) throw new Error('Invalid Customer Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/customer/${cus}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getCustomer () response is : ', JSON.stringify(authResponse, null, 2));
    const myCustomer = JSON.parse(authResponse.text());
    return myCustomer.Customer;
  })
  .catch((e) => {
    this.log('error', 'Get getCustomer ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks Employee
 * @param {string|number} employee_id - Id reference of Employee
 * @returns {Promise} QuickBooks Employee
 */

OAuthClient.prototype.getEmployee = function getEmployee(employee_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const employee0 = parseInt(employee_id, 10);
    if (Number.isNaN(employee0)) throw new Error('Invalid Employee Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/employee/${employee0}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getEmployee () response is : ', JSON.stringify(authResponse, null, 2));
    const myEmployee = JSON.parse(authResponse.text());
    return myEmployee.Employee;
  })
  .catch((e) => {
    this.log('error', 'Get getEmployee ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks Estimate
 * @param {string|number} estimate_id - Id reference of Estimate
 * @returns {Promise} QuickBooks Estimate
 */

OAuthClient.prototype.getEstimate = function getEstimate(estimate_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const estimate0 = parseInt(estimate_id, 10);
    if (Number.isNaN(estimate0)) throw new Error('Invalid Estimate Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/estimate/${estimate0}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getEstimate () response is : ', JSON.stringify(authResponse, null, 2));
    const myEstimate = JSON.parse(authResponse.text());
    return myEstimate.Estimate;
  })
  .catch((e) => {
    this.log('error', 'Get getEstimate ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get PDF of a quickbooks Estimate
 * @param {string|number} estimate_id - Id reference of EstimatePDF
 * @returns {Promise} QuickBooks EstimatePDF
 */

 OAuthClient.prototype.getEstimatePDF = function getEstimatePDF(estimate_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const estimate0 = parseInt(estimate_id, 10);
    if (Number.isNaN(estimate0)) throw new Error('Invalid Estimate Id! Must be a number or number as a string!');
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
    const req_options = {
      method: 'GET',
      headers: headers0,
    };
    const get_url = `${url0}v3/company/${companyID}/estimate/${estimate0}/pdf`;
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
    this.log('info', 'The getEstimatePDF () response is : ', authResponse ? authResponse.toString() : "EMPTY");
    return authResponse;
  })
  .catch((e) => {
    this.log('error', 'Get getEstimatePDF ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks Invoice
 * @param {string|number} invoice_id - Id reference of Invoice
 * @returns {Promise} QuickBooks Invoice
 */

OAuthClient.prototype.getInvoice = function getInvoice(invoice_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const invoice0 = parseInt(invoice_id, 10);
    if (Number.isNaN(invoice0)) throw new Error('Invalid Invoice Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/invoice/${invoice0}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getInvoice () response is : ', JSON.stringify(authResponse, null, 2));
    const myInvoice = JSON.parse(authResponse.text());
    return myInvoice.Invoice;
  })
  .catch((e) => {
    this.log('error', 'Get getInvoice ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get PDF of a quickbooks Invoice
 * @param {string|number} invoice_id - Id reference of InvoicePDF
 * @returns {Promise} QuickBooks InvoicePDF
 */

OAuthClient.prototype.getInvoicePDF = function getInvoicePDF(invoice_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const invoice0 = parseInt(invoice_id, 10);
    if (Number.isNaN(invoice0)) throw new Error('Invalid Invoice Id! Must be a number or number as a string!');
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
    const req_options = {
      method: 'GET',
      headers: headers0,
    };
    const get_url = `${url0}v3/company/${companyID}/invoice/${invoice0}/pdf`;
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
    this.log('info', 'The getInvoicePDF () response is : ', authResponse ? authResponse.toString() : "EMPTY");
    return authResponse;
  })
  .catch((e) => {
    this.log('error', 'Get getInvoicePDF ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks Item
 * @param {string|number} item_id - Id reference of Item
 * @returns {Promise} QuickBooks Item
 */

OAuthClient.prototype.getItem = function getItem(item_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const item0 = parseInt(item_id, 10);
    if (Number.isNaN(item0)) throw new Error('Invalid Item Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/item/${item0}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getItem () response is : ', JSON.stringify(authResponse, null, 2));
    const myItem = JSON.parse(authResponse.text());
    return myItem.Item;
  })
  .catch((e) => {
    this.log('error', 'Get getItem ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks Payment
 * @param {string|number} payment_id - Id reference of Payment
 * @returns {Promise} QuickBooks Payment
 */

OAuthClient.prototype.getPayment = function getPayment(payment_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const payment0 = parseInt(payment_id, 10);
    if (Number.isNaN(payment0)) throw new Error('Invalid Payment Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/payment/${payment0}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getPayment () response is : ', JSON.stringify(authResponse, null, 2));
    const myPayment = JSON.parse(authResponse.text());
    return myPayment.Payment;
  })
  .catch((e) => {
    this.log('error', 'Get getPayment ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get quickbooks Preferences for default company ID i.e. realmId
 * @returns {Promise} QuickBooks Preferences
 */

OAuthClient.prototype.getPreferences = function getPreferences() {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/preferences`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getPreferences () response is : ', JSON.stringify(authResponse, null, 2));
    const myPreferences = JSON.parse(authResponse.text());
    return myPreferences.Preferences;
  })
  .catch((e) => {
    this.log('error', 'Get getPreferences ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks TaxAgency
 * @param {string|number} tax_agency_id - Id reference of TaxAgency
 * @returns {Promise} QuickBooks TaxAgency
 */

OAuthClient.prototype.getTaxAgency = function getTaxAgency(tax_agency_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const taxagency0 = parseInt(tax_agency_id, 10);
    if (Number.isNaN(taxagency0)) throw new Error('Invalid TaxAgency Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/taxagency/${taxagency0}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getTaxAgency () response is : ', JSON.stringify(authResponse, null, 2));
    const myTaxAgency = JSON.parse(authResponse.text());
    return myTaxAgency.TaxAgency;
  })
  .catch((e) => {
    this.log('error', 'Get getTaxAgency ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

/**
 * Get details of a quickbooks Vendor
 * @param {string|number} vendor_id - Id reference of Vendor
 * @returns {Promise} QuickBooks Vendor
 */

 OAuthClient.prototype.getVendor = function getVendor(vendor_id) {
  return new Promise((resolve) => {
    if (!this.isAccessTokenValid()) throw new Error('OAuth authentication failed! Invalid Token!');
    const vendor0 = parseInt(vendor_id, 10);
    if (Number.isNaN(vendor0)) throw new Error('Invalid Vendor Id! Must be a number or number as a string!');
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
    const request = {
      method: 'GET',
      url: `${url0}v3/company/${companyID}/vendor/${vendor0}`,
      headers: headers0,
    };
    resolve(this.getTokenRequest(request));
  })
  .then((authResponse) => {
    this.log('info', 'The getVendor () response is : ', JSON.stringify(authResponse, null, 2));
    const myVendor = JSON.parse(authResponse.text());
    return myVendor.Vendor;
  })
  .catch((e) => {
    this.log('error', 'Get getVendor ()  threw an exception : ', JSON.stringify(e, null, 2));
    throw e;
  });
};

//  OAuthClient.prototype.getCompanyInfo = function getCompanyInfo() {
//   return new Promise((resolve) => {
//     const request = {
//       url:
//         this.environment === 'sandbox'
//           ? OAuthClient.userinfo_endpoint_sandbox
//           : OAuthClient.userinfo_endpoint_production,
//       method: 'GET',
//       headers: {
//         Authorization: `Bearer ${this.token.access_token}`,
//         Accept: AuthResponse._jsonContentType,
//         'User-Agent': OAuthClient.user_agent,
//       },
//     };

//     resolve(this.getTokenRequest(request));
//   })
//     .then((res) => {
//       const authResponse = res.json ? res : null;
//       this.log(
//         'info',
//         'The Get User Info () response is : ',
//         JSON.stringify(authResponse, null, 2),
//       );
//       return authResponse;
//     })
//     .catch((e) => {
//       this.log('error', 'Get User Info ()  threw an exception : ', JSON.stringify(e, null, 2));
//       throw e;
//     });
// };


module.exports = OAuthClient;
