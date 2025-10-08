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
const axios = require('axios');
const os = require('os');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const AuthResponse = require('./response/AuthResponse');
const version = require('../package.json');
const Token = require('./access-token/Token');

// Move error classes to a separate file
const OAuthError = require('./errors/OAuthError');
const ValidationError = require('./errors/ValidationError');
const TokenError = require('./errors/TokenError');

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
  this.token = new Token(config.token);
  this.logging = !!(
    Object.prototype.hasOwnProperty.call(config, 'logging') && config.logging === true
  );
  this.logger = null;
  this.state = new Csrf();

  // Configure Axios instance
  this.axiosInstance = axios.create({
    validateStatus(status) {
      return status >= 200 && status < 500;
    },
  });

  if (this.logging) {
    const dir = './logs';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp({
          format: 'YYYY-MM-DD HH:mm:ss.SSS Z',  // This will include local timezone offset
        }),
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
OAuthClient.qbo_environment = {
  sandbox: 'https://sandbox.qbo.intuit.com/app/',
  production: 'https://qbo.intuit.com/app/',
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

OAuthClient.prototype.getEnvironmentURI = function getEnvironmentURI() { 
  return (this.environment && this.environment === 'production') ? OAuthClient.environment.production : OAuthClient.environment.sandbox;
}


OAuthClient.prototype.getQBOEnvironmentURI = function getQBOEnvironmentURI() {
  return (this.environment && this.environment === 'production') ? OAuthClient.qbo_environment.production : OAuthClient.qbo_environment.sandbox;
}


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
 * Safe JSON stringify that handles circular references
 * @param {*} obj - Object to stringify
 * @returns {string} JSON string
 */
function safeStringify(obj) {
  try {
    return JSON.stringify(obj, (key, value) => {
      if (key === '_redirectable' || key === '_currentRequest' || key === 'socket') {
        return undefined;
      }
      return value;
    });
  } catch (e) {
    return String(obj);
  }
}

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
    if ('state' in params) this.getToken().state = params.state;

    const body = {};
    if (params.code) {
      body.grant_type = 'authorization_code';
      body.code = params.code;
      body.redirect_uri = params.redirectUri || this.redirectUri;
    }

    const request = {
      url: OAuthClient.tokenEndpoint,
      data: body,
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
      const authResponse = Object.prototype.hasOwnProperty.call(res, 'json') ? res : null;
      const json = (authResponse && authResponse.json) || res;
      this.token.setToken(json);
      this.log('info', 'Create Token response is : ', safeStringify(authResponse && authResponse.json));
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Create Token () threw an exception : ', safeStringify(e));
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
      data: body,
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
      const authResponse = Object.prototype.hasOwnProperty.call(res, 'json') ? res : null;
      const json = (authResponse && authResponse.json) || res;
      this.token.setToken(json);
      this.log('info', 'Refresh Token () response is : ', safeStringify(authResponse && authResponse.json));
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Refresh Token () threw an exception : ', safeStringify(e));
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
      data: body,
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
      const authResponse = Object.prototype.hasOwnProperty.call(res, 'json') ? res : null;
      const json = (authResponse && authResponse.json) || res;
      this.token.setToken(json);
      this.log(
        'info',
        'Refresh usingToken () response is : ', safeStringify(authResponse && authResponse.json),
      );
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Refresh Token () threw an exception : ', safeStringify(e));
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
      data: body,
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
    .then((res) => {
      const authResponse = Object.prototype.hasOwnProperty.call(res, 'json') ? res : null;
      this.token.clearToken();
      this.log('info', 'Revoke Token () response is : ', safeStringify(authResponse && authResponse.json));
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Revoke Token () threw an exception : ', safeStringify(e));
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
      const authResponse = Object.prototype.hasOwnProperty.call(res, 'json') ? res : null;
      this.log(
        'info',
        'The Get User Info () response is : ', safeStringify(authResponse && authResponse.json),
      );
      return authResponse;
    })
    .catch((e) => {
      this.log('error', 'Get User Info ()  threw an exception : ', safeStringify(e));
      throw e;
    });
};

/**
 * Make API call. Pass the url,method,headers using `params` object
 *
 * @param {params} params
 * @param {string} params.url
 * @param {string} params.method (optional) default is GET
 * @param {Object} params.headers (optional)
 * @param {Object} params.body (optional)
 * @param {string} params.responseType (optional) default is json - options are json, text, stream, arraybuffer
 * @returns {Promise}
 */
OAuthClient.prototype.makeApiCall = async function makeApiCall({ url, method, headers: customHeaders, body, params, timeout, responseType, maxRetries = 3 }) {
  if (!url) {
    throw new ValidationError('URL is required for API call');
  }

  // Determine the full URL - backward compatibility for relative endpoints
  let fullUrl = url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    // User provided a relative endpoint
    const baseURL = (this.environment && this.environment === 'production') 
      ? OAuthClient.environment.production 
      : OAuthClient.environment.sandbox;
    
    // Remove leading slash if present to avoid double slashes
    const endpoint = url.startsWith('/') ? url.slice(1) : url;
    fullUrl = baseURL + endpoint;
  }

  let attempt = 0;
  let lastError = null;

  while (attempt < maxRetries) {
    try {
      const requestConfig = {
        method: method || 'GET',
        headers: {
          ...this.authHeader(),
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'User-Agent': OAuthClient.user_agent,
          ...customHeaders,
        },
        timeout: timeout || 30000,
        responseType: responseType || 'json',
        data: body,
        params,
      };

      // Make the API call
      const response = await this.axiosInstance(fullUrl, requestConfig);
      
      // Log the successful response
      this.log('info', 'The makeAPICall () response is : ', JSON.stringify(response.data, null, 2));
      
      // Return in AuthResponse-compatible format for backward compatibility
      return {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        json: response.data,
        body: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
      };
    } catch (error) {
      attempt += 1;
      lastError = error;

      // Detailed error analysis and logging
      const errorAnalysis = {
        // Basic error properties
        basic: {
          name: error.name,
          message: error.message,
          stack: error.stack,
          code: error.code,
        },
        // Response analysis
        response: error.response ? {
          status: error.response.status,
          statusText: error.response.statusText,
          headers: error.response.headers,
          // Deep analysis of response data
          data: error.response.data,
          // Specific Fault object analysis
          fault: error.response.data && error.response.data.Fault ? {
            type: error.response.data.Fault.type,
            error: error.response.data.Fault.Error ? error.response.data.Fault.Error.map(err => ({
              message: err.Message,
              detail: err.Detail,
              code: err.code,
              element: err.element,
              additionalInfo: err.additionalInfo,
            })) : null,
            timestamp: error.response.data.time,
          } : null,
          // OAuth error fields
          oauth: {
            error: error.response.data && error.response.data.error,
            error_description: error.response.data && error.response.data.error_description,
          },
        } : null,
        // Request analysis
        request: error.request ? {
          method: error.request.method,
          path: error.request.path,
          headers: error.request.headers,
        } : null,
        // Context
        context: {
          attempt,
          url: fullUrl,
          timestamp: new Date().toISOString(),
        },
      };

      // Log the detailed error analysis
      this.log('error', 'Exception Analysis:', {
        hasFaultObject: !!(error.response && error.response.data && error.response.data.Fault),
        faultType: error.response && error.response.data && error.response.data.Fault && error.response.data.Fault.type,
        faultErrors: error.response && error.response.data && error.response.data.Fault && error.response.data.Fault.Error,
        fullAnalysis: errorAnalysis,
      });

      // Log the error for debugging
      this.log('error', 'API call failed:', {
        error: (error.response && error.response.data) || error.message,
        status: error.response && error.response.status,
        attempt,
        url: fullUrl,
      });

      // Handle Axios errors
      if (error.response) {
        const { status, data, headers: responseHeaders } = error.response;
        const intuitTid = responseHeaders && responseHeaders.intuit_tid;

        // Handle 400 errors with Fault object
        if (status === 400) {
          if (data && data.Fault) {
            const fault = data.Fault;
            const faultError = fault.Error && fault.Error[0];
            
            // Extract detailed error information from Fault object
            const errorMessage = (faultError && faultError.Message) || 'Bad Request';
            const errorCode = (faultError && faultError.code) || '400';
            const errorDetail = (faultError && faultError.Detail) || 'Request validation failed';
            const faultType = (fault && fault.type) || 'ValidationFault';
            
            // Create a more descriptive error message
            const detailedMessage = `${errorMessage}`;
            
            throw new OAuthError(
              detailedMessage,
              errorCode,
              errorDetail,
              intuitTid,
              {
                faultType,
                fault: {
                  type: faultType,
                  errors: fault.Error ? fault.Error.map(err => ({
                    message: err.Message,
                    detail: err.Detail,
                    code: err.code,
                  })) : [],
                  time: data.time,
                },
                timestamp: data.time,
              },
            );
          }
          
          // Handle other 400 errors
          throw new OAuthError(
            (data && data.error) || 'Bad Request',
            '400',
            (data && data.error_description) || 'Request validation failed',
            intuitTid,
          );
        }

        // Handle rate limit errors
        if (status === 429) {
          throw new OAuthError(
            'Rate limit exceeded',
            'RATE_LIMIT_EXCEEDED',
            'Too many requests, please try again later',
            intuitTid,
          );
        }

        // Handle other HTTP errors
        throw new OAuthError(
          (data && data.error) || error.message || 'Unknown error',
          status === 500 ? 'INTERNAL_SERVER_ERROR' : status.toString(),
          (data && data.error_description) || 'An error occurred during the API call',
          intuitTid,
        );
      }

      // Handle network errors
      if (error.code === 'ECONNABORTED') {
        throw new OAuthError(
          `Request timeout of ${timeout || 30000}ms exceeded`,
          'TIMEOUT_ERROR',
          'The request took too long to complete',
        );
      }

      // Handle other errors (no response received)
      if (error.request) {
        throw new OAuthError(
          'Connection reset by peer',
          'NETWORK_ERROR',
          'A network error occurred while making the request',
        );
      }

      // Handle any other errors
      throw new OAuthError(
        error.message || 'Unknown error',
        'OAUTH_ERROR',
        'An unexpected error occurred',
      );
    }

    // Add delay between retries
    if (attempt < maxRetries) {
      const delay = 2 ** attempt * 1000;
      // eslint-disable-next-line no-await-in-loop
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  // If we've exhausted all retries, throw the last error
  if (lastError) {
    if (lastError instanceof OAuthError) {
      throw lastError;
    }
    throw new OAuthError(
      lastError.message || 'Maximum retry attempts reached',
      'MAX_RETRIES_EXCEEDED',
      'The request failed after multiple retry attempts',
    );
  }

  // This should never be reached, but TypeScript needs it
  throw new OAuthError(
    'Unexpected error in makeApiCall',
    'UNKNOWN_ERROR',
    'An unexpected error occurred in the API call',
  );
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
      this.log('info', 'The validateIdToken () response is :', safeStringify(res));
      if (res) return true;
      return false;
    })
    .catch((e) => {
      this.log('error', 'The validateIdToken () threw an exception : ', safeStringify(e));
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
      const key = response.data.keys.find((el) => el.kid === kid);
      const cert = this.getPublicKey(key.n, key.e);

      return jwt.verify(id_token, cert);
    })
    .catch((e) => {
      e = this.createError(e);
      this.log(
        'error',
        'The getKeyFromJWKsURI () threw an exception : ',
        safeStringify(e),
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
      this.validateResponse(response);
      authResponse.processResponse(response);

      if (!authResponse.valid()) {
        throw new OAuthError(
          'Response has an Error',
          response.status.toString(),
          response.statusText,
          response.headers && response.headers.intuit_tid,
        );
      }

      return authResponse;
    })
    .catch((e) => {
      if (!e.authResponse) {
        e = this.createError(e, authResponse);
      }
      throw e;
    });
};

/**
 * Validate Token { validates if token object has refresh token }
 * *
 * @returns {boolean}
 */
OAuthClient.prototype.validateToken = function validateToken() {
  if (!this.token.refreshToken()) {
    throw new Error('The Refresh token is missing');
  }

  if (!this.token.isRefreshTokenValid()) {
    throw new Error('The Refresh token is invalid, please Authorize again.');
  }

  return true;
};

// Add retry configuration
OAuthClient.retryConfig = {
  maxRetries: 3,
  retryDelay: 1000, // 1 second
  retryableStatusCodes: [408, 429, 500, 502, 503, 504],
  retryableErrors: ['ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED'],
};

OAuthClient.prototype.shouldRetry = function shouldRetry(error, attempt) {
  if (attempt >= OAuthClient.retryConfig.maxRetries) {
    return false;
  }

  // Check if it's a retryable status code
  if (error.response && OAuthClient.retryConfig.retryableStatusCodes.includes(error.response.status)) {
    return true;
  }

  // Check if it's a retryable network error
  if (error.code && OAuthClient.retryConfig.retryableErrors.includes(error.code)) {
    return true;
  }

  return false;
};

/**
 * Make HTTP Request using Axios Client
 * @param request
 * @returns response
 */
OAuthClient.prototype.loadResponse = function loadResponse(request) {
  this.currentRequest = request;
  let attempt = 0;

  const executeRequest = () => axios(request)
      .then((response) => {
        this.currentRequest = null;
        return response;
      })
      .catch((error) => {
        this.currentRequest = null;
        
        if (this.shouldRetry(error, attempt)) {
          attempt += 1;
          const delay = OAuthClient.retryConfig.retryDelay * (2 ** (attempt - 1));
          
          this.log('warn', `Retrying request (attempt ${attempt}/${OAuthClient.retryConfig.maxRetries})`, {
            error: error.message,
            delay,
            url: request.url,
          });

          return new Promise((resolve) => {
            setTimeout(() => {
              resolve(executeRequest());
            }, delay);
          });
        }

        throw error;
      });

  return executeRequest();
};

/**
 * Load response from JWK URI
 * @param request
 * @returns response
 */
OAuthClient.prototype.loadResponseFromJWKsURI = function loadResponseFromJWKsURI(request) {
  return axios.get(request).then((response) => response);
};

/**
 * Create Error Wrapper
 * @param {Error|string} error - Error object or error message
 * @param {AuthResponse} authResponse - AuthResponse object
 * @returns {Error} error
 */
OAuthClient.prototype.createError = function createError(error, authResponse) {
  if (!error) {
    return new Error('');
  }

  const wrappedError = new Error();
  wrappedError.error = '';
  wrappedError.authResponse = authResponse || '';
  wrappedError.intuit_tid = (authResponse && authResponse.getIntuitTid()) || '';
  wrappedError.originalMessage = error.message || '';
  wrappedError.error_description = '';

  if (authResponse) {
    if (authResponse.body) {
      try {
        const body = typeof authResponse.body === 'string' ? JSON.parse(authResponse.body) : authResponse.body;
        if (body.error) {
          wrappedError.error = body.error;
          wrappedError.error_description = body.error_description || '';
          wrappedError.message = body.error;
          return wrappedError;
        }
      } catch (e) {
        // If parsing fails, use the original body
        wrappedError.error = authResponse.body;
        wrappedError.error_description = authResponse.body;
        wrappedError.message = authResponse.body;
        return wrappedError;
      }
    }
    
    if (authResponse.response && authResponse.response.statusText) {
      wrappedError.error = authResponse.response.statusText;
      wrappedError.error_description = authResponse.response.statusText;
      wrappedError.message = authResponse.response.statusText;
      return wrappedError;
    }
  }

  if (error instanceof Error) {
    wrappedError.error = error.message;
    wrappedError.message = error.message;
  } else if (typeof error === 'string') {
    wrappedError.error = error;
    wrappedError.message = error;
  } else {
    wrappedError.error = error.toString();
    wrappedError.message = error.toString();
  }

  return wrappedError;
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

/**
 * Log the message
 * @param {string} level - Log level
 * @param {string} message - Log message
 * @param {*} data - Log data
 */
OAuthClient.prototype.log = function log(level, message, data) {
  if (!this.logger) {
    return;
  }

  if (typeof data === 'string') {
    this.logger.log(level, message + data);
    return;
  }

  const logData = {
    timestamp: new Date().toISOString(),
    level,
    message,
    environment: this.environment,
    clientId: this.clientId,
  };

  // Add safe request context if available
  if (this.currentRequest) {
    logData.request = {
      url: this.currentRequest.url,
      method: this.currentRequest.method,
      headers: { ...this.currentRequest.headers },
    };
  }

  // Add safe data context
  if (data) {
    try {
      logData.data = JSON.parse(safeStringify(data));
    } catch (e) {
      logData.data = String(data);
    }
  }

  this.logger.log(level, safeStringify(logData));
};

OAuthClient.prototype.validateResponse = function validateResponse(response) {
  if (!response) {
    throw new ValidationError('Empty response received');
  }

  if (!response.status) {
    throw new ValidationError('Response missing status code');
  }

  const intuitTid = response.headers && response.headers.intuit_tid;

  if (response.status === 429) {
    throw new OAuthError(
      'Rate limit exceeded',
      'RATE_LIMIT_EXCEEDED',
      'Too many requests, please try again later',
      intuitTid,
    );
  }

  if (response.status === 401) {
    throw new TokenError(
      'Unauthorized',
      'UNAUTHORIZED',
      'Invalid or expired access token',
      intuitTid,
    );
  }

  if (response.status === 403) {
    throw new OAuthError(
      'Forbidden',
      'FORBIDDEN',
      'Insufficient permissions',
      intuitTid,
    );
  }

  return true;
};

module.exports = OAuthClient;
