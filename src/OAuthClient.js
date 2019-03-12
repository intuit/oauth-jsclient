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

var atob = require('atob');
var Tokens = require('csrf');
var csrf = new Tokens()
var AuthResponse = require("./response/AuthResponse");
var oauthSignature = require('oauth-signature');
var objectAssign = require('object-assign');
var queryString = require('query-string');
var popsicle = require('popsicle');
var Token = require("./access-token/Token");
var package = require('../package.json');
var os = require('os');
var winston = require('winston');
var path = require('path');
var fs = require('fs');
var jwt = require('jsonwebtoken')

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
    this.logging =  config.hasOwnProperty('logging') && config.logging == true ? true : false;
    this.logger = null;

    if(this.logging) {

        var dir = './logs';
        if (!fs.existsSync(dir)){
            fs.mkdirSync(dir);
        }
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.printf(info => {
                    return `${info.timestamp} ${info.level}: ${info.message}`;
                })
            ),
            transports: [new winston.transports.File({filename: path.join(dir , 'oAuthClient-log.log')})]
        });
    }
}


OAuthClient.cacheId = 'cacheID';
OAuthClient.authorizeEndpoint = 'https://appcenter.intuit.com/connect/oauth2';
OAuthClient.tokenEndpoint = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
OAuthClient.revokeEndpoint = 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke';
OAuthClient.userinfo_endpoint_production = 'https://accounts.platform.intuit.com/v1/openid_connect/userinfo'
OAuthClient.userinfo_endpoint_sandbox = 'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo';
OAuthClient.migrate_sandbox = 'https://developer-sandbox.api.intuit.com/v2/oauth2/tokens/migrate';
OAuthClient.migrate_production = 'https://developer.api.intuit.com/v2/oauth2/tokens/migrate';
OAuthClient.environment = {sandbox:'https://sandbox-quickbooks.api.intuit.com/', production:'https://quickbooks.api.intuit.com/'};
OAuthClient.jwks_uri = 'https://oauth.platform.intuit.com/op/v1/jwks';
OAuthClient.scopes = {
  Accounting: 'com.intuit.quickbooks.accounting',
  Payment: 'com.intuit.quickbooks.payment',
  Payroll: 'com.intuit.quickbooks.payroll',
  TimeTracking: 'com.intuit.quickbooks.payroll.timetracking',
  Benefits: 'com.intuit.quickbooks.payroll.benefits',
  Profile: 'profile',
  Email:  'email',
  Phone: 'phone',
  Address: 'address',
  OpenId: 'openid',
  Intuit_name: 'intuit_name'
}
OAuthClient.user_agent = 'Intuit-OAuthClient-JS'+ '_' + package.version + '_' + os.type() + '_' + os.release() + '_' + os.platform();


/**
 * Redirect  User to Authorization Page
 * @param params
 * @returns {string} authorize Uri
 */
OAuthClient.prototype.authorizeUri = function(params) {

    params = params || {};

    // check if the scopes is provided
    if(!params.scope) throw new Error('Provide the scopes');

    var authorizeUri = OAuthClient.authorizeEndpoint + '?' + queryString.stringify({
        'response_type': 'code',
        'redirect_uri': this.redirectUri ,
        'client_id': this.clientId,
        'scope': (Array.isArray(params.scope)) ? params.scope.join(' ') : params.scope,
        'state': params.state || csrf.create(csrf.secretSync())
    });

    this.log('info','The Authorize Uri is :',authorizeUri);
    return authorizeUri;

};


/**
 * Create Token { exchange code for bearer_token }
 * @param options
 * @returns {Promise<any>}
 */
OAuthClient.prototype.createToken = function(uri) {

    return (new Promise(function(resolve) {

        if(!uri) throw new Error('Provide the Uri');
        var params = queryString.parse(uri.split('?').reverse()[0]);
        this.getToken().realmId = (params['realmId'] ? params['realmId'] : '');

        var body = {};
        if (params.code) {

            body.grant_type = 'authorization_code';
            body.code = params.code;
            body.redirect_uri = params.redirectUri || this.redirectUri;
        }

        var request = {
            url: OAuthClient.tokenEndpoint,
            body: body,
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + this.authHeader(),
                'Content-Type': AuthResponse._urlencodedContentType,
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuthClient.user_agent
            }
        };

        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(res) {

        var authResponse = res.json ? res : null;
        var json = authResponse && authResponse.getJson() || res;
        this.token.setToken(json);
        this.log('info','Create Token response is : ',JSON.stringify(authResponse, null, 2));
        return authResponse;

    }.bind(this)).catch(function(e) {

        this.log('error','Create Token () threw an exception : ',JSON.stringify(e, null, 2));
        throw e;

    }.bind(this));

};


/**
 * Refresh Token { Refresh access_token }
 * @param {Object} params.refresh_token (optional)
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.refresh = function() {

    return (new Promise(function(resolve) {

      /**
         * Check if the tokens exist and are valid
         */
        this.validateToken();

        var body = {};

        body.grant_type = 'refresh_token';
        body.refresh_token = this.getToken().refresh_token;

        var request = {
            url: OAuthClient.tokenEndpoint,
            body: body,
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + this.authHeader(),
                'Content-Type': AuthResponse._urlencodedContentType,
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuthClient.user_agent
            }
        };

        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(res) {

        var authResponse = res.json ? res : null;
        var json = authResponse && authResponse.getJson() || res;
        this.token.setToken(json);
        this.log('info','Refresh Token () response is : ',JSON.stringify(authResponse, null, 2));
        return authResponse;

    }.bind(this)).catch(function(e) {

        this.log('error','Refresh Token () threw an exception : ',JSON.stringify(e, null, 2));
        throw e;

    }.bind(this));

};


/**
 * Refresh Tokens by passing refresh_token parameter explicitly { Refresh access_token by passing refresh_token }
 * @param {Object} params.refresh_token (optional)
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.refreshUsingToken = function(refresh_token) {

  return (new Promise(function(resolve) {

    /**
     * Check if the tokens exist
     */

    if(!refresh_token) throw new Error('The Refresh token is missing');

    var body = {};

    body.grant_type = 'refresh_token';
    body.refresh_token = refresh_token;

    var request = {
      url: OAuthClient.tokenEndpoint,
      body: body,
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + this.authHeader(),
        'Content-Type': AuthResponse._urlencodedContentType,
        'Accept': AuthResponse._jsonContentType,
        'User-Agent': OAuthClient.user_agent
      }
    };

    resolve(this.getTokenRequest(request));

  }.bind(this))).then(function(res) {

    var authResponse = res.json ? res : null;
    this.log('info','Refresh Token () response is : ',JSON.stringify(authResponse, null, 2));
    return authResponse;

  }.bind(this)).catch(function(e) {

    this.log('error','Refresh Token () threw an exception : ',JSON.stringify(e, null, 2));
    throw e;

  }.bind(this));

};

/**
 * Revoke Token { revoke access/refresh_token }
 * @param {Object} params.access_token (optional)
 * @param {Object} params.refresh_token (optional)
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.revoke = function(params) {

    return (new Promise(function(resolve) {

        params = params || {};

        /**
         * Check if the tokens exist and are valid
         */
        this.validateToken();

        var body = {};

        body.token = params.access_token || params.refresh_token || (this.getToken().isAccessTokenValid() ? this.getToken().access_token : this.getToken().refresh_token);

        var request = {
            url: OAuthClient.revokeEndpoint,
            body: body,
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + this.authHeader(),
                'Accept': AuthResponse._jsonContentType,
                'Content-Type': AuthResponse._jsonContentType,
                'User-Agent': OAuthClient.user_agent
            }
        };

        resolve(this.getTokenRequest(request));


    }.bind(this))).then(function(authResponse) {

        this.log('info','Revoke Token () response is : ',JSON.stringify(authResponse, null, 2));
        return authResponse;

    }.bind(this)).catch(function(e) {

        this.log('error','Revoke Token () threw an exception : ',JSON.stringify(e, null, 2));
        throw e;

    }.bind(this));

};

/**
 * Get User Info  { Get User Info }
 * @param {Object} params
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.getUserInfo = function(params) {

    return (new Promise(function(resolve) {

        params = params || {};

        var request = {
            url: this.environment == 'sandbox' ? OAuthClient.userinfo_endpoint_sandbox : OAuthClient.userinfo_endpoint_production,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + this.token.access_token,
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuthClient.user_agent
            }
        };

        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(res) {

        var authResponse = res.json ? res : null;
        this.log('info','The Get User Info () response is : ',JSON.stringify(authResponse, null, 2));
        return authResponse;

    }.bind(this)).catch(function(e) {

        this.log('error','Get User Info ()  threw an exception : ',JSON.stringify(e, null, 2));
        throw e;

    }.bind(this));

};

/**
 * Make API call : Make API Call
 * @param params
 * @returns {Promise<any>}
 */
OAuthClient.prototype.makeApiCall = function(params)  {

    return (new Promise(function(resolve) {

        params = params || {};

        var request = {
            url: params.url,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + this.getToken().access_token,
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuthClient.user_agent
            }
        };

        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(authResponse) {

        this.log('info','The makeAPICall () response is : ',JSON.stringify(authResponse, null, 2));
        return authResponse;

    }.bind(this)).catch(function(e) {

        this.log('error','Get makeAPICall ()  threw an exception : ',JSON.stringify(e, null, 2));
        throw e;

    }.bind(this));

};

/**
 * Migrate OAuth1.0 apps to support OAuth2.0
 * @param params
 * @returns {Promise<any>}
 */
OAuthClient.prototype.migrate = function(params) {

    return (new Promise(function(resolve) {

        params = params || {};

        var uri = this.environment.toLowerCase() == 'sandbox' ? OAuthClient.migrate_sandbox : OAuthClient.migrate_production;

        var authHeader = this.generateOauth1Sign(objectAssign({}, {method: 'POST', uri: uri}, params));

        var body = {
            'scope':(Array.isArray(params.scope)) ? params.scope.join(' ') : params.scope,
            'redirect_uri':this.redirectUri,
            'client_id': this.clientId,
            'client_secret': this.clientSecret
        };

        var request = {
            url: uri,
            method: 'POST',
            body: body,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'OAuth ' + authHeader,
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuthClient.user_agent
            }
        };

        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(res) {

        var authResponse = res.json ? res : null;
        var json = authResponse && authResponse.getJson() || res;
        this.token.setToken(json);
        this.log('info','The migrate () response is : ',JSON.stringify(authResponse, null, 2));
        return authResponse;
    }.bind(this)).catch(function(e) {

        this.log('error','The migrate () threw an exception : ',JSON.stringify(e, null, 2));
        throw e;

    }.bind(this));


};

/**
 * Generate oAuth1 Sign : Helper Method to Migrate OAuth1.0 apps to OAuth2.0
 * @param params
 * @returns {string}
 */
OAuthClient.prototype.generateOauth1Sign = function(params) {


    var timestamp = Math.round(new Date().getTime()/1000);

    var parameters = {
        oauth_consumer_key : params.oauth_consumer_key,
        oauth_token : params.access_token,
        oauth_signature_method : 'HMAC-SHA1',
        oauth_timestamp : timestamp,
        oauth_nonce : 'nonce',
        oauth_version : '1.0'
    };

    var encodedSignature = oauthSignature.generate (params.method, params.uri, parameters, params.oauth_consumer_secret, params.access_secret);

    parameters ['oauth_signature'] = encodedSignature;
    var keys = Object.keys(parameters);
    var authHeader = '';

    for (key in parameters) {

        // Add this for Accounting API minorversion url query parameter
        if (key === 'minorversion') {
            continue;
        }
        if (key === keys[keys.length-1]) {
            authHeader += key + '=' + '"'+parameters[key]+'"';
        }
        else {
            authHeader += key + '=' + '"'+parameters[key]+'",';
        }
    }

    return authHeader;

};

/**
 * Validate id_token
 * @param params
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.validateIdToken = function(params) {

    return (new Promise(function(resolve) {

        if(!this.getToken().id_token) throw new Error('The bearer token does not have id_token');

        var id_token = this.getToken().id_token || params.id_token;

        params = params || {};

        // Decode ID Token
        var token_parts = id_token.split('.')
        var id_token_header = JSON.parse(atob(token_parts[0]));
        var id_token_payload = JSON.parse(atob(token_parts[1]));

        var id_token_signature = atob(token_parts[2]);
        //
        // Step 1 : First check if the issuer is as mentioned in "issuer"
        if(id_token_payload.iss != 'https://oauth.platform.intuit.com/op/v1') return false;

        // Step 2 : check if the aud field in idToken is same as application's clientId
        if(id_token_payload.aud != this.clientId) return false;


        // Step 3 : ensure the timestamp has not elapsed
        if(id_token_payload.exp < Date.now() / 1000) return false;

        var request = {
            url: OAuthClient.jwks_uri,
            method: 'GET',
            headers: {
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuthClient.user_agent
            }
        };

        resolve(this.getKeyFromJWKsURI(id_token, id_token_header.kid, request));

    }.bind(this))).then(function(res) {

        this.log('info','The validateIdToken () response is : ',JSON.stringify(res, null, 2));
        if(res) return  true;

    }.bind(this)).catch(function(e) {

        this.log('error','The validateIdToken () threw an exception : ',JSON.stringify(e, null, 2));
        throw e;

    }.bind(this));
}

/**
 *
 * @param id_token
 * @param kid
 * @param request
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.getKeyFromJWKsURI = function(id_token, kid, request) {

    return (new Promise(function(resolve) {

        resolve(this.loadResponse(request));

    }.bind(this))).then(function(response) {

        if(response.status != "200") throw new Error('Could not reach JWK endpoint');

        // Find the key by KID
        var responseBody = JSON.parse(response.body);
        var key = responseBody.keys.find(el => (el.kid == kid))
        var cert = this.getPublicKey(key.n, key.e)

        return jwt.verify(id_token, cert);

    }.bind(this)).catch(function(e) {

        e = this.createError(e);
        this.log('error','The getKeyFromJWKsURI () threw an exception : ',JSON.stringify(e, null, 2));
        throw e;

    }.bind(this));

}

/**
 * get Public Key
 * @param modulus
 * @param exponent
 */
OAuthClient.prototype.getPublicKey = function(modulus, exponent) {
    var getPem = require('rsa-pem-from-mod-exp');
    var pem = getPem(modulus, exponent);
    return pem
};

/**
 * Get Token Request
 * @param {Object} request
 * @returns {Promise<AuthResponse>}
 */
OAuthClient.prototype.getTokenRequest = function(request) {

    var authResponse = new AuthResponse({token:this.token});

    return (new Promise(function(resolve) {

        resolve(this.loadResponse(request));

    }.bind(this))).then(function(response) {

        authResponse.processResponse(response);

        if (!authResponse.valid()) throw new Error('Response has an Error');

        return authResponse;

    }.bind(this)).catch(function(e) {

        if (!e.authResponse) e = this.createError(e, authResponse);
        throw e;

    }.bind(this));

};

/**
 * Token Validation
 */
OAuthClient.prototype.validateToken = function() {

    if(!this.token.refreshToken()) throw new Error('The Refresh token is missing');
    if(!this.token.isRefreshTokenValid()) throw new Error('The Refresh token is invalid, please Authorize again.');
};


/**
 * Make HTTP Request using Popsicle Client
 * @param request
 * @returns response
 */
OAuthClient.prototype.loadResponse = function (request) {

    return popsicle.get(request).then(function (response) {
        return response;
    });
};

/**
 * Load response from JWK URI
 * @param request
 * @returns response
 */
OAuthClient.prototype.loadResponseFromJWKsURI = function (request) {

    return popsicle.get(request).then(function (response) {
        return response;
    });
};

/**
 * Wrap the exception with more information
 * @param {Error|IApiError} e
 * @param {AuthResponse} authResponse
 * @return {Error|IApiError}
 */
OAuthClient.prototype.createError = function(e, authResponse) {

    if(!authResponse || authResponse.body == ""){

        e.error = e.originalMessage;
        return e;
    }

    e.authResponse = authResponse ? authResponse : null;
    e.originalMessage = e.message;
    e.error =  ('error' in authResponse.getJson() ? authResponse.getJson().error : '');
    e.error_description = ('error_description' in authResponse.getJson() ? authResponse.getJson().error_description : '');
    e.intuit_tid = authResponse.headers()['intuit_tid'];

    return e;

};

/**
 * isAccessToken Valid () { TTL of access_token }
 * @returns {boolean}
 * @private
 */
OAuthClient.prototype.isAccessTokenValid = function() {
    return (this.token.expires_in > Date.now());
};

/**
 * GetToken
 * @returns {Token}
 */
OAuthClient.prototype.getToken = function() {
    return this.token;
};


/**
 * Set Token
 * @param {Object}
 * @returns {Token}
 */
OAuthClient.prototype.setToken = function(params) {

  this.token = new Token(params);
  return this.token;
};


/**
 * Get AuthHeader
 * @returns {string} authHeader
 */
OAuthClient.prototype.authHeader = function() {
    var apiKey = this.clientId + ':' + this.clientSecret;
    return (typeof btoa == 'function') ? btoa(apiKey) : new Buffer(apiKey).toString('base64');
};

OAuthClient.prototype.log = function(level,message,messageData) {
    if (this.logging) {
        this.logger.log(level,message + messageData);
    }
};

module.exports = OAuthClient;