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
 * @namespace Token
 */


/**
 * @param {Cache} options.cache
 * @param {string} options.cacheId
 * @constructor
 * @property {Cache} _cache
 * @property {string} _cacheId
 */
function Token(params) {

    params = params || {};

    this.realmId = params.realmId || '';
    this.token_type = params.token_type || '';
    this.access_token = params.access_token || '';
    this.refresh_token = params.refresh_token || '';
    this.expires_in = params.expires_in || 0;
    this.x_refresh_token_expires_in = params.x_refresh_token_expires_in || 0;
    this.id_token = params.id_token || '';
    this.latency = params.latency || 60 * 1000;
    this.createdAt = params.createdAt || Date.now();
}

/**
 * get accessToken()
 * @returns {string} access_token
 */
Token.prototype.accessToken = function() {
    return this.getToken().access_token;
};

/**
 * get refreshToken()
 * @returns {string} refresh_token
 */
Token.prototype.refreshToken = function() {
    return this.getToken().refresh_token;
};

/**
 * get tokenType()
 * @returns {string} token_type
 */
Token.prototype.tokenType = function() {
    return this.getToken().token_type;
};


/**
 * Helper Method to get accessToken { get Token Object }
 * @returns {{token_type: *, access_token: *, expires_in: *, refresh_token: *, x_refresh_token_expires_in: *}}
 */
Token.prototype.getToken = function() {

    return  {
        token_type: this.token_type,
        access_token: this.access_token,
        expires_in: this.expires_in,
        refresh_token: this.refresh_token,
        x_refresh_token_expires_in: this.x_refresh_token_expires_in,
        realmId: this.realmId,
        id_token: this.id_token,
        createdAt: this.createdAt
    };

};

/**
 * Helper Method to set accessToken { set Token Object }
 * @param tokenData
 * @returns {Token}
 */
Token.prototype.setToken = function(tokenData) {

    this.access_token = tokenData.access_token;
    this.refresh_token = tokenData.refresh_token;
    this.token_type = tokenData.token_type ;
    this.expires_in = tokenData.expires_in;
    this.x_refresh_token_expires_in = tokenData.x_refresh_token_expires_in;
    this.id_token = tokenData.id_token || '';
    this.createdAt = tokenData.createdAt || Date.now();
    return this;

};

/**
 * Helper Method to check token expiry { set Token Object }
 * @param seconds
 * @returns {boolean}
 */
Token.prototype._checkExpiry = function(seconds) {
    var expiry = this.createdAt + (seconds * 1000);
    return (expiry  - this.latency > Date.now());
}

/**
 * Check if access_token is valid
 * @returns {boolean}
 */
Token.prototype.isAccessTokenValid = function() {
    return this._checkExpiry(this.expires_in);
};

/**
 * Check if there is a valid (not expired) access token
 * @return {boolean}
 */
Token.prototype.isRefreshTokenValid = function() {
    return this._checkExpiry(this.x_refresh_token_expires_in);
};

module.exports = Token;