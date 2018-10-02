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
 * @namespace AuthResponse
 */

/**
 * AuthResponse
 * @property {Token} token
 * @property {Response} response
 * @property {string} body
 * @property {object} json
 * @property {string} intuit_tid
 */
function AuthResponse(params) {

    this.token = params.token || '';
    this.response = params.response || '';
    this.body = params.responseText || '';
    this.json = null;
    this.intuit_tid = params.intuit_tid || '';
}

/**
 * Process Response
 * @param response
 */
AuthResponse.prototype.processResponse = function(response) {

    this.response = response || '';
    this.body = response.body || '';
    this.json = this.body ? JSON.parse(this.body) : null;
    this.intuit_tid = response.headers['intuit_tid'] || '';
}

/**
 * @return {AuthResponse}
 */
AuthResponse.prototype.getToken = function() {
    return this.token.getToken();
};



/**
 * @return {AuthResponse}
 */
AuthResponse.prototype.text = function() {
    return this.body;
};

/**
 *
 * @returns {*}
 */
AuthResponse.prototype.status = function() {
    return this.response.status;
};

/**
 * Get response headers
 * @returns {Object} headers
 */
AuthResponse.prototype.headers = function() {
    return this.response.headers;
};

/**
 * valid { response is valid ? }
 * @returns {*|boolean}
 */
AuthResponse.prototype.valid = function() {

    return (this.response && this.response.status == '200');
};


/**
 * Get Json () { returns token as JSON }
 * @return {object} this.json
 */
AuthResponse.prototype.getJson = function() {
    if (!this.isJson()) throw new Error('AuthResponse is not JSON');
    if (!this.json) {
        this.json = this.body ? JSON.parse(this.body) : null;
    }
    return this.json;
};

/**
 * Get Intuit tid
 * @returns {string} intuit_tid
 */
AuthResponse.prototype.get_intuit_tid = function() {

    return this.intuit_tid;
};


/**
 * @private
 */
AuthResponse.prototype.isContentType = function(contentType) {
    return this.getContentType().indexOf(contentType) > -1;
};

/**
 * @private
 */
AuthResponse.prototype.getContentType = function() {
    return this.response.get(AuthResponse._contentType) || '';
};

/**
 * @private
 */
AuthResponse.prototype.isJson = function() {
    return this.isContentType('application/json');
};


AuthResponse._contentType = 'Content-Type';
AuthResponse._jsonContentType = 'application/json';
AuthResponse._urlencodedContentType = 'application/x-www-form-urlencoded';


module.exports = AuthResponse;