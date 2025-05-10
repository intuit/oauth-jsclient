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

'use strict';

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
AuthResponse.prototype.processResponse = function processResponse(response) {
  this.response = response || '';
  
  // Handle response data
  if (response) {
    if (response.data) {
      // Handle axios response
      this.body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
      this.json = response.data;
    } else if (response.body) {
      // Handle other response types
      this.body = response.body;
      try {
        this.json = typeof response.body === 'string' ? JSON.parse(response.body) : response.body;
      } catch (e) {
        this.json = null;
      }
    } else {
      this.body = '';
      this.json = null;
    }
  } else {
    this.body = '';
    this.json = null;
  }

  // Set intuit_tid
  this.intuit_tid = (response && response.headers && response.headers.intuit_tid) || '';
};

/**
 * Get Token
 * *
 * @returns {object} token
 */
AuthResponse.prototype.getToken = function getToken() {
  return this.token.getToken();
};

/**
 * Get Token
 * *
 * @returns {string} text
 */
AuthResponse.prototype.text = function text() {
  return this.body;
};

/**
 * Get Token
 * *
 * @returns {Number} statusCode
 */
AuthResponse.prototype.status = function status() {
  return this.response.status;
};

/**
 * Get response headers
 * *
 * @returns {Object} headers
 */
AuthResponse.prototype.headers = function headers() {
  return this.response.headers;
};

/**
 * Is Response valid { response is valid ? }
 * *
 * @returns {*|boolean}
 */
AuthResponse.prototype.valid = function valid() {
  return this.response && Number(this.response.status) >= 200 && Number(this.response.status) < 300;
};

/**
 * Get Json () { returns token as JSON }
 * *
 * @return {object} json
 */
AuthResponse.prototype.getJson = function getJson() {
  if (!this.isJson()) {
    throw new Error('Response is not JSON');
  }
  if (!this.json) {
    try {
      this.json = this.body ? JSON.parse(this.body) : null;
    } catch (e) {
      throw new Error(`Invalid JSON response: ${e.message}`);
    }
  }
  return this.json;
};

/**
 * Get Intuit tid
 * *
 * @returns {string} intuit_tid
 */
AuthResponse.prototype.getIntuitTid = function getIntuitTid() {
  return this.intuit_tid;
};

/**
 * isContentType
 * *
 * @returns {boolean} isContentType
 */
AuthResponse.prototype.isContentType = function isContentType(contentType) {
  return this.getContentType().indexOf(contentType) > -1;
};

/**
 * getContentType
 * *
 * @returns {string} getContentType
 */
AuthResponse.prototype.getContentType = function getContentType() {
  return this.response.headers[AuthResponse._contentType] || '';
};

/**
 * isJson
 * *
 * @returns {boolean} isJson
 */
AuthResponse.prototype.isJson = function isJson() {
  return this.isContentType('application/json');
};

AuthResponse._contentType = 'content-type';
AuthResponse._jsonContentType = 'application/json';
AuthResponse._urlencodedContentType = 'application/x-www-form-urlencoded';

module.exports = AuthResponse;
