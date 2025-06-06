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
    // Set intuit_tid from headers if available
    this.intuit_tid = (response.headers && response.headers.intuit_tid) || '';

    if (response.data) {
      // Handle axios response
      this.body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
      
      // Handle QuickBooks API error response
      if (response.data.Fault) {
        this.json = {
          Fault: response.data.Fault,
          time: response.data.time || new Date().toISOString(),
          intuit_tid: this.intuit_tid,
        };
        // Store the full response including headers and status
        this.response = {
          ...response,
          data: this.json,
          status: response.status || 400,
          statusText: response.statusText || 'Bad Request',
        };
      } else {
        // Store the raw response data
        this.json = response.data;
        // Store the full response for successful responses
        this.response = {
          ...response,
          data: this.json,
        };
      }
    } else if (response.body) {
      // Handle other response types
      this.body = response.body;
      try {
        const parsedBody = typeof response.body === 'string' ? JSON.parse(response.body) : response.body;
        
        // Handle QuickBooks API error response
        if (parsedBody.Fault) {
          this.json = {
            Fault: parsedBody.Fault,
            time: parsedBody.time || new Date().toISOString(),
            intuit_tid: this.intuit_tid,
          };
          // Store the full response including headers and status
          this.response = {
            ...response,
            data: this.json,
            status: response.status || 400,
            statusText: response.statusText || 'Bad Request',
          };
        } else {
          // Store the raw response data
          this.json = parsedBody;
          // Store the full response for successful responses
          this.response = {
            ...response,
            data: this.json,
          };
        }
      } catch (e) {
        this.json = null;
        this.response = response;
      }
    } else {
      this.body = '';
      this.json = null;
      this.response = response;
    }
  } else {
    this.body = '';
    this.json = null;
    this.response = null;
  }
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
 * Get Json () { returns response as JSON }
 * *
 * @return {object} json
 * @throws {Error} If response cannot be parsed as JSON
 */
AuthResponse.prototype.getJson = function getJson() {
  // If we already have parsed JSON, return it
  if (this.json !== null) {
    return this.json;
  }

  // Try to parse the body if we have one
  if (this.body) {
    try {
      this.json = typeof this.body === 'string' ? JSON.parse(this.body) : this.body;
      
      // Handle QuickBooks API error response
      if (this.json.Fault) {
        this.json = {
          Fault: this.json.Fault,
          time: this.json.time || new Date().toISOString(),
          intuit_tid: this.intuit_tid,
        };
      }
      
      return this.json;
    } catch (e) {
      throw new Error(`Failed to parse response as JSON: ${e.message}`);
    }
  }

  // If we have no body, return null
  return null;
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
