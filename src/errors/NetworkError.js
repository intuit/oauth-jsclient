'use strict';

const OAuthError = require('./OAuthError');

/**
 * Error class for network related errors
 * @extends OAuthError
 */
class NetworkError extends OAuthError {
  /**
   * Create a new NetworkError
   * @param {string} message - Error message
   * @param {string} intuitTid - Intuit transaction ID
   */
  constructor(message, intuitTid) {
    super(message, 'NETWORK_ERROR', 'Network request failed', intuitTid);
    this.name = 'NetworkError';
  }
}

module.exports = NetworkError; 