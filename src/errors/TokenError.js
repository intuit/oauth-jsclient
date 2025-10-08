'use strict';

const OAuthError = require('./OAuthError');

/**
 * Error class for token related errors
 * @extends OAuthError
 */
class TokenError extends OAuthError {
  /**
   * Create a new TokenError
   * @param {string} message - Error message
   * @param {string} [code] - Error code
   * @param {string} [description] - Error description
   * @param {string} [intuitTid] - Intuit transaction ID
   */
  constructor(message, code, description, intuitTid) {
    super(message, code || 'TOKEN_ERROR', description || message, intuitTid);
    this.name = 'TokenError';
    Object.setPrototypeOf(this, TokenError.prototype);
  }
}

module.exports = TokenError; 