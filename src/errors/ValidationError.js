'use strict';

const OAuthError = require('./OAuthError');

/**
 * Error class for validation related errors
 * @extends OAuthError
 */
class ValidationError extends OAuthError {
  /**
   * Create a new ValidationError
   * @param {string} message - Error message
   * @param {string} [code] - Error code
   * @param {string} [description] - Error description
   * @param {string} [intuitTid] - Intuit transaction ID
   */
  constructor(message, code, description, intuitTid) {
    super(message, code || 'VALIDATION_ERROR', description || message, intuitTid);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

module.exports = ValidationError; 