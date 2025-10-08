'use strict';

/**
 * Base error class for OAuth related errors
 * @extends Error
 */
class OAuthError extends Error {
  /**
   * Create a new OAuthError
   * @param {string} message - Error message
   * @param {string} [code] - Error code
   * @param {string} [description] - Error description
   * @param {string} [intuitTid] - Intuit transaction ID
   * @throws {TypeError} If message is not a string
   */
  constructor(message, code, description, intuitTid) {
    if (typeof message !== 'string') {
      throw new TypeError('Error message must be a string');
    }

    // Call parent constructor
    super(message);

    // Set error name
    this.name = 'OAuthError';

    // Set error properties
    this.message = message;
    this.description = description || message;
    this.intuitTid = intuitTid || '';

    // Set error code
    if (typeof code === 'number' || (typeof code === 'string' && /^\d{3}$/.test(code))) {
      const statusCode = parseInt(code, 10);
      switch (statusCode) {
        case 400:
          this.code = '400';
          break;
        case 401:
          this.code = '401';
          break;
        case 403:
          this.code = '403';
          break;
        case 404:
          this.code = '404';
          break;
        case 429:
          this.code = '429';
          break;
        case 500:
          this.code = '500';
          break;
        case 502:
        case 503:
        case 504:
          this.code = statusCode.toString();
          break;
        default:
          this.code = code;
      }
    } else {
      this.code = code || 'OAUTH_ERROR';
    }

    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, OAuthError.prototype);

    // Capture stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, OAuthError);
    }
  }

  /**
   * Convert error to string representation
   * @returns {string} String representation of the error
   */
  toString() {
    let errorString = `${this.name}: ${this.message}`;
    
    if (this.code) {
      errorString += ` (${this.code})`;
    }
    
    if (this.description && this.description !== this.message) {
      errorString += ` - ${this.description}`;
    }
    
    if (this.intuitTid) {
      errorString += ` [TID: ${this.intuitTid}]`;
    }
    
    return errorString;
  }

  /**
   * Convert error to JSON representation
   * @returns {Object} JSON representation of the error
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      description: this.description,
      intuitTid: this.intuitTid,
      stack: this.stack,
    };
  }
}

module.exports = OAuthError; 