/**
 * TypeScript declarations for intuit-oauth
 * Intuit Node.js client for OAuth2.0 and OpenIDConnect
 */

// =============================================================================
// Type Definitions
// =============================================================================

/**
 * Environment type for OAuth client
 */
type Environment = 'sandbox' | 'production';

/**
 * HTTP methods supported by makeApiCall
 */
type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

/**
 * Response types supported by makeApiCall
 */
type ResponseType = 'json' | 'text' | 'stream' | 'arraybuffer';

// =============================================================================
// Token Interfaces
// =============================================================================

/**
 * Token data structure
 */
interface TokenData {
  realmId?: string;
  token_type?: string;
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  x_refresh_token_expires_in?: number;
  id_token?: string;
  latency?: number;
  createdAt?: number;
  state?: string;
}

/**
 * Token class for managing OAuth tokens
 */
declare class Token {
  realmId: string;
  token_type: string;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  x_refresh_token_expires_in: number;
  id_token: string;
  latency: number;
  createdAt: number;
  /** State parameter (set during OAuth flow) */
  state?: string;

  constructor(params?: TokenData);

  /**
   * Get the access token string
   */
  accessToken(): string;

  /**
   * Get the refresh token string
   */
  refreshToken(): string;

  /**
   * Get the token type
   */
  tokenType(): string;

  /**
   * Get the full token object
   */
  getToken(): TokenData;

  /**
   * Set token data
   */
  setToken(tokenData: TokenData): Token;

  /**
   * Clear all token data
   */
  clearToken(): Token;

  /**
   * Check if access token is valid (not expired)
   */
  isAccessTokenValid(): boolean;

  /**
   * Check if refresh token is valid (not expired)
   */
  isRefreshTokenValid(): boolean;
}

// =============================================================================
// AuthResponse Interfaces
// =============================================================================

/**
 * Parameters for AuthResponse constructor
 */
interface AuthResponseParams {
  token?: Token;
  response?: any;
  responseText?: string;
  intuit_tid?: string;
}

/**
 * AuthResponse class for handling OAuth responses
 */
declare class AuthResponse {
  token: Token | string;
  response: any;
  body: string;
  json: any | null;
  intuit_tid: string;

  constructor(params: AuthResponseParams);

  /**
   * Process an HTTP response
   */
  processResponse(response: any): void;

  /**
   * Get the token object
   */
  getToken(): TokenData;

  /**
   * Get the response body as text
   */
  text(): string;

  /**
   * Get the HTTP status code
   */
  status(): number;

  /**
   * Get the response headers
   */
  headers(): Record<string, string>;

  /**
   * Check if the response is valid (2xx status)
   */
  valid(): boolean;

  /**
   * Get the response as JSON
   */
  getJson(): any | null;

  /**
   * Get the Intuit transaction ID
   */
  getIntuitTid(): string;

  /**
   * Check if response has specific content type
   */
  isContentType(contentType: string): boolean;

  /**
   * Get the content type header
   */
  getContentType(): string;

  /**
   * Check if response is JSON
   */
  isJson(): boolean;

  static _contentType: string;
  static _jsonContentType: string;
  static _urlencodedContentType: string;
}

// =============================================================================
// Error Classes
// =============================================================================

/**
 * Fault error detail from QuickBooks API
 */
interface FaultError {
  message: string;
  detail: string;
  code: string;
}

/**
 * Fault object from QuickBooks API error responses
 */
interface Fault {
  type: string;
  errors: FaultError[];
  time?: string;
}

/**
 * Base OAuth error class
 */
declare class OAuthError extends Error {
  name: string;
  message: string;
  code: string;
  description: string;
  intuitTid: string;
  /** Fault object from QuickBooks API error responses (present on 400 errors with Fault) */
  fault?: Fault;
  /** Fault type (e.g., 'ValidationFault') */
  faultType?: string;
  /** Timestamp from error response */
  timestamp?: string;

  constructor(
    message: string,
    code?: string,
    description?: string,
    intuitTid?: string,
    additionalProps?: {
      faultType?: string;
      fault?: Fault;
      timestamp?: string;
    }
  );

  /**
   * Convert error to string representation
   */
  toString(): string;

  /**
   * Convert error to JSON representation
   */
  toJSON(): {
    name: string;
    message: string;
    code: string;
    description: string;
    intuitTid: string;
    stack?: string;
  };
}

/**
 * Validation error class
 */
declare class ValidationError extends OAuthError {
  constructor(
    message: string,
    code?: string,
    description?: string,
    intuitTid?: string
  );
}

/**
 * Token error class
 */
declare class TokenError extends OAuthError {
  constructor(
    message: string,
    code?: string,
    description?: string,
    intuitTid?: string
  );
}

/**
 * Network error class
 */
declare class NetworkError extends OAuthError {
  constructor(message: string, intuitTid?: string);
}

// =============================================================================
// OAuthClient Interfaces
// =============================================================================

/**
 * Configuration for OAuthClient constructor
 */
interface OAuthClientConfig {
  /**
   * Environment: 'sandbox' or 'production'
   */
  environment: Environment;

  /**
   * OAuth client ID
   */
  clientId: string;

  /**
   * OAuth client secret
   */
  clientSecret: string;

  /**
   * Redirect URI for OAuth callback
   */
  redirectUri: string;

  /**
   * Initial token data (optional)
   */
  token?: TokenData;

  /**
   * Enable logging (optional, defaults to false)
   */
  logging?: boolean;
}

/**
 * Parameters for authorizeUri method
 */
interface AuthorizeUriParams {
  /**
   * OAuth scopes - can be a single scope string or array of scopes
   */
  scope: string | string[];

  /**
   * State parameter for CSRF protection (optional, auto-generated if not provided)
   */
  state?: string;
}

/**
 * Parameters for revoke method
 */
interface RevokeParams {
  /**
   * Access token to revoke (optional)
   */
  access_token?: string;

  /**
   * Refresh token to revoke (optional)
   */
  refresh_token?: string;
}

/**
 * Parameters for validateIdToken method
 */
interface ValidateIdTokenParams {
  /**
   * ID token to validate (optional, uses stored token if not provided)
   */
  id_token?: string;
}

/**
 * Parameters for setAuthorizeURLs method
 */
interface SetAuthorizeUrlsParams {
  /**
   * Custom authorize endpoint URL
   */
  authorizeEndpoint: string;

  /**
   * Custom token endpoint URL
   */
  tokenEndpoint: string;

  /**
   * Custom revoke endpoint URL
   */
  revokeEndpoint: string;

  /**
   * Custom user info endpoint URL
   */
  userInfoEndpoint: string;
}

/**
 * Parameters for makeApiCall method
 */
interface MakeApiCallParams {
  /**
   * URL for the API call (can be full URL or relative endpoint)
   */
  url: string;

  /**
   * HTTP method (optional, defaults to 'GET')
   */
  method?: HttpMethod;

  /**
   * Custom headers (optional)
   */
  headers?: Record<string, string>;

  /**
   * Request body (optional)
   */
  body?: any;

  /**
   * Query parameters (optional)
   */
  params?: Record<string, any>;

  /**
   * Request timeout in milliseconds (optional, defaults to 30000)
   */
  timeout?: number;

  /**
   * Response type (optional, defaults to 'json')
   */
  responseType?: ResponseType;

  /**
   * Maximum retry attempts (optional, defaults to 3)
   */
  maxRetries?: number;
}

/**
 * Response from makeApiCall
 */
interface ApiResponse {
  /**
   * HTTP status code
   */
  status: number;

  /**
   * HTTP status text
   */
  statusText: string;

  /**
   * Response headers
   */
  headers: Record<string, string>;

  /**
   * Parsed JSON response data
   */
  json: any;

  /**
   * Response body as string
   */
  body: string;
}

/**
 * OAuth scopes available
 */
interface OAuthScopes {
  Accounting: string;
  Payment: string;
  Payroll: string;
  TimeTracking: string;
  Benefits: string;
  Profile: string;
  Email: string;
  Phone: string;
  Address: string;
  OpenId: string;
  Intuit_name: string;
}

/**
 * Environment URLs
 */
interface EnvironmentUrls {
  sandbox: string;
  production: string;
}

/**
 * Retry configuration
 */
interface RetryConfig {
  maxRetries: number;
  retryDelay: number;
  retryableStatusCodes: number[];
  retryableErrors: string[];
}

// =============================================================================
// OAuthClient Class
// =============================================================================

/**
 * Wrapped error structure from createError method
 */
interface WrappedError extends Error {
  error: string;
  error_description: string;
  authResponse: AuthResponse | string;
  intuit_tid: string;
  originalMessage: string;
}

/**
 * Main OAuthClient class for Intuit OAuth2.0 and OpenID Connect
 */
declare class OAuthClient {
  /**
   * Current environment ('sandbox' or 'production')
   */
  environment: string | null;

  /**
   * OAuth client ID
   */
  clientId: string;

  /**
   * OAuth client secret
   */
  clientSecret: string;

  /**
   * Redirect URI
   */
  redirectUri: string;

  /**
   * Current token
   */
  token: Token;

  /**
   * Logging enabled
   */
  logging: boolean;

  /**
   * Logger instance (winston)
   */
  logger: any | null;

  // Static properties
  static cacheId: string;
  static authorizeEndpoint: string;
  static tokenEndpoint: string;
  static revokeEndpoint: string;
  static userinfo_endpoint_production: string;
  static userinfo_endpoint_sandbox: string;
  static migrate_sandbox: string;
  static migrate_production: string;
  static environment: EnvironmentUrls;
  static qbo_environment: EnvironmentUrls;
  static jwks_uri: string;
  static scopes: OAuthScopes;
  static user_agent: string;
  static retryConfig: RetryConfig;

  /**
   * Create a new OAuthClient instance
   */
  constructor(config: OAuthClientConfig);

  /**
   * Set custom OAuth endpoint URLs
   */
  setAuthorizeURLs(params: SetAuthorizeUrlsParams): OAuthClient;

  /**
   * Get the base environment URI
   */
  getEnvironmentURI(): string;

  /**
   * Get the QBO environment URI
   */
  getQBOEnvironmentURI(): string;

  /**
   * Generate the authorization URI for OAuth flow
   */
  authorizeUri(params: AuthorizeUriParams): string;

  /**
   * Exchange authorization code for access token
   * @param uri - The callback URI containing the authorization code
   */
  createToken(uri: string): Promise<AuthResponse>;

  /**
   * Refresh the access token using stored refresh token
   */
  refresh(): Promise<AuthResponse>;

  /**
   * Refresh tokens using an explicit refresh token
   * @param refresh_token - The refresh token to use
   */
  refreshUsingToken(refresh_token: string): Promise<AuthResponse>;

  /**
   * Revoke access or refresh token
   */
  revoke(params?: RevokeParams): Promise<AuthResponse>;

  /**
   * Get user info from OpenID Connect endpoint
   */
  getUserInfo(): Promise<AuthResponse>;

  /**
   * Make an API call to QuickBooks or other Intuit APIs
   */
  makeApiCall(params: MakeApiCallParams): Promise<ApiResponse>;

  /**
   * Validate an ID token
   */
  validateIdToken(params?: ValidateIdTokenParams): Promise<boolean>;

  /**
   * Get the current token
   */
  getToken(): Token;

  /**
   * Set a new token
   */
  setToken(params: TokenData): Token;

  /**
   * Check if access token is valid
   */
  isAccessTokenValid(): boolean;

  /**
   * Create a wrapped error with additional context
   * @param error - Original error
   * @param authResponse - AuthResponse object (optional)
   */
  createError(error: Error | string, authResponse?: AuthResponse | null): WrappedError;

  /**
   * Generate the authorization header (Base64 encoded clientId:clientSecret)
   */
  authHeader(): string;

  /**
   * Log a message (only if logging is enabled)
   */
  log(level: string, message: string, data?: any): void;

  /**
   * Validate the current token (checks refresh token validity)
   * @throws Error if refresh token is missing or invalid
   */
  validateToken(): boolean;

  /**
   * Get public key from modulus and exponent (for JWT validation)
   */
  getPublicKey(modulus: string | number, exponent: string | number): string;

  /**
   * Load response from JWKs URI
   */
  loadResponseFromJWKsURI(request: any): Promise<any>;

  /**
   * Make a token request (internal method, but exposed publicly)
   */
  getTokenRequest(request: any): Promise<AuthResponse>;

  /**
   * Load HTTP response using axios
   */
  loadResponse(request: any): Promise<any>;

  /**
   * Get key from JWKs URI for ID token validation
   */
  getKeyFromJWKsURI(id_token: string, kid: string, request: any): Promise<any>;

  /**
   * Check if request should be retried based on error and attempt count
   */
  shouldRetry(error: any, attempt: number): boolean;

  /**
   * Validate HTTP response
   * @throws OAuthError for invalid responses
   */
  validateResponse(response: any): boolean;
}

export = OAuthClient;
