import * as winston from "winston";
import * as popsicle from 'popsicle';
import * as jwt from 'jsonwebtoken';
import { AuthResponse } from "./response/AuthResponse";
import { Token } from "./access-token/Token";
import * as Csrf from 'csrf';

interface Scopes {
  Accounting: 'com.intuit.quickbooks.accounting',
  Payment: 'com.intuit.quickbooks.payment',
  Payroll: 'com.intuit.quickbooks.payroll',
  TimeTracking: 'com.intuit.quickbooks.payroll.timetracking',
  Benefits: 'com.intuit.quickbooks.payroll.benefits',
  Profile: 'profile',
  Email: 'email',
  Phone: 'phone',
  Address: 'address',
  OpenId: 'openid',
  Intuit_name: 'intuit_name',
}
interface Environment {
  sandbox: 'https://sandbox-quickbooks.api.intuit.com/',
  production: 'https://quickbooks.api.intuit.com/',
}

export default class OAuthClient {
  static cacheId: 'cacheID';
  static authorizeEndpoint: 'https://appcenter.intuit.com/connect/oauth2';
  static tokenEndpoint: 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
  static revokeEndpoint: 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke';
  static userinfo_endpoint_production:
    'https://accounts.platform.intuit.com/v1/openid_connect/userinfo';
  static userinfo_endpoint_sandbox:
    'https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo';
  static migrate_sandbox: 'https://developer-sandbox.api.intuit.com/v2/oauth2/tokens/migrate';
  static migrate_production: 'https://developer.api.intuit.com/v2/oauth2/tokens/migrate';
  static environment: Environment;
  static jwks_uri: 'https://oauth.platform.intuit.com/op/v1/jwks';
  static user_agent: string;
  static scopes: Scopes;
  environment: keyof Environment;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  token: Token;
  logging: boolean;
  logger: winston.Logger | null;
  state: Csrf;

  constructor(params: {
    clientId: string,
    clientSecret: string,
    environment: keyof Environment,
    redirectUri: string
  });
  getJson(): Record<string, any>;
  setToken(opts: {
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
    x_refresh_token_expires_in: number;
    id_token?: string;
    createdAt?: number
  }): Token;
  setAuthorizeURLs(params: {
    authorizeEndpoint: string;
    tokenEndpoint: string;
    revokeEndpoint: string;
    userInfoEndpoint: string;
  }): this;
  authorizeUri(opts: {
    scope: Scopes[keyof Scopes][],
    state: string
  }): string;
  createToken(uri: string): Promise<AuthResponse>;
  refresh(): Promise<AuthResponse>;
  refreshUsingToken(refreshToken: string): Promise<AuthResponse>;
  revoke(params?: { access_token: string, refresh_token: string }): Promise<AuthResponse>;
  getUserInfo(): Promise<AuthResponse>;
  makeApiCall(params: { transport: popsicle.TransportOptions, url: string, method: string, headers: Record<string, string>, body: Record<string, any> }): Promise<AuthResponse>;
  validateIdToken(params?: { id_token: string }): Promise<boolean>;
  getValidatedIdToken(params?: { id_token: string }): Promise<jwt.JwtPayload>;
  getKeyFromJWKsURI(id_token: string, kid: string, request: popsicle.Request): Promise<jwt.JwtPayload>;
  getPublicKey(): string;
  getTokenRequest(request: popsicle.Request): Promise<AuthResponse>;
  validateToken(): boolean;
  loadResponse(request: popsicle.Request): Promise<popsicle.Response>;
  loadResponseFromJWKsURI(request: popsicle.Request): Promise<popsicle.Response>;
  createError(e: Error, authResponse: AuthResponse): Error;
  isAccessTokenValid(): boolean;
  getToken(): Token;
  authHeader(): string;
  log(level: keyof winston.config.NpmConfigSetLevels, message: string, messageData: string): void;
}
