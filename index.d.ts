declare module 'intuit-oauth' {
  export default OAuthClient;

  export type OAuthClientConfig = {
    clientId: string,
    clientSecret: string,
    environment: 'sandbox' | 'production',
    redirectUri: string,
    logging?: boolean
  };

  export class OAuthClient {
    public clientId: string;
    public clientSecret: string;
    public environment: string;
    public redirectUri: string;
    constructor(config: OAuthClientConfig);
    authorizeUri(params: AuthorizeUriParams): string;
    createToken(uri: string): Promise<Response<TokenData>>;
    refresh(): Promise<Response<TokenData>>;
    refreshUsingToken(refreshToken: string): Promise<Response<TokenData>>;
    revoke(params?: RevokeParams): Promise<Response>;
    isAccessTokenValid(): boolean;
    isRefreshTokenValid(): boolean;
    getToken(): Token;
    setToken(params?: TokenParams): Token;
    static scopes: {
      Accounting: string,
      Payment: string,
      Payroll: string,
      TimeTracking: string,
      Benefits: string,
      Profile: string,
      Email: string,
      Phone: string,
      Address: string,
      OpenId: string
    };
    static environment: {
      sandbox: string,
      production: string
    };
  };

  export class Response<T extends object = object> {
    getJson(): T;
  }

  export type TokenParams = {
    realmId?: string;
    token_type?: string;
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    x_refresh_token_expires_in?: number;
    id_token?: string;
    latency?: number;
    createdAt?: Date;
  };

  export class Token {
    realmId: string;
    constructor(params?: TokenParams);
    accessToken(): string;
    refreshToken(): string;
    tokenType(): string;
    getToken(): TokenData;
    setToken(tokenData: TokenData): Token;
    clearToken(): Token;
    isAccessTokenValid(): boolean;
    isRefreshTokenValid(): boolean;
  };

  export type TokenData = {
    token_type: string;
    access_token: string;
    refresh_token: string;
    expires_in: number;
    x_refresh_token_expires_in: number;
    id_token: string;
    latency: number;
    createdAt: Date;
  };

  export type AuthorizeUriParams = {
    scope: string | Array<string>,
    state?: string
  };

  export type RevokeParams = {
    access_token?: string,
    refresh_token?: string
  };
}
