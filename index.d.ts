import csrf from 'csrf';

declare class AuthResponse {
    constructor(params: AuthResponse.AuthResponseParams);
    getToken(): Token;
    text(): string;
    status(): number;
    headers(): Object;
    valid(): boolean;
    getJson(): Object;
    get_intuit_tid(): string;
}

declare namespace AuthResponse {
    export interface AuthResponseParams {
        token?: Token;
        response?: Response;
        body?: string;
        json?: Object;
        intuit_tid?: string;
    }
}

declare class Token implements Token.TokenData {
    latency: number;
    accessToken(): string;
    refreshToken(): string;
    tokenType(): string;
    getToken(): Token.TokenData;
    setToken(tokenData: Token.TokenData): Token;
    clearToken(): Token;
    isAccessTokenValid(): boolean;
    isRefreshTokenValid(): boolean;
}

declare namespace Token {
    export interface TokenData {
        realmId: string;
        token_type: string;
        access_token: string;
        refresh_token: string;
        expires_in: number;
        x_refresh_token_expires_in: number;
        id_token: string;
        createdAt: string;
    }
}

declare class OAuthClient {
    constructor(config: OAuthClient.OAuthClientConfig);
    authHeader(): string;
    authorizeUri(params: OAuthClient.AuthorizeParams): string;
    createError(e: Error, authResponse?: AuthResponse): OAuthClient.OAuthClientError;
    createToken(uri: string): Promise<AuthResponse>;
    generateOauth1Sign(params: OAuthClient.GenerateOAuth1SignParams): string;
    getKeyFromJWKsURI(id_token: string, kid: string, request: Request): Promise<object | string>;
    getPublicKey(modulus: string, exponent: string): string;
    getToken(): Token;
    getTokenRequest(request: Request): Promise<AuthResponse>;
    getUserInfo(params?: OAuthClient.GetUserInfoParams): Promise<AuthResponse>;
    isAccessTokenValid(): boolean;
    loadResponse(request: Request): Promise<Response>;
    loadResponseFromJWKsURI(request: Request): Promise<Response>;
    log(level: string, message: string, messageData: any): void;
    makeApiCall(params?: OAuthClient.MakeApiCallParams): Promise<AuthResponse>;
    migrate(params: OAuthClient.MigrateParams): Promise<AuthResponse>;
    refresh(): Promise<AuthResponse>;
    refreshUsingToken(refresh_token: string): Promise<AuthResponse>;
    revoke(params?: OAuthClient.RevokeParams): Promise<AuthResponse>;
    setToken(params: Token.TokenData): Token;
    validateIdToken(params: OAuthClient.ValidateIdTokenParams): Promise<any>;
    validateToken(): void;
}

declare namespace OAuthClient {
    export interface OAuthClientConfig {
        environment: string;
        appSecret: string;
        appKey: string;
        cachePrefix?: string;
    }

    export enum Environment {
        sandbox = 'https://sandbox-quickbooks.api.intuit.com/',
        production = 'https://quickbooks.api.intuit.com/'
    }

    export enum AuthorizeScope {
        Accounting = 'com.intuit.quickbooks.accounting',
        Payment = 'com.intuit.quickbooks.payment',
        Payroll = 'com.intuit.quickbooks.payroll',
        TimeTracking = 'com.intuit.quickbooks.payroll.timetracking',
        Benefits = 'com.intuit.quickbooks.payroll.benefits',
        Profile = 'profile',
        Email = 'email',
        Phone = 'phone',
        Address = 'address',
        OpenId = 'openid',
        Intuit_name = 'intuit_name'
    }

    export interface AuthorizeParams {
        scope: AuthorizeScope | AuthorizeScope[] | string;
        state?: csrf;
    }

    export interface RevokeParams {
        access_token?: string;
        refresh_token?: string;
    }

    export interface GetUserInfoParams { }

    export interface MakeApiCallParams {
        url: string;
    }

    export interface MigrateParams extends GenerateOAuth1SignParams {
        scope?: AuthorizeScope | AuthorizeScope[] | string;
    }

    export interface GenerateOAuth1SignParams {
        oauth_consumer_key: string;
        oauth_consumer_secret: string;
        access_token: string;
        access_secret: string;
        method: 'GET' | 'POST';
        uri: string;
    }

    export interface ValidateIdTokenParams {
        id_token?: string;
    }

    export interface OAuthClientError extends Error {
        intuit_tid: string;
        authResponse: AuthResponse;
        originalMessage: string;
        error_description: string;
    }
}

export = OAuthClient;
