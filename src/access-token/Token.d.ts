
export class Token {
  realmId:                    string;
  token_type:                 string;
  access_token:               string;
  refresh_token:              string;
  expires_in:                 number;
  x_refresh_token_expires_in: number;
  id_token:                   string;
  latency:                    number;
  createdAt:                  number;
  constructor(opts?: {
    realmId: string,
    token_type: string,
    access_token: string,
    refresh_token: string,
    expires_in: number,
    x_refresh_token_expires_in: number,
    id_token: string,
    latency: number,
    createdAt: number
  });
  isAccessTokenValid(): boolean;
  isRefreshTokenValid(): boolean;
  accessToken(): string;
  refreshToken(): string;
  tokenType(): string;
  getToken(): Token;
  setToken(opts: {
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
    x_refresh_token_expires_in: number;
    id_token?: string;
    createdAt?: number
  }): this;
  clearToken(): this;
}
