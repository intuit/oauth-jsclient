import * as popsicle from "popsicle";
import { Token } from "../access-token/Token";

export class AuthResponse {
  response: popsicle.Response;
  body: string;
  json: Record<string, any>;
  intuit_tid: string;
  token: Token;
  constructor(params: {
    token?: Token,
    response?: popsicle.Response,
    body?: string,
    intuit_id?: string
  });
  processResponse(response: popsicle.Response): void;
  getToken(): Token;
  text(): string;
  status(): number;
  headers(): Record<string, any>;
  valid(): boolean;
  getJson(): Record<string, any>;
  get_intuit_tid(): string;
  isContentType(): boolean;
  getContentType(): string;
  isJson(): boolean;
}
