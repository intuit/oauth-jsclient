[![SDK Banner](views/SDK.png)][ss1]

[![Build Status](https://travis-ci.org/intuit/oauth-jsclient.svg?branch=master)](https://travis-ci.org/intuit/oauth-jsclient?branch=master)
[![NPM Package Version](https://img.shields.io/npm/v/intuit-oauth.svg?style=flat-square)](https://www.npmjs.com/package/intuit-oauth)
[![Coverage Status](https://coveralls.io/repos/github/intuit/oauth-jsclient/badge.svg?branch=master)](https://coveralls.io/github/intuit/oauth-jsclient?branch=master)
[![GitHub contributors](https://img.shields.io/github/contributors/intuit/oauth-jsclient?style=flat-square)](https://github.com/intuit/oauth-jsclient/graphs/contributors)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/intuit/oauth-jsclient/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/intuit/oauth-jsclient/?branch=master)
![npm](https://img.shields.io/npm/dm/intuit-oauth?style=flat-square)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=shield)](https://github.com/prettier/prettier)
[![Known Vulnerabilities](https://snyk.io/test/github/intuit/oauth-jsclient/badge.svg)](https://snyk.io/test/github/intuit/oauth-jsclient)

# OAuth Client for Intuit

A Node.js client for Intuit's OAuth 2.0 implementation.

## Features

- OAuth 2.0 authentication flow
- Token management and refresh
- API request handling
- Error handling with custom error types
- Automatic retry for transient errors
- Structured logging
- Response validation

## Installation

```bash
npm install oauth-jsclient
```

## Usage

```javascript
const OAuthClient = require('oauth-jsclient');

const oauthClient = new OAuthClient({
  clientId: 'your_client_id',
  clientSecret: 'your_client_secret',
  environment: 'sandbox', // or 'production'
  redirectUri: 'http://localhost:8000/callback',
  logging: true // Enable logging
});
```

## Error Handling

The client provides several custom error types for better error handling:

- `OAuthError`: Base error class for all OAuth related errors
- `NetworkError`: For network related errors
- `ValidationError`: For validation related errors
- `TokenError`: For token related errors

Example error handling:

```javascript
try {
  await oauthClient.makeApiCall({ url: 'https://api.example.com' });
} catch (error) {
  if (error instanceof TokenError) {
    // Handle token errors
    console.error('Token error:', error.code, error.description);
  } else if (error instanceof NetworkError) {
    // Handle network errors
    console.error('Network error:', error.message);
  } else if (error instanceof ValidationError) {
    // Handle validation errors
    console.error('Validation error:', error.message);
  } else {
    // Handle other errors
    console.error('Unexpected error:', error);
  }
}
```

## Retry Logic

The client includes automatic retry logic for transient errors:

- Maximum 3 retries
- Exponential backoff (1s, 2s, 4s)
- Retries on specific status codes (408, 429, 500, 502, 503, 504)
- Retries on network errors (ECONNRESET, ETIMEDOUT, ECONNREFUSED)

You can configure retry behavior:

```javascript
OAuthClient.retryConfig = {
  maxRetries: 3,
  retryDelay: 1000,
  retryableStatusCodes: [408, 429, 500, 502, 503, 504],
  retryableErrors: ['ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED']
};
```

## Logging

The client provides structured logging when enabled:

```javascript
const oauthClient = new OAuthClient({
  // ... other config
  logging: true
});
```

Log entries include:
- Timestamp
- Log level
- Message
- Request context (URL, method, headers)
- Error details (for error logs)
- Environment information
- Client ID

Example log entry:
```json
{
  "timestamp": "2024-03-14T12:00:00.000Z",
  "level": "error",
  "message": "API call failed",
  "data": {
    "error": {
      "name": "TokenError",
      "code": "UNAUTHORIZED",
      "message": "Invalid or expired access token",
      "stack": "...",
      "intuit_tid": "1234-1234-1234-123"
    }
  },
  "environment": "sandbox",
  "clientId": "your_client_id",
  "request": {
    "url": "https://api.example.com",
    "method": "GET",
    "headers": {
      "Authorization": "Bearer ...",
      "Accept": "application/json"
    }
  }
}
```

## Response Validation

The client validates responses and throws appropriate errors for common scenarios:

- 401 Unauthorized: Invalid or expired access token
- 403 Forbidden: Insufficient permissions
- 429 Too Many Requests: Rate limit exceeded
- Missing or invalid response data
- Invalid content types

## API Reference

### OAuthClient

#### constructor(config)
Creates a new OAuthClient instance.

```javascript
const oauthClient = new OAuthClient({
  clientId: 'your_client_id',
  clientSecret: 'your_client_secret',
  environment: 'sandbox',
  redirectUri: 'http://localhost:8000/callback',
  logging: true
});
```

#### makeApiCall(params)
Makes an API call with automatic retry and error handling.

```javascript
const response = await oauthClient.makeApiCall({
  url: 'https://api.example.com',
  method: 'GET',
  headers: {
    'Custom-Header': 'value'
  },
  body: {
    key: 'value'
  }
});
```

#### validateResponse(response)
Validates an API response and throws appropriate errors.

```javascript
try {
  oauthClient.validateResponse(response);
} catch (error) {
  // Handle validation errors
}
```

## License

Apache License 2.0

# Intuit OAuth2.0 NodeJS Library

The OAuth2 Nodejs Client library is meant to work with Intuit's
[OAuth2.0](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0)
and
[OpenID Connect](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/openid-connect)
implementations which conforms to the specifications.

## Table of Contents

- [Intuit OAuth2.0 NodeJS Library](#intuit-oauth20-nodejs-library)
  - [Table of Contents](#table-of-contents)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Using NodeJS](#using-nodejs)
    - [Options :](#options)
- [Usage](#usage)
  - [Authorization Code Flow](#authorization-code-flow)
    - [Step 1](#step-1)
    - [Scopes :](#scopes)
    - [Step 2](#step-2)
- [Sample](#sample)
  - [Helpers](#helpers)
    - [Is AccessToken Valid](#is-accesstoken-valid)
    - [Refresh access_token](#refresh-access_token)
    - [Refresh access_token by passing the refresh_token explicitly](#refresh-access_token-by-passing-the-refresh_token-explicitly)
    - [Revoke access_token](#retrieve-the-token-)
    - [Getter / Setter for Token](#getter--setter-for-token)
      - [Retrieve the Token :](#retrieve-the-token)
      - [Set the Token :](#set-the-token-)
    - [Migrate OAuth1.0 Tokens to OAuth2.0](#migrate-oauth10-tokens-to-oauth20)
    - [Validate ID Token](#validate-id-token)
    - [Make API call](#make-api-call)
    - [Auth-Response](#auth-response)
    - [Error Logging](#error-logging)
  - [FAQ](#faq)
  - [Contributing](#contributing)
    - [Steps](#steps)
  - [Changelog](#changelog)
  - [License](#license)

# Requirements

The Node.js client library is tested against the `Node 10` and newer versions.

| Version                                                                          | Node support                      |
|----------------------------------------------------------------------------------|-----------------------------------|
| [intuit-oauth@1.x.x](https://github.com/intuit/oauth-jsclient/tree/1.5.0)        | Node 6.x or higher                |
| [intuit-oauth@2.x.x](https://github.com/intuit/oauth-jsclient/tree/2.0.0)        | Node 7.x or higher                |
| [intuit-oauth@3.x.x](https://github.com/intuit/oauth-jsclient/tree/3.0.2)        | Node 8.x or Node 9.x and higher   |

**Note**: Older node versions are not supported.

# Installation

Follow the instructions below to use the library :

## Using NodeJS

1. Install the NPM package:

   ```sh
   npm install intuit-oauth --save
   ```

2. Require the Library:

   ```js
   const OAuthClient = require('intuit-oauth');

   const oauthClient = new OAuthClient({
     clientId: '<Enter your clientId>',
     clientSecret: '<Enter your clientSecret>',
     environment: 'sandbox' || 'production',
     redirectUri: '<Enter your callback URL>',
   });
   ```

### Options

- `clientId` - clientID for your app. Required
- `clientSecret` - clientSecret fpor your app. Required
- `environment` - environment for the client. Required
  - `sandbox` - for authorizing in sandbox.
  - `production` - for authorizing in production.
- `redirectUri` - redirectUri on your app to get the `authorizationCode` from Intuit Servers. Make sure this redirect URI is also added on your app in the [developer portal](https://developer.intuit.com) on the Keys & OAuth tab. Required
- `logging` - by default, logging is disabled i.e `false`. To enable provide`true`.

# Usage

We assume that you have a basic understanding about OAuth2.0. If not please read
[API Documentation](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0)
for clear understanding

## Authorization Code Flow

The Authorization Code flow is made up of two parts :

**Step 1.** Redirect user to `oauthClient.authorizeUri(options)`.  
**Step 2.** Parse response uri and get access-token using the function
`oauthClient.createToken(req.url)` which returns a
[Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise).

### Step 1

```javascript
// Instance of client
const oauthClient = new OAuthClient({
  clientId: '<Enter your clientId>',
  clientSecret: '<Enter your clientSecret>',
  environment: 'sandbox',
  redirectUri: '<http://localhost:8000/callback>',
});

// AuthorizationUri
const authUri = oauthClient.authorizeUri({
  scope: [OAuthClient.scopes.Accounting, OAuthClient.scopes.OpenId],
  state: 'testState',
}); // can be an array of multiple scopes ex : {scope:[OAuthClient.scopes.Accounting,OAuthClient.scopes.OpenId]}

// Redirect the authUri
res.redirect(authUri);
```

### Scopes

The available scopes include :

- `com.intuit.quickbooks.accounting` - for accounting scope include `OAuthClient.scopes.Accounting`
- `com.intuit.quickbooks.payment` - for payment scope include `OAuthClient.scopes.Payment`
- `com.intuit.quickbooks.payroll` - for QuickBooks Payroll API (whitelisted beta apps only)
- `com.intuit.quickbooks.payroll.timetracking` - for QuickBooks Payroll API for for access to
  compensation (whitelisted beta apps only)
- `com.intuit.quickbooks.payroll.benefits` - for QuickBooks Payroll API for access to
  benefits/pension/deduction (whitelisted beta apps only)

OpenID Scopes :

- `openid` - for openID assertion include `OAuthClient.scopes.OpenId`
- `profile` - for profile assertion include `OAuthClient.scopes.Profile`
- `email` - for email assertion include `OAuthClient.scopes.Email`
- `phone` - for phone assertion include `OAuthClient.scopes.Phone`
- `address` - for address assertion include `OAuthClient.scopes.Address`

### Step 2

```javascript
// Parse the redirect URL for authCode and exchange them for tokens
const parseRedirect = req.url;

// Exchange the auth code retrieved from the **req.url** on the redirectUri
oauthClient
  .createToken(parseRedirect)
  .then(function (authResponse) {
    console.log('The Token is  ' + JSON.stringify(authResponse.getToken()));
  })
  .catch(function (e) {
    console.error('The error message is :' + e.originalMessage);
    console.error(e.intuit_tid);
  });
```

# Sample

For more clarity, we suggest you take a look at the sample application below :  
[sample](https://github.com/intuit/oauth-jsclient/tree/master/sample)

## Helpers

### Is AccessToken Valid

You can check if the `access_token` associated with the `oauthClient` is valid ( not expired ) or
not using the helper method.

```javascript
if (oauthClient.isAccessTokenValid()) {
  console.log('The access_token is valid');
}

if (!oauthClient.isAccessTokenValid()) {
  oauthClient
    .refresh()
    .then(function (authResponse) {
      console.log('Tokens refreshed : ' + JSON.stringify(authResponse.getToken()));
    })
    .catch(function (e) {
      console.error('The error message is :' + e.originalMessage);
      console.error(e.intuit_tid);
    });
}
```

\*\* Note: If the access_token is not valid, you can call the client's `refresh()` method to refresh
the tokens for you as shown below

### Refresh access_token

Access tokens are valid for 3600 seconds (one hour), after which time you need to get a fresh one
using the latest refresh_token returned to you from the previous request. When you request a fresh
access_token, always use the refresh token returned in the most recent token_endpoint response. Your
previous refresh tokens expire 24 hours after you receive a new one.

```javascript
oauthClient
  .refresh()
  .then(function (authResponse) {
    console.log('Tokens refreshed : ' + JSON.stringify(authResponse.getToken()));
  })
  .catch(function (e) {
    console.error('The error message is :' + e.originalMessage);
    console.error(e.intuit_tid);
  });
```

### Refresh access_token by passing the refresh_token explicitly

You can call the below helper method to refresh tokens by explictly passing the refresh_token.  
\*\*Note : `refresh_token` should be of the type `string`

```javascript
oauthClient
  .refreshUsingToken('<Enter the refresh token>')
  .then(function (authResponse) {
    console.log('Tokens refreshed : ' + JSON.stringify(authResponse.getToken()));
  })
  .catch(function (e) {
    console.error('The error message is :' + e.originalMessage);
    console.error(e.intuit_tid);
  });
```

### Revoke access_token

When you no longer need the access_token, you could use the below helper method to revoke the
tokens.

```javascript
oauthClient
  .revoke()
  .then(function (authResponse) {
    console.log('Tokens revoked : ' + JSON.stringify(authResponse.json));
  })
  .catch(function (e) {
    console.error('The error message is :' + e.originalMessage);
    console.error(e.intuit_tid);
  });
```

Alternatively you can also pass `access_token` or `refresh_token` to this helper method using the
`params` object: refer to - [Getter / Setter for Token](#getter--setter-for-token) section to know
how to retrieve the `token` object

```javascript
oauthClient
  .revoke(params)
  .then(function (authResponse) {
    console.log('Tokens revoked : ' + JSON.stringify(authResponse.json));
  })
  .catch(function (e) {
    console.error('The error message is :' + e.originalMessage);
    console.error(e.intuit_tid);
  });
```

** Note ** : `params` is the Token JSON object as shown below : ( _If you do not pass the `params`
then the token object of the client would be considered._)

```
{
    "token_type": "bearer",
    "expires_in": 3600,
    "refresh_token":"<refresh_token>",
    "x_refresh_token_expires_in":15552000,
    "access_token":"<access_token>",
    "createdAt": "(Optional Default = Date.now()) <Milliseconds> from the unix epoch"

}
```

** Note ** :

### Getter / Setter for Token

You can call the below methods to set and get the tokens using the `oauthClient` instance:

#### Retrieve the Token :

```javascript
// To get the tokens
let authToken = oauthClient.getToken().getToken();

`OR`;

let authToken = oauthClient.token.getToken();
```

#### Set the Token :

```javascript
// To Set the retrieved tokens explicitly using Token Object but the same instance
oauthClient.setToken(authToken);

OR;

// To set the retrieved tokens using a new client instance
const oauthClient = new OAuthClient({
  clientId: '<Enter your clientId>',
  clientSecret: '<Enter your clientSecret>',
  environment: 'sandbox',
  redirectUri: '<http://localhost:8000/callback>',
  token: authToken,
});
```

The authToken parameters are as follows:

```
{
    token_type: '<String>',
    access_token: '<String>',
    expires_in: '<Int> Seconds',
    refresh_token: '<String>',
    x_refresh_token_expires_in: '<Int>  Seconds',
    id_token: "(Optional Default = '') <String>",
    createdAt: '(Optional Default = Date.now()) <Milliseconds> from the unix epoch'
}
```

**Note** :  
The OAuth Client library converts the accessToken and refreshToken expiry time to `TimeStamp`. If
you are setting a stored token, please pass in the `createdAt` for accurate experiations.

```javascript
oauthClient.setToken(authToken);
```

### Migrate OAuth1.0 Tokens to OAuth2.0

You can call the below method to migrate the bearer / refresh tokens from OAuth1.0 to OAuth2.0. You

```javascript
// Fill in the params object ( argument to the migrate function )

let params = {
  oauth_consumer_key: '<Enter oauth1ConsumerKey>',
  oauth_consumer_secret: '<Enter oauth1ConsumerSecret>',
  oauth_signature_method: 'HMAC-SHA1',
  oauth_timestamp: Math.round(new Date().getTime() / 1000),
  oauth_nonce: 'nonce',
  oauth_version: '1.0',
  access_token: '<Enter OAuth1.0 access_token>',
  access_secret: '<Enter OAuth1.0 access_secret>',
  scope: [OAuthClient.scopes.Accounting],
};

oauthClient
  .migrate(params)
  .then(function (response) {
    console.log('The response is ' + JSON.stringify(response));
  })
  .catch(function (e) {
    console.log('The error is ' + e.message);
  });
```

### Validate ID Token

You can validate the ID token obtained from `Intuit Authorization Server` as shown below :

```javascript
oauthClient
  .validateIdToken()
  .then(function (response) {
    console.log('Is my ID token validated  : ' + response);
  })
  .catch(function (e) {
    console.log('The error is ' + JSON.stringify(e));
  });

// Is my ID token validated : true
```

The client validates the ID Token and returns boolean `true` if validates successfully else it would
throw an exception.

### Make API Call

You can make API call using the token generated from the client as shown below :

```javascript
// Body sample from API explorer examples
const body = {
  TrackQtyOnHand: true,
  Name: 'Garden Supplies',
  QtyOnHand: 10,
  InvStartDate: '2015-01-01',
  Type: 'Inventory',
  IncomeAccountRef: {
    name: 'Sales of Product Income',
    value: '79',
  },
  AssetAccountRef: {
    name: 'Inventory Asset',
    value: '81',
  },
  ExpenseAccountRef: {
    name: 'Cost of Goods Sold',
    value: '80',
  },
};

oauthClient
  .makeApiCall({
    url: 'https://sandbox-quickbooks.api.intuit.com/v3/company/1234/item',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
  .then(function (response) {
    console.log('The API response is  : ' + response);
  })
  .catch(function (e) {
    console.log('The error is ' + JSON.stringify(e));
  });
```


You can also make the calling using the endpoint path:

```javascript
// Body sample from API explorer examples
const body = {
  TrackQtyOnHand: true,
  Name: 'Garden Supplies',
  QtyOnHand: 10,
  InvStartDate: '2015-01-01',
  Type: 'Inventory',
  IncomeAccountRef: {
    name: 'Sales of Product Income',
    value: '79',
  },
  AssetAccountRef: {
    name: 'Inventory Asset',
    value: '81',
  },
  ExpenseAccountRef: {
    name: 'Cost of Goods Sold',
    value: '80',
  },
};

oauthClient
  .makeApiCall({
    url: '/v3/company/1234/item',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
  .then(function (response) {
    console.log('The API response is  : ' + response);
  })
  .catch(function (e) {
    console.log('The error is ' + JSON.stringify(e));
  });
```



The client validates the ID Token and returns boolean `true` if validates successfully else it would
throw an exception.

#### Support for PDF format
In order to save the PDF generated from the APIs properly, the correct transport type should be passed into the `makeAPI()`.Below is an example of the same:
```
.makeApiCall({ url: `${url}v3/company/${companyID}/invoice/${invoiceNumber}/pdf?minorversion=59` , headers:{'Content-Type': 'application/pdf','Accept':'application/pdf'}, transport: popsicle.createTransport({type: 'buffer'})})
```
The response is an actual buffer( binary BLOB) which could then be saved to the file. 

### Auth-Response

The response provided by the client is a wrapped response of the below items which is what we call
authResponse, lets see how it looks like:

```text

    1. response             // response from `HTTP Client` used by library
    2. token                // instance of `Token` Object
    3. body                 // res.body in `text`
    4. json                 // res.body in `JSON`
    5. intuit_tid           // `intuit-tid` from response headers

```

A sample `AuthResponse` object would look similar to :

```json
{
  "token": {
    "realmId": "<realmId>",
    "token_type": "bearer",
    "access_token": "<access_token>",
    "refresh_token": "<refresh_token>",
    "expires_in": 3600,
    "x_refresh_token_expires_in": 8726400,
    "id_token": "<id_token>",
    "latency": 60000
  },
  "response": {
    "url": "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
    "headers": {
      "content-type": "application/json;charset=UTF-8",
      "content-length": "61",
      "connection": "close",
      "server": "nginx",
      "strict-transport-security": "max-age=15552000",
      "intuit_tid": "1234-1234-1234-123",
      "cache-control": "no-cache, no-store",
      "pragma": "no-cache"
    },
    "body": "{\"id_token\":\"<id_token>\",\"expires_in\":3600,\"token_type\":\"bearer\",\"x_refresh_token_expires_in\":8726400,\"refresh_token\":\"<refresh_token>\",\"access_token\":\"<access_token>\"}",
    "status": 200,
    "statusText": "OK"
  },
  "body": "{\"id_token\":\"<id_token>\",\"expires_in\":3600,\"token_type\":\"bearer\",\"x_refresh_token_expires_in\":8726400,\"refresh_token\":\"<refresh_token>\",\"access_token\":\"<access_token>\"}",
  "json": {
    "access_token": "<access_token>",
    "refresh_token": "<refresh_token>",
    "token_type": "bearer",
    "expires_in": "3600",
    "x_refresh_token_expires_in": "8726400",
    "id_token": "<id_token>"
  },
  "intuit_tid": "4245c696-3710-1548-d1e0-d85918e22ebe"
}
```

You can use the below helper methods to make full use of the Auth Response Object :

```javascript
oauthClient.createToken(parseRedirect).then(function (authResponse) {
  console.log('The Token in JSON is  ' + JSON.stringify(authResponse.json));
  let status = authResponse.status();
  let body = authResponse.text();
  let jsonResponse = authResponse.json;
  let intuit_tid = authResponse.get_intuit_tid();
});
```

### Error Logging

By default the logging is `disabled` i.e set to `false`. However, to enable logging, pass
`logging=true` when you create the `oauthClient` instance :

```javascript
const oauthClient = new OAuthClient({
  clientId: '<Enter your clientId>',
  clientSecret: '<Enter your clientSecret>',
  environment: 'sandbox',
  redirectUri: '<http://localhost:8000/callback>',
  logging: true,
});
```

The logs would be captured under the directory `/logs/oAuthClient-log.log`

Whenever there is an error, the library throws an exception and you can use the below helper methods
to retrieve more information :

```javascript
oauthClient.createToken(parseRedirect).catch(function (error) {
  console.log(error);
});

/**
* This is how the Error Object Looks : 
{  
   "originalMessage":"Response has an Error",
   "error":"invalid_grant",
   "error_description":"Token invalid",
   "intuit_tid":"4245c696-3710-1548-d1e0-d85918e22ebe"
}
*/
```

## FAQ

You can refer to our [FAQ](https://github.com/intuit/oauth-jsclient/wiki/FAQ) if you have any
questions.

## Contributing

- You are welcome to send a PR to `develop` branch.
- The `master` branch will always point to the latest published version.
- The `develop` branch will contain the latest development/testing changes.

### Steps

- Fork and clone the repository (`develop` branch).
- Run `npm install` for dependencies.
- Run `npm test` to execute all specs.

## Changelog

See the changelog [here](https://github.com/intuit/oauth-jsclient/blob/master/CHANGELOG.md)

## License

Intuit `oauth-jsclient` is licensed under the
[Apache License, Version 2.0](https://github.com/intuit/oauth-jsclient/blob/master/LICENSE)

[ss1]: https://help.developer.intuit.com/s/SDKFeedback?cid=1120
