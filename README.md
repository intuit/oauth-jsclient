[![SDK Banner](views/SDK.png)][ss1]


[![Build Status](https://travis-ci.org/intuit/oauth-jsclient.svg?branch=master)](https://travis-ci.org/intuit/oauth-jsclient)
[![NPM Package Version](https://img.shields.io/npm/v/intuit-oauth.svg?style=flat-square)](https://www.npmjs.com/package/intuit-oauth)

# Intuit OAuth2.0 NodeJS Library 

The OAuth2 Nodejs Client library is meant to work with Intuit's [OAuth2.0](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0) and [OpenID Connect](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/openid-connect) implementations which conforms to the specifications.


## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
  - [Using NodeJS](#using-nodejs)
- [Usage](#usage)
  - [Authorization Code flow](#authorization-code-flow)
- [Sample](#sample)  
- [Helpers](#helpers)  
  - [Is Access Token valid](#is-accesstoken-valid)
  - [Refresh Access_Token](#refresh-access_token)
  - [Refresh Access_Token by passing the refresh_token explicitly](#refresh-access_token_explicitly)
  - [Auto Refresh](#auto-refresh)
  - [Revoke Access Token](#revoke-access_token)
  - [Getter / Setter for Token](#getter-/-setter-for-token )
  - [Auth Response](#auth-response) 
  - [Error Logging](#error-logging)
- [Contributing](#contributing)
- [Authors](#authors)
  - [Contributors](#contributors)
- [Changelog](#changelog)
- [License](#license)


# Requirements

The Node.js client library is tested against the `Node`  >= `6.0.0`

# Installation

Follow the instructions below to use the library : 

## Using NodeJS

1. Install the NPM package:

    ```sh
    npm install intuit-oauth --save
    ```

2. Require the Library:

    ```js
    var OAuthClient = require('intuit-oauth');

    var oauthClient = new OAuthClient({
        clientId: '<Enter your clientId>',
        clientSecret: '<Enter your clientSecret>',
        environment: 'sandbox' || 'production',
        redirectUri: '<Enter your callback URL>'
    });
    ```

### Options :

* `clientId` - clientID for your app. Required
* `clientSecret` - clientSecret fpor your app. Required
* `environment` - environment for the client. Required
    * `sandbox` - for authorizing in sandbox.
    * `production` -  for authorizing in production.
* `redirectUri` - redirectUri on your app to get the `authorizationCode` from Intuit Servers. Required    
* `logging` - by default, logging is disabled i.e `false`. To enable provide`true`.

 

# Usage

We assume that you have a basic understanding about OAuth2.0. If not please read [API Documentation](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0) for clear understanding

## Authorization Code Flow 

The Authorization Code flow is made up of two parts :   
 
**Step 1.** Redirect user to `oauthClient.authorizeUri(options)`.  
**Step 2.** Parse response uri and get access-token using the function `oauthClient.createToken(req.url)` which returns a [Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise).


### Step 1
```javascript

// Instance of client
var oauthClient = new OAuthClient({
    clientId: '<Enter your clientId>',
    clientSecret: '<Enter your clientSecret>',
    environment: 'sandbox',
    redirectUri: '<http://localhost:8000/callback>'
});

// AuthorizationUri
var authUri = oauthClient.authorizeUri({scope:[OAuthClient.scopes.Accounting,OAuthClient.scopes.OpenId],state:'testState'});  // can be an array of multiple scopes ex : {scope:[OAuthClient.scopes.Accounting,OAuthClient.scopes.OpenId]}


// Redirect the authUri 
res.redirect(authUri);

```
### Scopes :

The available scopes include :

* `com.intuit.quickbooks.accounting` - for accounting scope include `OAuthClient.scopes.Accounting`  
* `com.intuit.quickbooks.payment` - for payment scope include `OAuthClient.scopes.Payment` 

OpenID Scopes :

* `openid` - for openID assertion include `OAuthClient.scopes.Openid`
* `profile` - for profile assertion include `OAuthClient.scopes.Profile`  
* `email` - for email assertion include `OAuthClient.scopes.Email`
* `phone` - for phone assertion include `OAuthClient.scopes.Phone`
* `address` - for address assertion include `OAuthClient.scopes.Address`



### Step 2
```javascript

// Parse the redirect URL for authCode and exchange them for tokens
var parseRedirect = req.url;

// Exchange the auth code retrieved from the **req.url** on the redirectUri
oauthClient.createToken(parseRedirect)
    .then(function(authResponse) {
        console.log('The Token is  '+ JSON.stringify(authResponse.getJson()));
    })
    .catch(function(e) {
        console.error("The error message is :"+e.originalMessage);
        console.error(e.intuit_tid);
    });

```

# Sample
For more clarity, we suggest you take a look at the sample application below :  
[sample](https://github.com/intuit/oauth-jsclient/tree/master/sample)


## Helpers

### Is AccessToken Valid

You can check if the `access_token` associated with the `oauthClient` is valid ( not expired ) or not using the helper method. 

```javascript

if(oauthClient.isAccessTokenValid()) {
    console.log("The access_token is valid");
} 

if(!oauthClient.isAccessTokenValid()){
    
    oauthClient.refresh()
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error("The error message is :"+e.originalMessage);
            console.error(e.intuit_tid);
        });
    
}

```
** Note: If the access_token is not valid, you can call the client's `refresh()` method to refresh the tokens for you as shown below


### Refresh access_token

Access tokens are valid for 3600 seconds (one hour), after which time you need to get a fresh one using the latest refresh_token returned to you from the previous request. When you request a fresh access_token, always use the refresh token returned in the most recent token_endpoint response. Your previous refresh tokens expire 24 hours after you receive a new one. 

```javascript

    oauthClient.refresh()
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error("The error message is :"+e.originalMessage);
            console.error(e.intuit_tid);
        });
```

### Refresh access_token by passing the refresh_token explicitly 

You can call the below helper method to refresh tokens by explictly passing the refresh_token.  
**Note : `refresh_token` should be of the type `string`     

```javascript

    oauthClient.refreshUsingToken('<Enter the refresh token>')
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error("The error message is :"+e.originalMessage);
            console.error(e.intuit_tid);
        });
```


### Revoke access_token

When you no longer need the access_token, you could use the below helper method to revoke the tokens. You can also optionally pass the `access_token` or `refresh_token` to this helper method : 

```javascript

oauthClient.revoke(params)
        .then(function(authResponse) {
            console.log('Tokens revoked : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error("The error message is :"+e.originalMessage);
            console.error(e.intuit_tid);
        });
```
** Note ** : `params` is the Token JSON object as shown below :  

```
{
    "token_type": "bearer",
    "expires_in": 3600,
    "refresh_token":"<refresh_token>",
    "x_refresh_token_expires_in":15552000,
    "access_token":"<access_token>"
} 
``` 
** Note ** : If you do not pass the `params` then the token object of the client would be considered.   

### Getter / Setter for Token 

You can call the below methods to set and get the tokens using the `oauthClient` instance:


#### Retrieve the Token :

```javascript
// To get the tokens 
var authToken = oauthClient.getToken().getToken();

`OR`

var authToken = oauthClient.token.getToken();

```

#### Set the Token : 
```javascript

// To Set the retrieved tokens explicitly using Token Object but the same instance
oauthClient.setToken(authToken);        


OR 

// To set the retrieved tokens using a new client instance    
var oauthClient = new OAuthClient({
    clientId: '<Enter your clientId>',
    clientSecret: '<Enter your clientSecret>',
    environment: 'sandbox',
    redirectUri: '<http://localhost:8000/callback>',
    token: authToken
});

```
**Note** :   

The OAuth Client library converts the accessToken and refreshToken expiry time to `TimeStamp` for better maintainability as shown below :   

    this.expires_in = Date.now() + (tokenData.expires_in * 1000);
    this.x_refresh_token_expires_in = Date.now() + (tokenData.x_refresh_token_expires_in * 1000);
    
so if you're providing the token that was returned from `createToken` or `refresh` then be sure you set the token as shown above or refer below :

```javascript
oauthClient.setToken(authToken);
```
   

### Migrate OAuth1.0 Tokens to OAuth2.0  

You can call the below method to migrate the bearer / refresh tokens from OAuth1.0 to OAuth2.0. You  

```javascript

// Fill in the params object ( argument to the migrate function )

var params = {
    oauth_consumer_key : '<Enter oauth1ConsumerKey>',
    oauth_consumer_secret : '<Enter oauth1ConsumerSecret>',
    oauth_signature_method : 'HMAC-SHA1',
    oauth_timestamp : Math.round(new Date().getTime()/1000),
    oauth_nonce : 'nonce',
    oauth_version : '1.0',
    access_token : '<Enter OAuth1.0 access_token>',
    access_secret : '<Enter OAuth1.0 access_secret>',
    scope : [OAuthClient.scopes.Accounting]
}

oauthClient.migrate(params)
    .then(function(response){
        console.log('The response is '+ JSON.stringify(response));
    })
    .catch(function(e) {
        console.log('The error is '+e.message);
    });

```

### Validate ID Token 

You can validate the ID token obtained from `Intuit Authorization Server` as shown below : 

```javascript

 oauthClient.validateIdToken()
        .then(function(response){
            console.log('Is my ID token validated  : ' + response);
        })
        .catch(function(e) {
            console.log('The error is '+ JSON.stringify(e));
        });

        // Is my ID token validated : true
```

The client validates the ID Token and returns boolean `true` if validates successfully else it would throw an exception. 



### Auth-Response 

The response provided by the client is a wrapped response of the below items which is what we call authResponse, lets see how it looks like:

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
      "token":{  
         "realmId":"<realmId>",
         "token_type":"bearer",
         "access_token":"<access_token>",
         "refresh_token":"<refresh_token>",
         "expires_in":3600,
         "x_refresh_token_expires_in":8726400,
         "id_token":"<id_token>",
         "latency":60000
      },
      "response":{  
         "url":"https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
         "headers":{  
            "content-type":"application/json;charset=UTF-8",
            "content-length":"61",
            "connection":"close",
            "server":"nginx",
            "strict-transport-security":"max-age=15552000",
            "intuit_tid":"1234-1234-1234-123",
            "cache-control":"no-cache, no-store",
            "pragma":"no-cache"
         },
         "body":"{\"id_token\":\"<id_token>\",\"expires_in\":3600,\"token_type\":\"bearer\",\"x_refresh_token_expires_in\":8726400,\"refresh_token\":\"<refresh_token>\",\"access_token\":\"<access_token>\"}",
         "status":200,
         "statusText":"OK"
      },
      "body":"{\"id_token\":\"<id_token>\",\"expires_in\":3600,\"token_type\":\"bearer\",\"x_refresh_token_expires_in\":8726400,\"refresh_token\":\"<refresh_token>\",\"access_token\":\"<access_token>\"}",
      "json":{
        "access_token": "<access_token>",
        "refresh_token": "<refresh_token>",
        "token_type": "bearer",
        "expires_in": "3600",
        "x_refresh_token_expires_in": "8726400",
        "id_token": "<id_token>"
      },
      "intuit_tid":"4245c696-3710-1548-d1e0-d85918e22ebe"
}

```
You can use the below helper methods to make full use of the Auth Response Object :

```javascript
oauthClient.createToken(parseRedirect)
    .then(function(authResponse) {
        console.log('The Token in JSON is  '+ JSON.stringify(authResponse.getJson()));
        var status = authResponse.status();
        var body = authResponse.text();
        var jsonResponse = authResponse.getJson();
        var intuit_tid = authResponse.get_intuit_tid();
    });

```




### Error Logging

By default the logging is `disabled` i.e set to `false`. However, to enable logging, pass `logging=true` when you create the `oauthClient` instance :

```javascript
var oauthClient = new OAuthClient({
    clientId: '<Enter your clientId>',
    clientSecret: '<Enter your clientSecret>',
    environment: 'sandbox',
    redirectUri: '<http://localhost:8000/callback>',
    logging: true
});

```
The logs would be captured under the directory `/logs/oAuthClient-log.log`  

Whenever there is an error, the library throws an exception and you can use the below helper methods to retrieve more information :

```javascript

oauthClient.createToken(parseRedirect)
        .catch(function(error) {
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

You can refer to our [FAQ](https://github.com/intuit/oauth-jsclient/wiki/FAQ) if you have any questions.

## Contributing

* You are welcome to send a PR to `develop` branch.
* The `master` branch will always point to the latest published version.
* The `develop` branch will contain the latest development/testing changes.

### Steps

* Fork and clone the repository (`develop` branch).
* Run `npm install` for dependencies.
* Run `npm test` to execute all specs.


## License

Intuit `oauth-jsclient` is licensed under the [Apache License, Version 2.0](https://github.com/intuit/oauth-jsclient/blob/master/LICENSE)

[ss1]: https://help.developer.intuit.com/s/SDKFeedback?cid=1120



