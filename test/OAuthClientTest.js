'use strict';

var nock = require('nock');
var { expect } = require('chai');
// var Response = require('Response');

var OAuthClientTest = require('../src/OAuthClient');
var AuthResponse = require('../src/response/AuthResponse');
var expectedAccessToken = require('./mocks/bearer-token.json');
var expectedTokenResponse = require("./mocks/tokenResponse.json");
var expectedUserInfo = require("./mocks/userInfo.json");
var expectedMakeAPICall = require("./mocks/makeAPICallResponse.json");
var expectedjwkResponseCall = require("./mocks/jwkResponse.json");
var expectedvalidateIdToken = require("./mocks/validateIdToken.json");
var expectedOpenIDToken = require('./mocks/openID-token.json');
var expectedErrorResponse = require('./mocks/errorResponse.json');
var expectedMigrationResponse = require('./mocks/authResponse.json');


var oauthClient = new OAuthClientTest({
    clientId: 'clientID',
    clientSecret: 'clientSecret',
    environment: 'sandbox',
    redirectUri: 'http://localhost:8000/callback'
});


describe('Tests for OAuthClient', function()  {
    var scope;

    it('Creates a new access token instance', function()  {
        var accessToken = oauthClient.getToken();
        expect(accessToken).to.have.property('realmId');
        expect(accessToken).to.have.property('token_type');
        expect(accessToken).to.have.property('refresh_token');
        expect(accessToken).to.have.property('expires_in');
        expect(accessToken).to.have.property('x_refresh_token_expires_in');
        expect(accessToken).to.have.property('id_token');
        expect(accessToken).to.have.property('latency');
    });


    describe('Get the authorizationURI', function() {
        it('When Scope is passed', function() {
            var actualAuthUri = oauthClient.authorizeUri({scope:'testScope',state:'testState'});
            var expectedAuthUri = 'https://appcenter.intuit.com/connect/oauth2?client_id=clientID&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&response_type=code&scope=testScope&state=testState';
            expect(actualAuthUri).to.be.equal(expectedAuthUri);
        });

        it('When NO Scope is passed', function() {
            try {
                oauthClient.authorizeUri();

            } catch (e) {
                expect(e.message).to.equal('Provide the scopes');
            }
        });
        it('When Scope is passed as an array', function() {
            var actualAuthUri = oauthClient.authorizeUri({scope:[OAuthClientTest.scopes.Accounting,OAuthClientTest.scopes.Payment,OAuthClientTest.scopes.OpenId],state:'testState'});
            var expectedAuthUri = 'https://appcenter.intuit.com/connect/oauth2?client_id=clientID&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&response_type=code&scope=com.intuit.quickbooks.accounting%20com.intuit.quickbooks.payment%20openid&state=testState';
            expect(actualAuthUri).to.be.equal(expectedAuthUri);
        });
    });

    // Create bearer tokens
    describe('Create Bearer Token', function() {

        before(function() {

            scope = nock('https://oauth.platform.intuit.com').persist()
                .post('/oauth2/v1/tokens/bearer')
                .reply(200, expectedTokenResponse, {
                    "content-type":"application/json",
                    "content-length":"1636",
                    "connection":"close",
                    "server":"nginx",
                    "intuit_tid":"12345-123-1234-12345",
                    "cache-control":"no-cache, no-store",
                    "pragma":"no-cache"
                });
        });

        it('Provide the uri to get the tokens', function() {
            var parseRedirect = 'http://localhost:8000/callback?state=testState&code=Q011535008931rqveFweqmueq0GlOHhLPAFMp3NI2KJm5gbMMx';
            return oauthClient.createToken(parseRedirect)
                .then(function(authResponse) {
                    expect(authResponse.getToken().access_token).to.be.equal(expectedAccessToken.access_token);
                });
        });

        it('When NO uri is provided', function() {
            return oauthClient.createToken()
                .then(function(authResponse) {
                    expect(authResponse.getToken().access_token).to.be.equal(expectedAccessToken.access_token);
                })
                .catch(function(e) {
                    expect(e.message).to.equal('Provide the Uri');
                });
        });
    });

    // Refresh bearer tokens
    describe('Refresh Bearer Token', function() {
        before(function() {
            var refreshAccessToken = require("./mocks/refreshResponse.json");
            scope = nock('https://oauth.platform.intuit.com').persist()
                .post('/oauth2/v1/tokens/bearer')
                .reply(200,refreshAccessToken , {
                    "content-type":"application/json",
                    "content-length":"1636",
                    "connection":"close",
                    "server":"nginx",
                    "intuit_tid":"12345-123-1234-12345",
                    "cache-control":"no-cache, no-store",
                    "pragma":"no-cache"
                });
        });

        it('Refresh the existing tokens', function() {
            return oauthClient.refresh()
                .then(function(authResponse) {
                    expect(authResponse.getToken().refresh_token).to.be.equal(expectedAccessToken.refresh_token);
                });
        });

        it('Refresh : refresh token is missing', function(){
            oauthClient.getToken().refresh_token = null;
            return oauthClient.refresh()
                .catch(function(e) {
                    expect(e.message).to.equal('The Refresh token is missing');
                });
        });

        it('Refresh : refresh token is invalid', function(){
            oauthClient.getToken().refresh_token = 'sample_refresh_token';
            oauthClient.getToken().x_refresh_token_expires_in = '300';
            return oauthClient.refresh()
                .catch(function(e) {
                    expect(e.message).to.equal('The Refresh token is invalid, please Authorize again.');
                });
        });
    });

    // Revoke bearer tokens
    describe('Revoke Bearer Token', function(){
        before(function()  {
            scope = nock('https://developer.api.intuit.com').persist()
                .post('/v2/oauth2/tokens/revoke')
                .reply(200, '' , {
                    "content-type":"application/json",
                    "content-length":"1636",
                    "connection":"close",
                    "server":"nginx",
                    "intuit_tid":"12345-123-1234-12345",
                    "cache-control":"no-cache, no-store",
                    "pragma":"no-cache"
                });
        });

        it('Revoke the existing tokens', function()  {
            oauthClient.getToken().x_refresh_token_expires_in = '4535995551112';
            return oauthClient.revoke()
                .then(function(authResponse) {
                    expect(authResponse.getToken().refresh_token).to.be.equal(expectedAccessToken.refresh_token);
                });
        });

        it('Revoke : refresh token is missing', function()  {
            oauthClient.getToken().refresh_token = null;
            return oauthClient.revoke()
                .catch(function(e) {
                    expect(e.message).to.equal('The Refresh token is missing');
                });
        });

        it('Revoke : refresh token is invalid', function()  {
            oauthClient.getToken().refresh_token = 'sample_refresh_token';
            oauthClient.getToken().x_refresh_token_expires_in = '300';
            return oauthClient.revoke()
                .catch(function(e) {
                    expect(e.message).to.equal('The Refresh token is invalid, please Authorize again.');
                });
        });
    });

    // Get User Info ( OpenID )
    describe('Get User Info ( OpenID )', function() {
      describe('', function () {
        before(function () {
          scope = nock('https://sandbox-accounts.platform.intuit.com').persist()
            .get('/v1/openid_connect/userinfo')
            .reply(200, expectedUserInfo, {
              "content-type": "application/json",
              "content-length": "1636",
              "connection": "close",
              "server": "nginx",
              "intuit_tid": "12345-123-1234-12345",
              "cache-control": "no-cache, no-store",
              "pragma": "no-cache"
            });
        });

        it('Get User Info in Sandbox', function () {
          return oauthClient.getUserInfo()
            .then(function (authResponse) {
              expect(JSON.stringify(authResponse.getJson())).to.be.equal(JSON.stringify(expectedUserInfo));
            });
        });
      });

      describe('', function () {
        before(function () {
          scope = nock('https://accounts.platform.intuit.com').persist()
            .get('/v1/openid_connect/userinfo')
            .reply(200, expectedUserInfo, {
              "content-type": "application/json",
              "content-length": "1636",
              "connection": "close",
              "server": "nginx",
              "intuit_tid": "12345-123-1234-12345",
              "cache-control": "no-cache, no-store",
              "pragma": "no-cache"
            });
        });

        it('Get User Info in Production', function () {
          oauthClient.environment = 'production';
          return oauthClient.getUserInfo()
            .then(function (authResponse) {
              expect(JSON.stringify(authResponse.getJson())).to.be.equal(JSON.stringify(expectedUserInfo));
            });
        });
      });
    });

    // make API Call
    describe('Make API Call ', function()  {
        describe('', function()  {
            before(function()  {
                scope = nock('https://sandbox-quickbooks.api.intuit.com').persist()
                    .get('/v3/company/12345/companyinfo/12345')
                    .reply(200, expectedMakeAPICall , {
                        "content-type":"application/json",
                        "content-length":"1636",
                        "connection":"close",
                        "server":"nginx",
                        "intuit_tid":"12345-123-1234-12345",
                        "cache-control":"no-cache, no-store",
                        "pragma":"no-cache"
                    });
            });
            it('Make API Call in Sandbox Environment', function()  {
                oauthClient.getToken().realmId = '12345';
                return oauthClient.makeApiCall({url:'https://sandbox-quickbooks.api.intuit.com/v3/company/'+'12345'+'/companyinfo/'+'12345'})
                    .then(function(authResponse) {
                        expect(JSON.stringify(authResponse.getJson())).to.be.equal(JSON.stringify(expectedMakeAPICall));
                    });
            });
        });

        describe('', function()  {
            before(function()  {
                scope = nock('https://quickbooks.api.intuit.com').persist()
                    .get('/v3/company/12345/companyinfo/12345')
                    .reply(200, expectedMakeAPICall , {
                        "content-type":"application/json",
                        "content-length":"1636",
                        "connection":"close",
                        "server":"nginx",
                        "intuit_tid":"12345-123-1234-12345",
                        "cache-control":"no-cache, no-store",
                        "pragma":"no-cache"
                    });
            });
            it('Make API Call in Production Environment', function() {
                oauthClient.environment = 'production';
                oauthClient.getToken().realmId = '12345';
                return oauthClient.makeApiCall({url:'https://quickbooks.api.intuit.com/v3/company/'+'12345'+'/companyinfo/'+'12345'})
                    .then(function(authResponse) {
                        expect(JSON.stringify(authResponse.getJson())).to.be.equal(JSON.stringify(expectedMakeAPICall));
                    });
            });
        });
    });

    // make API Call
    describe('Validate Id Token ', function()  {
        describe('', function()  {
            before(function()  {
                scope = nock('https://oauth.platform.intuit.com').persist()
                    .get('/op/v1/jwks')
                    .reply(200, expectedjwkResponseCall , {
                        "content-type":"application/json;charset=UTF-8",
                        "content-length":"264",
                        "connection":"close",
                        "server":"nginx",
                        "strict-transport-security":"max-age=15552000",
                        "intuit_tid":"1234-1234-1234-123",
                        "cache-control":"no-cache, no-store",
                        "pragma":"no-cache"
                    });
            });

            it('Validate Id Token', function()  {
                oauthClient.getToken().setToken(expectedOpenIDToken);
                oauthClient.validateIdToken()
                    .then(function(response) {
                        expect(response).to.be.equal(expectedvalidateIdToken);
                    });
            });

        });
    });

    // Check Access Token Validity
    describe('Check Access-Token Validity', function()  {
        it('access-token is valid', function()  {
            var validity = oauthClient.isAccessTokenValid();
            expect(validity).to.be.true;
        });
        it('access-token is not valid', function()  {
            oauthClient.getToken().expires_in = null;
            var validity = oauthClient.isAccessTokenValid();
            expect(validity).to.be.false;
        });
    });

    // Get Token
    describe('Get Token', function()  {
        it('get token instance', function()  {
            var token = oauthClient.getToken();
            expect(token).to.be.a('Object');
        });
        it('accesstoken is not valid', function()  {
            oauthClient.getToken().expires_in = null;
            var validity = oauthClient.isAccessTokenValid();
            expect(validity).to.be.false;
        });
    });

    // Get Auth Header
    describe('Get Auth Header', function()  {
        it('Auth Header is valid', function()  {
            var authHeader = oauthClient.authHeader();
            expect(authHeader).to.be.equal('Y2xpZW50SUQ6Y2xpZW50U2VjcmV0');
        });
        it('accesstoken is not valid', function()  {
            oauthClient.getToken().expires_in = null;
            var validity = oauthClient.isAccessTokenValid();
            expect(validity).to.be.false;
        });
    });

    // Generate OAuth1Sign

    describe('Generate OAuth1Sign', function()  {
        it('Generate OAuth1Sign String', function()  {
            var params = {
                method: 'POST',
                uri: 'uri',
                oauth_consumer_key : 'qyprdFsHNQtdRupMKmYnDt6MOjWBW9',
                oauth_consumer_secret : 'TOI5I5dK94dkqDy9SlRD7s08uQUvtow6CK53SpJ1',
                oauth_signature_method : 'HMAC-SHA1',
                oauth_timestamp : 'timestamp',
                oauth_nonce : 'nonce',
                oauth_version : '1.0',
                access_token : 'qyprdlGm45UFPPhwAM59Awaq4BAd6hNFwp1SSkZDn54Zrgv9',
                access_secret : 'xPZ44ZvT17H56pkAAqhfyjuZlF5zZb2k9ej3ohko'
            }

            var oauth1Sign = oauthClient.generateOauth1Sign(params);
            expect(oauth1Sign).to.be.a('String');
        });
    });

    // Migrate Tokens
    describe('Migrate OAuth Tokens', function()  {
        describe('Sandbox', function() {
            before(function()  {
                scope = nock('https://developer.api.intuit.com').persist()
                    .post('/v2/oauth2/tokens/migrate')
                    .reply(200, expectedMigrationResponse , {
                        "content-type":"application/json;charset=UTF-8",
                        "content-length":"264",
                        "connection":"close",
                        "server":"nginx",
                        "strict-transport-security":"max-age=15552000",
                        "intuit_tid":"1234-1234-1234-123",
                        "cache-control":"no-cache, no-store",
                        "pragma":"no-cache"
                    });
            });

            it('Migrate OAuth Tokens - Sandbox', function() {

                var timestamp = Math.round(new Date().getTime()/1000);

                var params = {
                    oauth_consumer_key : 'oauth_consumer_key',
                    oauth_consumer_secret : 'oauth_consumer_secret',
                    oauth_signature_method : 'HMAC-SHA1',
                    oauth_timestamp : timestamp,
                    oauth_nonce : 'nonce',
                    oauth_version : '1.0',
                    access_token : 'sample_access_token',
                    access_secret : 'sample_access_secret',
                    scope : ['com.intuit.quickbooks.accounting']
                }
                oauthClient.migrate(params)
                    .then(function(response){
                        expect(response).to.be.equal(expectedMigrationResponse);
                    });
            });

        });

    });



});