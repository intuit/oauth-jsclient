'use strict';

var nock = require('nock');
var { expect } = require('chai');

var OAuthClientTest = require('../src/OAuthClient');
var AuthResponse = require('../src/response/AuthResponse');
var expectedAccessToken = require('./mocks/bearer-token.json');
var expectedTokenResponse = require("./mocks/tokenResponse.json");
var expectedUserInfo = require("./mocks/userInfo.json");
var expectedMakeAPICall = require("./mocks/makeAPICallResponse.json");
var expectedResponse = require("./mocks/response.json");
var expectedAuthResponse = require("./mocks/authResponse.json");


var oauthClient = new OAuthClientTest({
    clientId: 'clientID',
    clientSecret: 'clientSecret',
    environment: 'sandbox',
    redirectUri: 'http://localhost:8000/callback'
});

oauthClient.getToken().setToken(expectedAccessToken);
var authResponse = new AuthResponse({token:oauthClient.getToken()});
authResponse.processResponse(expectedResponse);

describe('Tests for AuthResponse', function() {
    var scope;
    var result;

    it('Creates a new auth response instance', () => {
        expect(authResponse).to.have.property('token');
        expect(authResponse).to.have.property('response');
        expect(authResponse).to.have.property('body');
        expect(authResponse).to.have.property('json');
        expect(authResponse).to.have.property('intuit_tid');
    });

    it('Process Response', function() {
        authResponse.processResponse(expectedResponse);
        expect(authResponse.response).to.deep.equal(expectedResponse);
        expect(authResponse.intuit_tid).to.deep.equal(expectedResponse.headers.intuit_tid);
    });

    it('Process Get Token', function() {
        var token = authResponse.getToken();
        expect(token).to.have.property('token_type');
        expect(token).to.have.property('refresh_token');
        expect(token).to.have.property('expires_in');
        expect(token).to.have.property('x_refresh_token_expires_in');
    });

    it('Process Text() when there is body ', function() {
        var text = authResponse.text();
        expect(text).to.be.a('string');
        expect(text).to.be.equal('{"id_token":"sample_id_token","expires_in":3600,"token_type":"bearer","x_refresh_token_expires_in":8726400,"refresh_token":"sample_refresh_token","access_token":"sample_access_token"}');
    });

    it('Process Status of AuthResponse', function() {
       var status = authResponse.status();
        expect(status).to.be.equal(200);
    });
});


