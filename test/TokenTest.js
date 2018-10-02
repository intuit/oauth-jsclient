'use strict';

var { expect } = require('chai');

var OAuthClientTest = require('../src/OAuthClient');
var expectedAccessToken = require('./mocks/bearer-token.json');



var oauthClient = new OAuthClientTest({
    clientId: 'clientID',
    clientSecret: 'clientSecret',
    environment: 'sandbox',
    redirectUri: 'http://localhost:8000/callback'
});

describe('Tests for Token', function() {

    it('Creates a new token instance', function() {

        var token = oauthClient.getToken();
        expect(token).to.have.property('realmId');
        expect(token).to.have.property('token_type');
        expect(token).to.have.property('access_token');
        expect(token).to.have.property('refresh_token');
        expect(token).to.have.property('expires_in');
        expect(token).to.have.property('x_refresh_token_expires_in');
        expect(token).to.have.property('latency');
        expect(token).to.have.property('id_token');
    });

    it('Get Access Token using Helper Method', function() {

        oauthClient.token.setToken(expectedAccessToken);
        var access_token = oauthClient.getToken().accessToken();

        expect(access_token).to.deep.equal(expectedAccessToken.access_token);
    });


    it('Get Refresh Token using Helper Method', function() {

        oauthClient.token.setToken(expectedAccessToken);
        var refresh_token = oauthClient.getToken().refreshToken();

        expect(refresh_token).to.deep.equal(expectedAccessToken.refresh_token);
    });

    it('Get TokenType using Helper Method', function() {

        oauthClient.token.setToken(expectedAccessToken);
        var token_type = oauthClient.getToken().tokenType();

        expect(token_type).to.deep.equal(expectedAccessToken.token_type);
    });

    it('Get Token  using Helper Method', function() {

        oauthClient.token.setToken(expectedAccessToken);
        var token = oauthClient.getToken().getToken()

        expect(token).to.be.a('Object');
        expect(token.access_token).to.deep.equal('sample_access_token');
    });

});


