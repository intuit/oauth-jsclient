/* eslint-disable camelcase */

'use strict';

const { describe, it } = require('mocha');
const { expect } = require('chai');

const OAuthClientTest = require('../src/OAuthClient');
const expectedAccessToken = require('./mocks/bearer-token.json');


let oauthClient = new OAuthClientTest({
  clientId: 'clientID',
  clientSecret: 'clientSecret',
  environment: 'sandbox',
  redirectUri: 'http://localhost:8000/callback',
});

describe('Tests for Token', () => {
  it('Creates a new token instance', () => {
    const token = oauthClient.getToken();
    expect(token).to.have.property('realmId');
    expect(token).to.have.property('token_type');
    expect(token).to.have.property('access_token');
    expect(token).to.have.property('refresh_token');
    expect(token).to.have.property('expires_in');
    expect(token).to.have.property('x_refresh_token_expires_in');
    expect(token).to.have.property('latency');
    expect(token).to.have.property('id_token');
  });

  it('Set Token using Constructor', () => {
    oauthClient = new OAuthClientTest({
      clientId: 'clientID',
      clientSecret: 'clientSecret',
      environment: 'sandbox',
      redirectUri: 'http://localhost:8000/callback',
      token: expectedAccessToken,
    });
    const token = oauthClient.getToken();

    expect(token.access_token).to.equal(expectedAccessToken.access_token);
    expect(token.refresh_token).to.equal(expectedAccessToken.refresh_token);
    expect(token.token_type).to.equal(expectedAccessToken.token_type);
    expect(token.expires_in).to.equal(expectedAccessToken.expires_in);
    expect(token.x_refresh_token_expires_in)
      .to.equal(expectedAccessToken.x_refresh_token_expires_in);
  });

  it('Set Token using Helper Method', () => {
    oauthClient.token.setToken(expectedAccessToken);
    const token = oauthClient.getToken();

    expect(token.access_token).to.equal(expectedAccessToken.access_token);
    expect(token.refresh_token).to.equal(expectedAccessToken.refresh_token);
    expect(token.token_type).to.equal(expectedAccessToken.token_type);
    expect(token.expires_in).to.equal(expectedAccessToken.expires_in);
    expect(token.x_refresh_token_expires_in)
      .to.equal(expectedAccessToken.x_refresh_token_expires_in);
  });

  it('Get Access Token using Helper Method', () => {
    oauthClient.token.setToken(expectedAccessToken);
    const accessToken = oauthClient.getToken().accessToken();

    expect(accessToken).to.deep.equal(expectedAccessToken.access_token);
  });


  it('Get Refresh Token using Helper Method', () => {
    oauthClient.token.setToken(expectedAccessToken);
    const refreshToken = oauthClient.getToken().refreshToken();

    expect(refreshToken).to.deep.equal(expectedAccessToken.refresh_token);
  });

  it('Get TokenType using Helper Method', () => {
    oauthClient.token.setToken(expectedAccessToken);
    const tokenType = oauthClient.getToken().tokenType();

    expect(tokenType).to.deep.equal(expectedAccessToken.token_type);
  });

  it('Get Token using Helper Method', () => {
    oauthClient.token.setToken(expectedAccessToken);
    const token = oauthClient.getToken().getToken();

    expect(token).to.be.a('Object');
    expect(token.access_token).to.deep.equal('sample_access_token');
  });

  it('Clear Token using Helper Method', () => {
    oauthClient.token.setToken(expectedAccessToken);
    const token = oauthClient.getToken().clearToken();

    expect(token.access_token).to.equal('');
    expect(token.refresh_token).to.equal('');
    expect(token.token_type).to.equal('');
    expect(token.expires_in).to.equal(0);
    expect(token.x_refresh_token_expires_in).to.equal(0);
  });
});
