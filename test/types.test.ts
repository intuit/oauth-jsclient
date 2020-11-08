'use strict';
import { expect } from 'chai';
import * as OAuthClient from '../src/OAuthClient';

const AuthResponse = require('../src/response/AuthResponse');

describe('OAuthClient type validation tests', () => {
    let oAuthClientConfig;

    beforeEach(() => {
        oAuthClientConfig = {
            clientId: 'clientId',
            clientSecret: 'clientSecret',
            environment: 'sandbox',
            redirectUri: 'http://localhost:8000/callback'
    };
    });

    it('environment should have appropriate fields and types', () => {
        const result = OAuthClient.environment;
        expect(typeof result).to.equal('object');
        expect(result.sandbox).to.equal('https://sandbox-quickbooks.api.intuit.com/');
        expect(result.xyz).to.be.undefined;
    });

    it('scopes should have appropriate fields and types', () => {
        const result = OAuthClient.scopes;
        expect(typeof result).to.equal('object');
        expect(result.Accounting).to.equal('com.intuit.quickbooks.accounting');
        expect(typeof result.Accounting).to.equal('string');
        expect(result.accounting).to.be.undefined;
    });

    it('OAuthClientConfig should have appropriate fields and types', () => {
        expect(typeof oAuthClientConfig.clientId).to.equal('string');
        expect(typeof oAuthClientConfig.clientSecret).to.equal('string');
        expect(typeof oAuthClientConfig.environment).to.equal('string');
        expect(typeof oAuthClientConfig.redirectUri).to.equal('string');
    });

    it('Should create OAuthClient with appropriate fields and types for valid OAuthClientConfig', () => {
        const oAuthClient = new OAuthClient({
            oAuthClientConfig
        });
        expect(typeof oAuthClient).to.equal('object');
        expect(typeof oAuthClient.token).to.equal('object');
        expect(typeof oAuthClient.logging).to.equal('boolean');
        expect(typeof oAuthClient.logger).to.equal('object');
        expect(typeof oAuthClient.state).to.equal('object');
    });

    it('should create new access token instance with appropriate fields and types for valid OAuthClient', () => {
        const oAuthClient = new OAuthClient({
            oAuthClientConfig
        });
        const accessToken = oAuthClient.getToken();
        expect(typeof accessToken).to.equal('object');
        expect(typeof accessToken.realmId).to.equal('string');
        expect(typeof accessToken.token_type).to.equal('string');
        expect(typeof accessToken.refresh_token).to.equal('string');
        expect(typeof accessToken.expires_in).to.equal('number');
        expect(typeof accessToken.x_refresh_token_expires_in).to.equal('number');
        expect(typeof accessToken.id_token).to.equal('string');
        expect(typeof accessToken.latency).to.equal('number');
        expect(typeof accessToken.createdAt).to.equal('number');
    });

    it('should create new auth response instance with appropriate fields and types for valid accessToken', () => {
        const oAuthClient = new OAuthClient({
            oAuthClientConfig
        });
        const accessToken = oAuthClient.getToken();
        const authResponse = new AuthResponse({ token: accessToken });
        expect(typeof authResponse.token).to.equal('object');
        expect(typeof authResponse.response).to.equal('string');
        expect(typeof authResponse.body).to.equal('string');
        expect(typeof authResponse.json).to.equal('object');
        expect(typeof authResponse.intuit_tid).to.equal('string');
    });

    it('Should create OAuthClientError with appropriate fields and types for empty authResponse', () => {
        const oAuthClient = new OAuthClient({
            oAuthClientConfig
        });
        const oAuthClientError = oAuthClient.createError(new Error(), null);
        expect(typeof oAuthClientError.error).to.equal('string');
        expect(typeof oAuthClientError.authResponse).to.equal('string');
        expect(typeof oAuthClientError.intuit_tid).to.equal('string');
        expect(typeof oAuthClientError.originalMessage).to.equal('string');
        expect(typeof oAuthClientError.error_description).to.equal('string');
    });
});
