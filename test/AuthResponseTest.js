'use strict';

// var nock = require('nock');
const {
  describe,
  it,
  xit,
  beforeEach,
  afterEach,
} = require('mocha');
const { expect } = require('chai');
const sinon = require('sinon');

const OAuthClientTest = require('../src/OAuthClient');
const AuthResponse = require('../src/response/AuthResponse');
const expectedAccessToken = require('./mocks/bearer-token.json');
const expectedResponseMock = require('./mocks/response.json');
const expectedPdfResponseMock = require('./mocks/pdfResponse.json');


const oauthClient = new OAuthClientTest({
  clientId: 'clientID',
  clientSecret: 'clientSecret',
  environment: 'sandbox',
  redirectUri: 'http://localhost:8000/callback',
});

oauthClient.getToken().setToken(expectedAccessToken);

describe('Tests for AuthResponse', () => {
  let authResponse;
  let getStub;
  let expectedResponse;

  beforeEach(() => {
    expectedResponse = JSON.parse(JSON.stringify(expectedResponseMock));
    getStub = sinon.stub().returns('application/json;charset=UTF-8');
    expectedResponse.get = getStub;

    authResponse = new AuthResponse({ token: oauthClient.getToken() });
    authResponse.processResponse(expectedResponse);
  });

  afterEach(() => {
    getStub.reset();
  });

  it('Creates a new auth response instance', () => {
    expect(authResponse).to.have.property('token');
    expect(authResponse).to.have.property('response');
    expect(authResponse).to.have.property('body');
    expect(authResponse).to.have.property('json');
    expect(authResponse).to.have.property('intuit_tid');
  });

  it('Process Response', () => {
    authResponse.processResponse(expectedResponse);
    expect(authResponse.response).to.deep.equal(expectedResponse);
    expect(authResponse.intuit_tid).to.deep.equal(expectedResponse.headers.intuit_tid);
  });

  it('Process Get Token', () => {
    const token = authResponse.getToken();
    expect(token).to.have.property('token_type');
    expect(token).to.have.property('refresh_token');
    expect(token).to.have.property('expires_in');
    expect(token).to.have.property('x_refresh_token_expires_in');
  });

  it('Process Text() when there is body ', () => {
    const text = authResponse.body;
    expect(text).to.be.a('string');
    expect(text).to.be.equal('{"id_token":"sample_id_token","expires_in":3600,"token_type":"bearer","x_refresh_token_expires_in":8726400,"refresh_token":"sample_refresh_token","access_token":"sample_access_token"}');
  });

  it('Process Status of AuthResponse', () => {
    const status = authResponse.status();
    expect(status).to.be.equal(200);
  });

  it('Process Headers of AuthResponse', () => {
    const headers = authResponse.headers();
    expect(headers).to.be.equal(expectedResponse.headers);
  });

  it('Process Get Json', () => {
    const json = authResponse.body;
    expect(json).to.be.equal(expectedResponse.body);
  });

  xit('Process Get Json when content type is not correct to throw an error', () => {
    getStub.returns('blah');
    authResponse.processResponse(expectedResponse);
    expect(() => authResponse.getJson()).to.throw(Error);
  });

  it('Process Get Json empty Body', () => {
    delete expectedResponse.body;
    authResponse = new AuthResponse({});
    authResponse.processResponse(expectedResponse);
    expect(authResponse.getJson()).to.be.equal(null);

    // Test putting the body back for branch coverage
    authResponse.body = expectedResponseMock.body;
    const json = authResponse.getJson();
    expect(JSON.stringify(json)).to.be.equal(JSON.stringify(JSON.parse(expectedResponseMock.body)));
  });

  it('GetContentType should handle False', () => {
    getStub.returns(false);
    expectedResponse.headers = getStub;
    // delete expectedResponse.contentType;
    authResponse = new AuthResponse({});
    authResponse.processResponse(expectedResponse);
    expect(authResponse.getContentType()).to.be.equal('');
  });

  it('Process get_intuit_tid', () => {
    const intuitTid = authResponse.getIntuitTid();
    expect(intuitTid).to.be.equal(expectedResponseMock.headers.intuit_tid);
  });

  it('ProcessResponse should handle empty response', () => {
    expect(() => authResponse.processResponse(null)).to.not.throw();
  });
});

describe('Tests for AuthResponse with not json content', () => {
  let authResponse;
  let getStub;
  let expectedResponse;

  beforeEach(() => {
    expectedResponse = JSON.parse(JSON.stringify(expectedPdfResponseMock));
    getStub = sinon.stub().returns('application/pdf');
    expectedResponse.get = getStub;

    authResponse = new AuthResponse({ token: oauthClient.getToken() });
    authResponse.processResponse(expectedResponse);
  });

  afterEach(() => {
    getStub.reset();
  });

  it('Creates a new auth response instance', () => {
    expect(authResponse).to.have.property('token');
    expect(authResponse).to.have.property('response');
    expect(authResponse).to.have.property('body');
    expect(authResponse).to.have.property('json');
    expect(authResponse).to.have.property('intuit_tid');
  });

  it('Process Response', () => {
    authResponse.processResponse(expectedResponse);
    expect(authResponse.response).to.deep.equal(expectedResponse);
  });

  it('Process Get Token', () => {
    const token = authResponse.getToken();
    expect(token).to.have.property('token_type');
    expect(token).to.have.property('refresh_token');
    expect(token).to.have.property('expires_in');
    expect(token).to.have.property('x_refresh_token_expires_in');
  });

  it('Process Text() when there is body ', () => {
    const text = authResponse.text();
    expect(text).to.be.a('string');
    expect(text).to.be.equal('%PDF-1.\ntrailer<</Root<</Pages<</Kids[<</MediaBox[0 0 3 3]>>]>>>>>>');
  });

  it('Process Status of AuthResponse', () => {
    const status = authResponse.status();
    expect(status).to.be.equal(200);
  });

  it('Process Headers of AuthResponse', () => {
    const headers = authResponse.headers();
    expect(headers).to.be.equal(expectedResponse.headers);
  });

  it('Process Get Json to throw an error', () => {
    expect(() => authResponse.getJson()).to.throw(Error);
  });

  it('GetContentType should handle False', () => {
    const contentType = authResponse.getContentType();
	  expect(contentType).to.be.equal('application/pdf');
  });
});

describe('Tests for AuthResponse with Fault Objects', () => {
  let authResponse;
  let getStub;

  beforeEach(() => {
    getStub = sinon.stub().returns('application/json;charset=UTF-8');
    authResponse = new AuthResponse({ token: oauthClient.getToken() });
  });

  afterEach(() => {
    getStub.reset();
  });

  it('should handle response with Fault object and data field', () => {
    const faultResponse = {
      data: {
        Fault: {
          Error: [
            {
              Message: 'Test Fault Error',
              Detail: 'Test fault detail',
              code: '500',
            },
          ],
          type: 'ValidationFault',
        },
        time: '2025-12-15T12:00:00.000Z',
      },
      headers: {
        'content-type': 'application/json',
        intuit_tid: 'fault-tid-123',
      },
      status: 400,
      statusText: 'Bad Request',
      get: getStub,
    };

    authResponse.processResponse(faultResponse);

    expect(authResponse.json).to.have.property('Fault');
    expect(authResponse.json.Fault.type).to.equal('ValidationFault');
    expect(authResponse.json.time).to.equal('2025-12-15T12:00:00.000Z');
    expect(authResponse.intuit_tid).to.equal('fault-tid-123');
  });

  it('should handle response with Fault object without time', () => {
    const faultResponse = {
      data: {
        Fault: {
          Error: [
            {
              Message: 'Test Error',
              Detail: 'Test detail',
              code: '400',
            },
          ],
          type: 'SystemFault',
        },
      },
      headers: {
        'content-type': 'application/json',
        intuit_tid: 'fault-tid-456',
      },
      status: 400,
      statusText: 'Bad Request',
      get: getStub,
    };

    authResponse.processResponse(faultResponse);

    expect(authResponse.json).to.have.property('Fault');
    expect(authResponse.json.Fault.type).to.equal('SystemFault');
    expect(authResponse.json.time).to.be.a('string'); // Should have generated timestamp
    expect(authResponse.intuit_tid).to.equal('fault-tid-456');
  });

  it('should handle response with Fault in body field', () => {
    const faultResponse = {
      body: JSON.stringify({
        Fault: {
          Error: [
            {
              Message: 'Body Fault Error',
              Detail: 'Body fault detail',
              code: '300',
            },
          ],
          type: 'AuthenticationFault',
        },
        time: '2025-12-15T13:00:00.000Z',
      }),
      headers: {
        'content-type': 'application/json',
        intuit_tid: 'body-fault-tid',
      },
      status: 401,
      statusText: 'Unauthorized',
      get: getStub,
    };

    authResponse.processResponse(faultResponse);

    expect(authResponse.json).to.have.property('Fault');
    expect(authResponse.json.Fault.type).to.equal('AuthenticationFault');
    expect(authResponse.json.time).to.equal('2025-12-15T13:00:00.000Z');
    expect(authResponse.intuit_tid).to.equal('body-fault-tid');
  });

  it('should handle response with invalid JSON in body', () => {
    const invalidResponse = {
      body: 'This is not valid JSON {',
      headers: {
        'content-type': 'application/json',
        intuit_tid: 'invalid-json-tid',
      },
      status: 500,
      statusText: 'Internal Server Error',
      get: getStub,
    };

    authResponse.processResponse(invalidResponse);

    expect(authResponse.json).to.be.null;
    expect(authResponse.body).to.equal('This is not valid JSON {');
    expect(authResponse.intuit_tid).to.equal('invalid-json-tid');
  });

  it('should handle response without data or body', () => {
    const emptyResponse = {
      headers: {
        'content-type': 'application/json',
        intuit_tid: 'empty-response-tid',
      },
      status: 204,
      statusText: 'No Content',
      get: getStub,
    };

    authResponse.processResponse(emptyResponse);

    expect(authResponse.body).to.equal('');
    expect(authResponse.json).to.be.null;
    expect(authResponse.intuit_tid).to.equal('empty-response-tid');
  });

  it('should handle getJson with Fault object', () => {
    const faultResponse = {
      body: JSON.stringify({
        Fault: {
          Error: [{ Message: 'Test', Detail: 'Detail', code: '100' }],
          type: 'TestFault',
        },
        time: '2025-12-15T14:00:00.000Z',
      }),
      headers: {
        'content-type': 'application/json',
        intuit_tid: 'getjson-fault-tid',
      },
      status: 400,
      get: getStub,
    };

    authResponse.processResponse(faultResponse);
    const json = authResponse.getJson();

    expect(json).to.have.property('Fault');
    expect(json.Fault.type).to.equal('TestFault');
    expect(json.intuit_tid).to.equal('getjson-fault-tid');
  });
});
