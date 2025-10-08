'use strict';

require('dotenv').config();

/**
 * Require the dependencies
 * @type {*|createApplication}
 */
const express = require('express');

const app = express();
const path = require('path');
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const ngrok = process.env.NGROK_ENABLED === 'true' ? require('ngrok') : null;

/**
 * Configure View and Handlebars
 */
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '/public')));
app.engine('html', require('ejs').renderFile);

app.set('view engine', 'html');
app.use(bodyParser.json());

const urlencodedParser = bodyParser.urlencoded({ extended: false });

/**
 * App Variables
 * @type {null}
 */
let oauth2_token_json = null;
let redirectUri = '';

/**
 * Instantiate new Client
 * @type {OAuthClient}
 */

let oauthClient = null;

/**
 * Home Route
 */
app.get('/', function (req, res) {
  res.render('index');
});

/**
 * Get the AuthorizeUri
 */
app.get('/authUri', urlencodedParser, function (req, res) {
  oauthClient = new OAuthClient({
    clientId: req.query.json.clientId,
    clientSecret: req.query.json.clientSecret,
    environment: req.query.json.environment,
    redirectUri: req.query.json.redirectUri,
    logging: true,        //NOTE: a "logs" folder will be created/used in the current working directory, this will have oAuthClient-log.log 
  });

  const authUri = oauthClient.authorizeUri({
    scope: [OAuthClient.scopes.Accounting, OAuthClient.scopes.OpenId, OAuthClient.scopes.Profile, OAuthClient.scopes.Email],
    state: 'intuit-test',
  });
  res.send(authUri);
});

/**
 * Handle the callback to extract the `Auth Code` and exchange them for `Bearer-Tokens`
 */
app.get('/callback', function (req, res) {
  oauthClient
    .createToken(req.url)
    .then(function (authResponse) {
      oauth2_token_json = JSON.stringify(authResponse.json, null, 2);
    })
    .catch(function (e) {
      console.error(e);
    });

  res.send('');
});

/**
 * Display the token : CAUTION : JUST for sample purposes
 */
app.get('/retrieveToken', function (req, res) {
  res.send(oauth2_token_json);
});

/**
 * Refresh the access-token
 */
app.get('/refreshAccessToken', function (req, res) {
  oauthClient
    .refresh()
    .then(function (authResponse) {
      console.log(`\n The Refresh Token is  ${JSON.stringify(authResponse.json)}`);
      oauth2_token_json = JSON.stringify(authResponse.json, null, 2);
      res.send(oauth2_token_json);
    })
    .catch(function (e) {
      console.error(e);
    });
});

/**
 * getCompanyInfo ()
 */
app.get('/getCompanyInfo', function (req, res) {
  const companyID = oauthClient.getToken().realmId;

  const url =
    oauthClient.environment == 'sandbox'
      ? OAuthClient.environment.sandbox
      : OAuthClient.environment.production;

  oauthClient
    .makeApiCall({ url: `${url}v3/company/${companyID}/companyinfo/${companyID}` })
    .then(function (authResponse) {
      const resp = authResponse.json ? authResponse.json : authResponse.data;
      console.log(`\n The response for API call is :${JSON.stringify(resp)}`);
      res.send(resp);
    })
    .catch(function (e) {
      // Detailed error analysis
      const errorAnalysis = {
        // Basic error properties
        basic: {
          name: e.name,
          message: e.message,
          stack: e.stack,
          code: e.code
        },
        // Response analysis
        response: e.response ? {
          status: e.response.status,
          statusText: e.response.statusText,
          headers: JSON.stringify(e.response.headers),
          // Deep analysis of response data
          data: JSON.stringify(e.response.data),
          // Specific Fault object analysis
          fault: JSON.stringify(e.response.data && e.response.data.Fault ? {
            type: e.response.data.Fault.type,
            error: e.response.data.Fault.Error ? e.response.data.Fault.Error.map(err => ({
              message: err.Message,
              detail: err.Detail,
              code: err.code,
              element: err.element,
              additionalInfo: err.additionalInfo
            })) : null,
            timestamp: e.response.data.time
          } : null),
          // OAuth error fields
          oauth: {
            error:e.response.data && e.response.data.error,
            error_description: e.response.data && e.response.data.error_description
          }
        } : null,
        // Request analysis
        request: e.request ? {
          method: e.request.method,
          path: e.request.path,
          headers: e.request.headers
        } : null
      };

      // Log the detailed error analysis
      console.error('Exception Analysis:', {
        hasFaultObject: !!(e.response && e.response.data && e.response.data.Fault),
        faultType: e.response && e.response.data && e.response.data.Fault && e.response.data.Fault.type,
        faultErrors: e.response && e.response.data && e.response.data.Fault && e.response.data.Fault.Error,
        fullAnalysis: errorAnalysis
      });

      // Send error response to client
      res.status(e.response ? e.response.status : 500).json({
        error: true,
        message: e.message,
        fault: e.response && e.response.data && e.response.data.Fault ? {
          type: e.response.data.Fault.type,
          errors: e.response.data.Fault.Error
        } : null
      });
    });
});

/**
 * disconnect ()
 */
app.get('/disconnect', function (req, res) {
  console.log('The disconnect called ');
  const authUri = oauthClient.authorizeUri({
    scope: [OAuthClient.scopes.OpenId, OAuthClient.scopes.Email],
    state: 'intuit-test',
  });
  res.redirect(authUri);
});

/**
 * Start server on HTTP (will use ngrok for HTTPS forwarding)
 */
const server = app.listen(process.env.PORT || 8000, () => {
  console.log(`💻 Server listening on port ${server.address().port}`);
  if (!ngrok) {
    redirectUri = `${server.address().port}` + '/callback';
    console.log(
      `💳  Step 1 : Paste this URL in your browser : ` +
        'http://localhost:' +
        `${server.address().port}`,
    );
    console.log(
      '💳  Step 2 : Copy and Paste the clientId and clientSecret from : https://developer.intuit.com',
    );
    console.log(
      `💳  Step 3 : Copy Paste this callback URL into redirectURI :` +
        'http://localhost:' +
        `${server.address().port}` +
        '/callback',
    );
    console.log(
      `💻  Step 4 : Make Sure this redirect URI is also listed under the Redirect URIs on your app in : https://developer.intuit.com`,
    );
  }
});

/**
 * Optional : If NGROK is enabled
 */
if (ngrok) {
  console.log('NGROK Enabled');
  ngrok
    .connect({ addr: process.env.PORT || 8000 })
    .then((url) => {
      redirectUri = `${url}/callback`;
      console.log(`💳 Step 1 : Paste this URL in your browser :  ${url}`);
      console.log(
        '💳 Step 2 : Copy and Paste the clientId and clientSecret from : https://developer.intuit.com',
      );
      console.log(`💳 Step 3 : Copy Paste this callback URL into redirectURI :  ${redirectUri}`);
      console.log(
        `💻 Step 4 : Make Sure this redirect URI is also listed under the Redirect URIs on your app in : https://developer.intuit.com`,
      );
    })
    .catch(() => {
      process.exit(1);
    });
}
