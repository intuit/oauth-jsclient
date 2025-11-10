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
  // Trim all input values to prevent whitespace issues
  const clientId = (req.query.json.clientId || '').trim();
  const clientSecret = (req.query.json.clientSecret || '').trim();
  const environment = (req.query.json.environment || '').trim();
  const redirectUri = (req.query.json.redirectUri || '').trim();

  // Validate inputs
  if (!clientId || !clientSecret || !environment || !redirectUri) {
    return res.status(400).send('Missing required parameters');
  }

  console.log('\n=== Creating OAuth Client ===');
  console.log('Client ID:', clientId.substring(0, 10) + '...');
  console.log('Environment:', environment);
  console.log('Redirect URI:', redirectUri);
  console.log('=============================\n');

  oauthClient = new OAuthClient({
    clientId,
    clientSecret,
    environment,
    redirectUri,
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
  console.log('\n=== OAuth Callback Received ===');
  console.log('Full callback URL:', req.url);
  console.log('Query params:', req.query);
  console.log('===============================\n');

  oauthClient
    .createToken(req.url)
    .then(function (authResponse) {
      oauth2_token_json = JSON.stringify(authResponse.json, null, 2);
      console.log('✅ Token creation successful!');
      console.log('Token details:', {
        has_access_token: !!authResponse.json.access_token,
        has_refresh_token: !!authResponse.json.refresh_token,
        realmId: authResponse.json.realmId,
      });
    })
    .catch(function (e) {
      console.error('\n❌ Token creation failed!');
      console.error('Error:', e.error || e.message);
      console.error('Error description:', e.error_description);
      console.error('Intuit TID:', e.intuit_tid);
      console.error('Full error:', e);
      console.error('\nPossible causes:');
      console.error('1. Authorization code already used (codes are single-use)');
      console.error('2. Redirect URI mismatch');
      console.error('3. Invalid client credentials');
      console.error('4. Authorization code expired (10 minute limit)');
      console.error('\nSolution: Try authorizing again with "Connect to QuickBooks"\n');
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
  // Validate that we have a valid oauth client and tokens
  if (!oauthClient) {
    return res.status(400).json({
      error: true,
      message: 'OAuth client not initialized. Please connect to QuickBooks first.',
    });
  }

  const token = oauthClient.getToken();
  
  // Check if we have a valid access token
  if (!token.access_token) {
    return res.status(401).json({
      error: true,
      message: 'No access token available. Please connect to QuickBooks first.',
      hint: 'Click "Connect to QuickBooks" button and complete authorization.',
    });
  }

  // Check if access token is still valid
  if (!oauthClient.isAccessTokenValid()) {
    return res.status(401).json({
      error: true,
      message: 'Access token has expired. Please refresh the token or reconnect.',
      hint: 'Click "Refresh Token" button to get a new access token.',
    });
  }

  const companyID = token.realmId;

  if (!companyID) {
    return res.status(400).json({
      error: true,
      message: 'No company ID (realmId) available.',
    });
  }

  const url =
    oauthClient.environment == 'sandbox'
      ? OAuthClient.environment.sandbox
      : OAuthClient.environment.production;

  console.log(`\n=== Making API Call ===`);
  console.log(`Company ID: ${companyID}`);
  console.log(`Environment: ${oauthClient.environment}`);
  console.log(`URL: ${url}v3/company/${companyID}/companyinfo/${companyID}`);
  console.log(`Access Token Length: ${token.access_token.length}`);
  console.log('======================\n');

  oauthClient
    .makeApiCall({ url: `${url}v3/company/${companyID}/companyinfo/${companyID}` })
    .then(function (authResponse) {
      const resp = authResponse.json ? authResponse.json : authResponse.data;
      console.log(`\n The response for API call is :${JSON.stringify(resp)}`);
      res.send(resp);
    })
    .catch(function (e) {
      // Check if it's an OAuthError with detailed information
      console.error('\n=== API Call Error ===');
      console.error('Error Name:', e.name);
      console.error('Error Message:', e.message);
      
      if (e.code) {
        console.error('Error Code:', e.code);
      }
      
      if (e.description) {
        console.error('Error Description:', e.description);
      }
      
      if (e.intuitTid) {
        console.error('Intuit Transaction ID:', e.intuitTid);
      }

      // Detailed error analysis
      const errorAnalysis = {
        // Basic error properties
        basic: {
          name: e.name,
          message: e.message,
          stack: e.stack,
          code: e.code,
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
              additionalInfo: err.additionalInfo,
            })) : null,
            timestamp: e.response.data.time,
          } : null),
          // OAuth error fields
          oauth: {
            error: e.response.data && e.response.data.error,
            error_description: e.response.data && e.response.data.error_description,
          },
        } : null,
        // Request analysis
        request: e.request ? {
          method: e.request.method,
          path: e.request.path,
          headers: e.request.headers,
        } : null,
      };

      // Log the detailed error analysis
      console.error('Exception Analysis:', {
        hasFaultObject: !!(e.response && e.response.data && e.response.data.Fault),
        faultType: e.response && e.response.data && e.response.data.Fault && e.response.data.Fault.type,
        faultErrors: e.response && e.response.data && e.response.data.Fault && e.response.data.Fault.Error,
        fullAnalysis: errorAnalysis,
      });
      
      console.error('======================\n');

      // Send error response to client with more detail
      const status = e.response ? e.response.status : 500;
      const errorResponse = {
        error: true,
        message: e.message,
        code: e.code,
        description: e.description,
        intuitTid: e.intuitTid,
        fault: e.response && e.response.data && e.response.data.Fault ? {
          type: e.response.data.Fault.type,
          errors: e.response.data.Fault.Error,
        } : null,
      };
      
      res.status(status).json(errorResponse);
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
