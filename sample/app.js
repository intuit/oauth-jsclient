'use strict';

require('dotenv').config();

/**
 * Require the dependencies
 * @type {*|createApplication}
 */
const express = require('express');
const TokenSaver = require('./TokenSaver')

const app = express();
const path = require('path');
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const ngrok = process.env.NGROK_ENABLED === 'true' ? require('ngrok') : null;
const querystring = require("querystring");
const tokenSaver = new TokenSaver()

/**
 * Configure View and Handlebars
 */
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static(path.join(__dirname, '/public')));
app.engine('html', require('ejs').renderFile);

app.set('view engine', 'html');
app.use(bodyParser.json());

const urlencodedParser = bodyParser.urlencoded({extended: false});

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
let yardId = null;

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

    yardId = req.query.json.yardId
    console.log('yardId is ', yardId)

    //? configure the client with our app creds
    oauthClient = new OAuthClient({
        clientId: process.env.QB_CLIENT_ID,
        clientSecret: process.env.QB_CLIENT_SECRET,
        environment: req.query.json.environment,
        redirectUri: process.env.REDIRECT_URI,
    });

    const authUri = oauthClient.authorizeUri({
        scope: [OAuthClient.scopes.Accounting, OAuthClient.scopes.Payment],
        state: 'intuit-test',
    });
    //? send the auth URI back to the client
    res.send(authUri);
});

/**
 * Handle the callback to extract the `Auth Code` and exchange them for `Bearer-Tokens`
 */
app.get('/callback', function (req, res) {
    oauthClient
        .createToken(req.url)
        .then(function (authResponse) {
            console.log("got auth response. raw QB token is: \n")
            console.log(JSON.stringify(authResponse.token))
            console.log('-------')
            console.log('-------')
            oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
            return authResponse
        })
        .then(function (authResponse) {
            //? save the returned token to the DB
            return tokenSaver.saveAuthToken(authResponse.token, yardId)
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
            console.log(`The Refresh Token is  ${JSON.stringify(authResponse.getJson())}`);
            oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
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
        .makeApiCall({url: `${url}v3/company/${companyID}/companyinfo/${companyID}`})
        .then(function (authResponse) {
            console.log(`The response for API call is :${JSON.stringify(authResponse)}`);
            res.send(JSON.parse(authResponse.text()));
        })
        .catch(function (e) {
            console.error(e);
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
        .connect({addr: process.env.PORT || 8000})
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
