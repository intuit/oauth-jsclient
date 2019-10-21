"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var dotenv_1 = __importDefault(require("dotenv"));
var express_1 = __importDefault(require("express"));
var path_1 = __importDefault(require("path"));
var intuit_oauth_1 = __importDefault(require("intuit-oauth"));
var body_parser_1 = __importDefault(require("body-parser"));
dotenv_1.default.config();
var app = express_1.default();
var ngrok = (process.env.NGROK_ENABLED === "true") ? require('ngrok') : null;
/**
 * Configure View and Handlebars
 */
app.use(body_parser_1.default.urlencoded({ extended: true }));
app.use(express_1.default.static(path_1.default.join(__dirname, '../../public')));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.use(body_parser_1.default.json());
var urlencodedParser = body_parser_1.default.urlencoded({ extended: false });
/**
 * App Variables
 * @type {null}
 */
var oauth2_token_json = null, redirectUri = '';
/**
 * Instantiate new Client
 * @type {OAuthClient}
 */
var oauthClient = null;
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
    oauthClient = new intuit_oauth_1.default({
        clientId: req.query.json.clientId,
        clientSecret: req.query.json.clientSecret,
        environment: req.query.json.environment,
        redirectUri: req.query.json.redirectUri
    });
    var authUri = oauthClient.authorizeUri({ scope: [intuit_oauth_1.default.scopes.Accounting], state: 'intuit-test' });
    res.send(authUri);
});
/**
 * Handle the callback to extract the `Auth Code` and exchange them for `Bearer-Tokens`
 */
app.get('/callback', function (req, res) {
    oauthClient.createToken(req.url)
        .then(function (authResponse) {
        oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
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
    oauthClient.refresh()
        .then(function (authResponse) {
        console.log('The Refresh Token is  ' + JSON.stringify(authResponse.getJson()));
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
    var companyID = oauthClient.getToken().realmId;
    var url = oauthClient.environment == 'sandbox' ? intuit_oauth_1.default.environment.sandbox : intuit_oauth_1.default.environment.production;
    oauthClient.makeApiCall({ url: url + 'v3/company/' + companyID + '/companyinfo/' + companyID })
        .then(function (authResponse) {
        console.log("The response for API call is :" + JSON.stringify(authResponse));
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
    var authUri = oauthClient.authorizeUri({ scope: [intuit_oauth_1.default.scopes.OpenId, intuit_oauth_1.default.scopes.Email], state: 'intuit-test' });
    res.redirect(authUri);
});
/**
 * Start server on HTTP (will use ngrok for HTTPS forwarding)
 */
var server = app.listen(process.env.PORT || 8000, function () {
    var address = server.address();
    console.log("\uD83D\uDCBB Server listening on port " + address.port);
    if (!ngrok) {
        redirectUri = "" + address.port + '/callback';
        console.log("\uD83D\uDCB3  Step 1 : Paste this URL in your browser : " + 'http://localhost:' + ("" + address.port));
        console.log('💳  Step 2 : Copy and Paste the clientId and clientSecret from : https://developer.intuit.com');
        console.log("\uD83D\uDCB3  Step 3 : Copy Paste this callback URL into redirectURI :" + 'http://localhost:' + ("" + address.port) + '/callback');
        console.log("\uD83D\uDCBB  Step 4 : Make Sure this redirect URI is also listed under the Redirect URIs on your app in : https://developer.intuit.com");
    }
});
/**
 * Optional : If NGROK is enabled
 */
if (ngrok) {
    console.log("NGROK Enabled");
    ngrok.connect({ addr: process.env.PORT || 8000 }, function (err, url) {
        if (err) {
            process.exit(1);
        }
        else {
            redirectUri = url + '/callback';
            console.log("\uD83D\uDCB3 Step 1 : Paste this URL in your browser :  " + url);
            console.log('💳 Step 2 : Copy and Paste the clientId and clientSecret from : https://developer.intuit.com');
            console.log("\uD83D\uDCB3 Step 3 : Copy Paste this callback URL into redirectURI :  " + redirectUri);
            console.log("\uD83D\uDCBB Step 4 : Make Sure this redirect URI is also listed under the Redirect URIs on your app in : https://developer.intuit.com");
        }
    });
}
