/**
 * Demonstration of the improved error handling in intuit-oauth
 * 
 * This script demonstrates how OAuth2 errors are now properly surfaced
 * when token operations fail (e.g., invalid_grant, expired tokens, etc.)
 */

const OAuthClient = require('../src/OAuthClient');

// Create an OAuth client instance
const oauthClient = new OAuthClient({
  clientId: 'ABM5BJFArjiVs9YHPY7TkiePSZnksMJwudp4F1JReuTX2MeuTc', //'YOUR_CLIENT_ID',
  clientSecret: 'V6zf3DSRCVTW0yFVVcrcF71IwvQdACiO6ip8mWNc',//'YOUR_CLIENT_SECRET',
  environment: 'sandbox',
  redirectUri: 'http://localhost:3000/callback'
});

/**
 * Example 1: Handling createToken errors
 * 
 * Before the fix:
 * - error.message: "Request failed with status code 400"
 * - error.authResponse.body: "" (empty)
 * - error.authResponse.json: null (null)
 * 
 * After the fix:
 * - error.error: "invalid_grant"
 * - error.error_description: "Token invalid"
 * - error.authResponse.body: '{"error":"invalid_grant","error_description":"Token invalid"}'
 * - error.authResponse.json: { error: "invalid_grant", error_description: "Token invalid" }
 * - error.intuit_tid: "1234-5678-9012-3456"
 */
async function demonstrateCreateTokenError() {
  try {
    const authResponse = await oauthClient.createToken('invalid_code');
    console.log('Token created:', authResponse.getToken());
  } catch (error) {
    console.error('Error creating token:');
    console.error('  error:', error.error);
    console.error('  error_description:', error.error_description);
    console.error('  intuit_tid:', error.intuit_tid);
    console.error('  authResponse.body:', error.authResponse.body);
    console.error('  authResponse.json:', error.authResponse.json);
    
    // Now you can handle specific OAuth2 errors
    if (error.error === 'invalid_grant') {
      console.log('The authorization code is invalid or expired. User needs to re-authorize.');
    }
  }
}

/**
 * Example 2: Handling refresh token errors
 * 
 * Similar improvements for refresh() method
 */
async function demonstrateRefreshTokenError() {
  try {
    const authResponse = await oauthClient.refresh();
    console.log('Token refreshed:', authResponse.getToken());
  } catch (error) {
    console.error('Error refreshing token:');
    console.error('  error:', error.error);
    console.error('  error_description:', error.error_description);
    console.error('  intuit_tid:', error.intuit_tid);
    
    // Handle specific refresh token errors
    if (error.error === 'invalid_grant') {
      console.log('The refresh token is invalid or expired. User needs to re-authorize.');
    }
  }
}

/**
 * Example 3: Programmatic error handling
 * 
 * You can now build sophisticated error handling based on the actual error type
 */
function handleOAuthError(error) {
  // Check if we have OAuth error details
  if (error.error && error.error_description) {
    switch (error.error) {
      case 'invalid_grant':
        return {
          userMessage: 'Your session has expired. Please sign in again.',
          action: 'REAUTHORIZE',
          logDetails: {
            error: error.error,
            description: error.error_description,
            transactionId: error.intuit_tid
          }
        };
      
      case 'invalid_client':
        return {
          userMessage: 'Authentication configuration error. Please contact support.',
          action: 'CONTACT_SUPPORT',
          logDetails: {
            error: error.error,
            description: error.error_description,
            transactionId: error.intuit_tid
          }
        };
      
      case 'invalid_request':
        return {
          userMessage: 'Invalid request. Please try again.',
          action: 'RETRY',
          logDetails: {
            error: error.error,
            description: error.error_description,
            transactionId: error.intuit_tid
          }
        };
      
      default:
        return {
          userMessage: 'An authentication error occurred. Please try again.',
          action: 'RETRY',
          logDetails: {
            error: error.error,
            description: error.error_description,
            transactionId: error.intuit_tid
          }
        };
    }
  }
  
  // Fallback for non-OAuth errors
  return {
    userMessage: 'An unexpected error occurred.',
    action: 'CONTACT_SUPPORT',
    logDetails: { message: error.message }
  };
}

console.log('='.repeat(80));
console.log('OAuth Error Handling Demonstration');
console.log('='.repeat(80));
console.log('\nThis script demonstrates the improved error handling in intuit-oauth');
console.log('See the code comments for before/after comparisons\n');

// Run a test with an invalid authorization code to demonstrate error handling
async function runDemo() {
  console.log('Testing createToken with an invalid authorization code...\n');
  
  // Simulate a callback URL with an invalid authorization code
  const invalidCallbackUrl = 'http://localhost:3000/callback?code=INVALID_CODE_12345&state=testState&realmId=123456789';
  
  try {
    const authResponse = await oauthClient.createToken(invalidCallbackUrl);
    console.log('✅ Token created successfully (unexpected)');
    console.log('Token:', authResponse.getToken());
  } catch (error) {
    console.log('❌ Error occurred (expected):\n');
    console.log('📋 Error Details:');
    console.log('  ├─ error:', error.error);
    console.log('  ├─ error_description:', error.error_description);
    console.log('  ├─ intuit_tid:', error.intuit_tid);
    console.log('  ├─ authResponse.body:', error.authResponse?.body ? 'Present ✓' : 'Missing ✗');
    console.log('  └─ authResponse.json:', error.authResponse?.json ? 'Present ✓' : 'Missing ✗');
    
    if (error.authResponse?.json) {
      console.log('\n📄 Full Error Response JSON:');
      console.log(JSON.stringify(error.authResponse.json, null, 2));
    }
    
    // Demonstrate the error handling helper
    console.log('\n🔧 Error Handling Result:');
    const handlingResult = handleOAuthError(error);
    console.log(JSON.stringify(handlingResult, null, 2));
  }
  
  console.log('\n' + '='.repeat(80));
  console.log('Demo Complete');
  console.log('='.repeat(80));
}

// Run the demo
runDemo().catch(err => {
  console.error('Unexpected error running demo:', err);
  process.exit(1);
});
