/**
 * Demonstration of the improved error handling in intuit-oauth
 * 
 * This script demonstrates how OAuth2 errors are now properly surfaced
 * when token operations fail (e.g., invalid_grant, expired tokens, etc.)
 */

'use strict';

const OAuthClient = require('../src/OAuthClient');

// Create an OAuth client instance
const oauthClient = new OAuthClient({
  clientId: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
  environment: 'sandbox',
  redirectUri: 'http://localhost:3000/callback',
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
  console.log('Testing createToken with an invalid authorization code...\n');
  
  try {
    // Use a properly formatted callback URL with invalid authorization code
    const invalidCallbackUrl = 'http://localhost:3000/callback?code=INVALID_CODE_12345&state=testState&realmId=123456789';
    const authResponse = await oauthClient.createToken(invalidCallbackUrl);
    console.log('✅ Token created successfully (unexpected)');
    console.log('Token:', authResponse.getToken());
  } catch (error) {
    console.log('❌ Error occurred (expected):\n');
    console.log('📋 Error Details:');
    console.log('  ├─ error:', error.error);
    console.log('  ├─ error_description:', error.error_description);
    console.log('  ├─ intuit_tid:', error.intuit_tid);
    console.log('  ├─ authResponse.body:', error.authResponse && error.authResponse.body ? 'Present ✓' : 'Missing ✗');
    console.log('  └─ authResponse.json:', error.authResponse && error.authResponse.json ? 'Present ✓' : 'Missing ✗');
    
    if (error.authResponse && error.authResponse.json) {
      console.log('\n📄 Full Error Response JSON:');
      console.log(JSON.stringify(error.authResponse.json, null, 2));
    }
    
    // Now you can handle specific OAuth2 errors
    if (error.error === 'invalid_grant') {
      console.log('\n💡 The authorization code is invalid or expired. User needs to re-authorize.');
    }
  }
}

/**
 * Example 2: Handling refresh token errors
 * 
 * Similar improvements for refresh() method
 */
async function demonstrateRefreshTokenError() {
  console.log('Testing refresh with an invalid refresh token...\n');
  
  // Set up a fake expired token to demonstrate refresh errors
  oauthClient.setToken({
    token_type: 'bearer',
    access_token: 'fake_access_token_12345',
    refresh_token: 'INVALID_REFRESH_TOKEN_67890',
    expires_in: 3600,
    x_refresh_token_expires_in: 8726400,
    createdAt: Date.now(),
  });
  
  try {
    const authResponse = await oauthClient.refresh();
    console.log('✅ Token refreshed successfully (unexpected)');
    console.log('Token:', authResponse.getToken());
  } catch (error) {
    console.log('❌ Error occurred (expected):\n');
    console.log('📋 Error Details:');
    console.log('  ├─ error:', error.error);
    console.log('  ├─ error_description:', error.error_description);
    console.log('  ├─ intuit_tid:', error.intuit_tid);
    console.log('  ├─ authResponse.body:', error.authResponse && error.authResponse.body ? 'Present ✓' : 'Missing ✗');
    console.log('  └─ authResponse.json:', error.authResponse && error.authResponse.json ? 'Present ✓' : 'Missing ✗');
    
    if (error.authResponse && error.authResponse.json) {
      console.log('\n📄 Full Error Response JSON:');
      console.log(JSON.stringify(error.authResponse.json, null, 2));
    }
    
    // Handle specific refresh token errors
    if (error.error === 'invalid_grant') {
      console.log('\n💡 The refresh token is invalid or expired. User needs to re-authorize.');
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
            transactionId: error.intuit_tid,
          },
        };
      
      case 'invalid_client':
        return {
          userMessage: 'Authentication configuration error. Please contact support.',
          action: 'CONTACT_SUPPORT',
          logDetails: {
            error: error.error,
            description: error.error_description,
            transactionId: error.intuit_tid,
          },
        };
      
      case 'invalid_request':
        return {
          userMessage: 'Invalid request. Please try again.',
          action: 'RETRY',
          logDetails: {
            error: error.error,
            description: error.error_description,
            transactionId: error.intuit_tid,
          },
        };
      
      default:
        return {
          userMessage: 'An authentication error occurred. Please try again.',
          action: 'RETRY',
          logDetails: {
            error: error.error,
            description: error.error_description,
            transactionId: error.intuit_tid,
          },
        };
    }
  }
  
  // Fallback for non-OAuth errors
  return {
    userMessage: 'An unexpected error occurred.',
    action: 'CONTACT_SUPPORT',
    logDetails: { message: error.message },
  };
}

console.log('='.repeat(80));
console.log('OAuth Error Handling Demonstration');
console.log('='.repeat(80));
console.log('\nThis script demonstrates the improved error handling in intuit-oauth');
console.log('See the code comments for before/after comparisons\n');

// Run all demonstration examples
async function runDemo() {
  try {
    // Example 1: Create Token Error
    const separator = '='.repeat(80);
    console.log(`\n${separator}`);
    console.log('Example 1: Create Token Error Handling');
    console.log(separator);
    await demonstrateCreateTokenError();
    
    // Example 2: Refresh Token Error
    console.log(`\n${separator}`);
    console.log('Example 2: Refresh Token Error Handling');
    console.log(separator);
    await demonstrateRefreshTokenError();
    
    // Example 3: Programmatic Error Handling
    console.log(`\n${separator}`);
    console.log('Example 3: Programmatic Error Handling with Helper Function');
    console.log(separator);
    console.log('Testing error handler with different error types...\n');
    
    // Simulate different OAuth errors
    const testErrors = [
      { error: 'invalid_grant', error_description: 'Authorization code expired', intuit_tid: 'test-tid-001' },
      { error: 'invalid_client', error_description: 'Client credentials invalid', intuit_tid: 'test-tid-002' },
      { error: 'invalid_request', error_description: 'Malformed request', intuit_tid: 'test-tid-003' },
      { message: 'Network timeout' }, // Non-OAuth error
    ];
    
    testErrors.forEach((testError, index) => {
      console.log(`\n🧪 Test ${index + 1}: ${testError.error || testError.message}`);
      const result = handleOAuthError(testError);
      console.log('Result:');
      console.log(JSON.stringify(result, null, 2));
    });
    
    console.log(`\n${separator}`);
    console.log('✅ All Examples Complete');
    console.log(separator);
    console.log('\n💡 Key Takeaways:');
    console.log('  1. OAuth errors now include detailed error codes and descriptions');
    console.log('  2. Transaction IDs (intuit_tid) are available for debugging with support');
    console.log('  3. Full response body and JSON are accessible for detailed analysis');
    console.log('  4. You can build sophisticated error handling based on error types');
    console.log('  5. Both createToken() and refresh() provide consistent error information\n');
    
  } catch (error) {
    console.error('\n❌ Unexpected error in demo:', error.message);
    throw error;
  }
}

// Run the demo
runDemo().catch(err => {
  console.error('Unexpected error running demo:', err);
  process.exit(1);
});
