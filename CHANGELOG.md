# Changelog

## [4.2.0](https://github.com/intuit/oauth-jsclient/tree/4.2.0)
#### Features 
- None (includes all minor releases and fixes since 4.1.0)
#### Issues Fixed
- [updated sync-protect package ref, test suite and enabled logs for the sample client](https://github.com/intuit/oauth-jsclient/pull/184)

## [4.1.3](https://github.com/intuit/oauth-jsclient/tree/4.1.3)
#### Features 
- None
#### Issues Fixed
- [minor fixes OAuthClient.js](https://github.com/intuit/oauth-jsclient/pull/171)

## [4.1.2](https://github.com/intuit/oauth-jsclient/tree/4.1.2)
#### Issues Fixed
- [fixed Error converting authResponse to JSON string](https://github.com/intuit/oauth-jsclient/pull/165)

## [4.1.1](https://github.com/intuit/oauth-jsclient/tree/4.1.1)
#### Features 
- Stop using Popsicle and start using Axios
#### Issues Fixed
- [fix authResponse.json](https://github.com/intuit/oauth-jsclient/pull/160)


## [4.1.0](https://github.com/intuit/oauth-jsclient/tree/4.1.0)
#### Features 
- Stop using Popsicle and start using Axios
#### Issues Fixed
- [Introduced Axios replacing Popsicle](https://github.com/intuit/oauth-jsclient/pull/157)


## [4.0.0](https://github.com/intuit/oauth-jsclient/tree/4.0.0)
#### Breaking Changes
- Minimum Node Version >= 10
#### Features 
- Supports Minimum Node version 10 and newer ( not backward compatible )
- Moved lower node versions ( node 8,9, node 7, node 6 to 3.x.x. , 2.x.x and 1.x.x release respectively )
  - node version 8,9 and higher refer to 3.x.x 
  - node version 7 and higher refer to 2.x.x
  - node version 6 and higher refer to 1.x.x
#### Issues Fixed
- [Adding Transport Override for PDF use case](https://github.com/intuit/oauth-jsclient/pull/98)

#### References
- [PDF Transport](https://github.com/intuit/oauth-jsclient/issues/97) 


## [3.0.2](https://github.com/intuit/oauth-jsclient/tree/3.0.2)
#### Features 
- [Added support for passing custom authorize URL's](https://github.com/intuit/oauth-jsclient/pull/92)


## [3.0.1](https://github.com/intuit/oauth-jsclient/tree/3.0.1)
#### Issues Fixed
- [`snyk` package as a dependency since the 3.0 version](https://github.com/intuit/oauth-jsclient/issues/88)

## [3.0.0](https://github.com/intuit/oauth-jsclient/tree/3.0.0)
#### Breaking Changes
- Minimum Node Version >= 8 LTS
#### Features 
- Supports Minimum Node version 8 LTS and newer ( not backward compatible )
- Moved lower node versions ( node 7, node 6 to 2.x.x and 1.x.x release respectively )
  - node version 6 and lower refer to 1.x.x 
  - node version 7 and lower refer to 2.x.x
- Enhanced Code Coverage
#### Issues Fixed
- ES Lint issues fixed.
- Vulnerabilities fixed.
- [Error failing to create if response is missing headers](https://github.com/intuit/oauth-jsclient/issues/70)

## [2.1.0](https://github.com/intuit/oauth-jsclient/tree/2.1.0)
#### Features 
- Accept Full Range of HTTP Success Codes
- Handle not JSON content in response parsing
- Dependency cleanup ( still pending. Opening an issue )
#### Issues Fixed
- [Accept Full Range of HTTP Success Codes](https://github.com/intuit/oauth-jsclient/pull/78)
- [Fix: handle not JSON content in response parsing](https://github.com/intuit/oauth-jsclient/pull/59)

## [2.0.2](https://github.com/intuit/oauth-jsclient/tree/2.0.2)
#### Features 
- Improved Code Coverage
- README Corrections
- Fixed npm package issues in 2.0.1

## [2.0.1](https://github.com/intuit/oauth-jsclient/tree/2.0.1)
#### Features 
- Improved Code Coverage
- README Corrections

## [2.0.0](https://github.com/intuit/oauth-jsclient/tree/2.0.0)
#### Breaking Changes
- Minimum Node Version >= 7.0.0
#### Features 
- Supports Minimum Node version >=7.0.0 ( not backward compatible )
- Support for HTTP methods for API calls other than GET
- Enhanced Code Coverage
- ES Lint issues fixed.
#### Issues Fixed
- [Does this library support any HTTP methods for API calls other than GET](https://github.com/intuit/oauth-jsclient/issues/40)
- [Improve code coverage](https://github.com/intuit/oauth-jsclient/issues/39)
- [Fix ESLint Issues](https://github.com/intuit/oauth-jsclient/issues/40)
- [ngrok current version doesn't work](https://github.com/intuit/oauth-jsclient/issues/41)

## [1.5.0](https://github.com/intuit/oauth-jsclient/releases/tag/1.5.0)
#### Features
Problem :
- The csrf tokens created did not follow the singleton pattern.
- Occasional use of strict mode keywords made the package usage difficult in ES6 compliant environments. 

Solution :

- csrf token instance created at the time of instantiating OAuthClient. Singleton JS design pattern adopted.
- Adopted ES6 standardization
- ESLint enabled
#### Issues Fixed
- [Strict mode keywords](https://github.com/intuit/oauth-jsclient/issues/4)
- [csrf update to OAuthClient](https://github.com/intuit/oauth-jsclient/issues/30)


## [1.4.0](https://github.com/intuit/oauth-jsclient/releases/tag/1.4.0)
#### Features
Problem : 
- The access-tokens are valid post the revoke() functionality.

Solution : 
- Clear Token Object on invoking revoke() functionality

#### Issues Fixed
- [isAccessTokenValid() is true after calling revoke()](https://github.com/intuit/oauth-jsclient/issues/28)


## [1.3.0](https://github.com/intuit/oauth-jsclient/releases/tag/1.3.0)
#### Features
- TokenValidation for Revoke functionality Fixed
#### Issues Fixed
- Release Updates
- Revoke token [README.md](https://github.com/intuit/oauth-jsclient#revoke-access_token)
  
## [1.2.0](https://github.com/intuit/oauth-jsclient/releases/tag/1.2.0)
#### Features
- Highly Improved Implementation : setToken functionality  
#### Issues Fixed
1.) the setToken() and the constructor for passing the tokens are handled efficiently now.
2.) [#20](https://github.com/intuit/oauth-jsclient/pull/20) and [#7](https://github.com/intuit/oauth-jsclient/pull/7) - Fixed
3.) [#19](https://github.com/intuit/oauth-jsclient/issues/19) - HTTP 4XX Errors handled with more information.

## [1.1.3](https://github.com/intuit/oauth-jsclient/releases/tag/1.1.3)
#### Features
- Setting the Token methodology fixed
#### Issues Fixed
- [Error revoking token, this.token.refreshToken is not a function](https://github.com/intuit/oauth-jsclient/issues/16)

## [1.1.2](https://github.com/intuit/oauth-jsclient/releases/tag/1.1.2)
#### Features
- Supports Token Setting Functionality + New Scopes added
- New scopes added :
  - Payroll: com.intuit.quickbooks.payroll,
  - TimeTracking: com.intuit.quickbooks.payroll.timetracking,
  - Benefits: com.intuit.quickbooks.payroll.benefits,  
#### Issues Fixed
- [typo '/getCompanyInfo' in app.js](https://github.com/intuit/oauth-jsclient/issues/11)
- [Console logging of tokens seems like a bad idea](https://github.com/intuit/oauth-jsclient/issues/13)
  
## [1.1.1](https://github.com/intuit/oauth-jsclient/releases/tag/1.1.1)

- Rolling Back changes to realmId field on createToken()

## [1.1.0](https://github.com/intuit/oauth-jsclient/releases/tag/1.1.0)
#### Features
- Support for passing realmId and id_token using setToken()
#### Issues Fixed
- Support for optionally passing realmId and id_token using setToken()
- Issues fixed for #5
- Issues fixed for #6
- Issues fixed for #7

## [1.0.3](https://github.com/intuit/oauth-jsclient/releases/tag/1.0.3)
#### Features 
- Support for RefreshUsingToken method

## [1.0.2](https://github.com/intuit/oauth-jsclient/releases/tag/1.0.2)

- Version Release -  1.0.2

## [1.0.1](https://github.com/intuit/oauth-jsclient/releases/tag/1.0.1)

- npm publish patch - 1.0.1

## [1.0.0](https://github.com/intuit/oauth-jsclient/releases/tag/1.0.0)

- First Release - 1.0.0
