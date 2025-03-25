//Instructions: 
// Run the program using this command from the terminal: 
// node grapqlClient.js

// Install npm package
// npm install graphql-request

'use strict';

//Import necessary modules
const { GraphQLClient, gql } = require('graphql-request');

//constants
const GRAPHQL_API_ENDPOINT = "https://qb-e2e.api.intuit.com/graphql";
const ENV = "E2E";
const API_TOKEN = "<your api token here>";

const client = new GraphQLClient(GRAPHQL_API_ENDPOINT, {
    headers: {
      Authorization: `Bearer ${API_TOKEN}`, // Optional: If your API requires authentication
    },
  });

  //define your GraphQL query or mutation
  const query = gql`
  query RequestEmployerInfo {
    payrollEmployerInfo {
        employerCompensations {
            edges {
                node {
                    id
                    alternateIds {
                        id
                    }
                    name
                    type {
                        key
                        value
                        description
                    }
                }
            }
        }
    }
}
`;

//Handle input variables
const queryWithVariables = gql`
query getEmployeeCompensationById {
  payrollEmployerInfo {
    employerCompensations (filter: {$employeeId: ID!}){
      edges {
        node {
          id
          alternateIds {
            id
          }
          name
        }
      }
    }
  }
}
`;
const variables = { employeeId: "3" };

//function to call the query with no variables
async function fetchData() {
    try {
      const data = await client.request(query);
      console.log(JSON.stringify(data, null, 2));
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  }

  async function fetchDataWithVariables() {
    try {
      const data = await client.request(queryWithVariables, variables);
      console.log(JSON.stringify(data, null, 2));
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  }

//run the query (one without input variable)
fetchData();

//run the query (one with input variable)
//fetchDataWithVariables();


