import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as AWS from 'aws-sdk';
import * as crypto from 'crypto';

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION ?? 'us-east-1',
});

const cognitoClientId = process.env.AWS_COGNITO_CLIENT_ID || '';
const cognitoClientSecret = process.env.AWS_COGNITO_CLIENT_SECRET || '';
const cognito = new AWS.CognitoIdentityServiceProvider();

const calculateSecretHash = (username: string) =>
  crypto
    .createHmac('sha256', cognitoClientSecret)
    .update(username + cognitoClientId)
    .digest('base64');

const respond = (
  statusCode: number,
  message: string,
): APIGatewayProxyResult => {
  return {
    statusCode,
    body: JSON.stringify({ message }),
  };
};

export const authorize = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  if (!event.headers?.Authorization) {
    return respond(401, 'Missing Authorization header');
  }

  const accessToken = event.headers.Authorization.replace('Bearer ', '');
  const params = {
    AccessToken: accessToken,
  };

  try {
    await cognito.getUser(params).promise();
    return respond(200, 'Authorized');
  } catch (error) {
    return respond(401, (error as Error).message || 'Unauthorized');
  }
};

export const authenticate = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  if (!event.body) {
    return respond(400, 'Missing body');
  }

  const { username, password } = JSON.parse(event.body);
  if (!username || !password) {
    return respond(400, 'Missing username or password');
  }

  const secretHash = calculateSecretHash(username);
  const params = {
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: cognitoClientId,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
      SECRET_HASH: secretHash,
    },
  };

  try {
    const response = await cognito.initiateAuth(params).promise();
    const accessToken = response.AuthenticationResult?.AccessToken;

    if (!accessToken) {
      return respond(400, 'Invalid username or password');
    }

    return respond(200, accessToken);
  } catch (error) {
    return respond(400, (error as Error).message || 'Authentication failed');
  }
};

export const register = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  if (!event.body) {
    return respond(400, 'Missing body');
  }

  const { email, username, password } = JSON.parse(event.body);
  if (!email || !username || !password) {
    return respond(400, 'Missing email, username, or password');
  }

  const secretHash = calculateSecretHash(username);
  const params = {
    ClientId: cognitoClientId,
    Password: password,
    Username: username,
    UserAttributes: [{ Name: 'email', Value: email }],
    SecretHash: secretHash,
  };

  try {
    await cognito.signUp(params).promise();
    return respond(200, 'User created');
  } catch (error) {
    return respond(400, (error as Error).message || 'User registration failed');
  }
};

export const confirm = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  if (!event.body) {
    return respond(400, 'Missing body');
  }

  const { username, code } = JSON.parse(event.body);
  if (!username || !code) {
    return respond(400, 'Missing username or code');
  }

  const secretHash = calculateSecretHash(username);
  const params = {
    ClientId: cognitoClientId,
    ConfirmationCode: code,
    Username: username,
    SecretHash: secretHash,
  };

  try {
    await cognito.confirmSignUp(params).promise();
    return respond(200, 'User confirmed');
  } catch (error) {
    return respond(400, (error as Error).message || 'Confirmation failed');
  }
};

// Manual tests

// const executeAuthenticate = async (username: string, password: string) => {
//   const response = await authenticate({
//     body: JSON.stringify({ username, password })
//   } as APIGatewayProxyEvent)
//   console.log(response)
// }

// const executeRegister = async (email: string, username: string, password: string) => {
//   const response = await register({
//     body: JSON.stringify({ email, username, password })
//   } as APIGatewayProxyEvent)
//   console.log(response)
// }

// const executeConfirm = async (username: string, code: string) => {
//   const response = await confirm({
//     body: JSON.stringify({ username, code })
//   } as APIGatewayProxyEvent)
//   console.log(response)
// }

// const executeAuthorize = async (accessToken: string) => {
//   const response = await authorize({
//     headers: { Authorization: `Bearer ${accessToken}` }
//   } as any)
//   console.log(response)
// }

// const email = 'souzantero@gmail.com'
// const username = '00011122233'
// const password = '@dR0m3d_'
// executeRegister(email, username, password)
// executeAuthenticate(username, password)

// const confirmCode = '139694'
// executeConfirm(username, confirmCode)

// const accessToken = 'eyJraWQiOiI5eHVGNlpmY2pyZGp5WEZzV2xubnM1ZjdtTXVXejVVc0M0R25xdXplam5jPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJlMDljNDM5Mi0xMGZjLTQ0MTgtOGZhOC1kMDU4OWQ0MTY4ZGMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9JYjBUbzhkVEoiLCJjbGllbnRfaWQiOiJvbjUzdm92aW1rMzZsZm5oMG9jMXJ0NzgiLCJvcmlnaW5fanRpIjoiMThmNWY0MjgtM2E3My00ODI3LTlhMzktNzM5OTBjNDNmNGU1IiwiZXZlbnRfaWQiOiI2MmIxYWJhMi03OWZjLTQ4ZjItYjkwNi01M2M4NmY2NDk1MWIiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiYXV0aF90aW1lIjoxNjk4MTkzNTg2LCJleHAiOjE2OTgxOTcxODYsImlhdCI6MTY5ODE5MzU4NiwianRpIjoiOGZjYzYyZjYtYzRhNy00OTAwLTkyOTQtYTBiNjg3ZDVlMjVkIiwidXNlcm5hbWUiOiIwMDAxMTEyMjIzMyJ9.U93rhG3aia9DtnJYMFjrQ-oNg3oJrq7vmhLErvBgjUuOocouZxU26rh-xJdgnPalUfNZjwOrwy0NH67sjy9sBos2-FMWFXhfWcQfLxVJBU75fDlo1C-rUNhbHQxjo-rzlkd1hDxx7oCEjXI_cpuasqdfXQeztMSO7Bdjl0ehvGGWrSE9XXpCtCI72eCQ7Dlkd6xa7pD0GH0JdrGg3WUOAkKLoMC15UZ0Ux41uAGvRK_weY2f1hscDb7saXHwOW0qtgJAT3uKUOc5WWf4rR97wZ-E2i-4nY9u1D3dW-24eIbVtr4rPN7qKqwpNk_bEpoZUw5lT-dNCLSe4hnZlbtBAw'
// executeAuthorize(accessToken)
