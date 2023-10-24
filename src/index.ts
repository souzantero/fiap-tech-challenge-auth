import * as AWS from 'aws-sdk'
import * as crypto from 'crypto'

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION ?? 'us-east-1'
})

const cognitoClientId = process.env.AWS_COGNITO_CLIENT_ID ?? ''
const cognitoClientSecret = process.env.AWS_COGNITO_CLIENT_SECRET ?? ''
const cognito = new AWS.CognitoIdentityServiceProvider()

const calculateSecretHash = (username: string) =>
  crypto
    .createHmac('sha256', cognitoClientSecret)
    .update(username + cognitoClientId)
    .digest('base64')


export const authenticate = async (event: any) => {
  const { username, password } = JSON.parse(event.body)
  if (!username || !password) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: 'Missing username or password',
      }),
    };
  }

  const secretHash = calculateSecretHash(username)
  const params = {
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: cognitoClientId,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
      SECRET_HASH: secretHash
    }
  }

  const response = await cognito.initiateAuth(params).promise()
  const accessToken = response.AuthenticationResult?.AccessToken

  if (!accessToken) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: 'Invalid username or password',
      }),
    };
  }

  return {
    statusCode: 200,
    body: JSON.stringify({ accessToken }),
  };
}