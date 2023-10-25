import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda'
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

export const authorize = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  if (!event.headers?.Authorization) {
    return {
      statusCode: 401,
      body: JSON.stringify({
        message: 'Missing Authorization header',
      }),
    };
  }

  const accessToken = event.headers.Authorization.replace('Bearer ', '')
  const params = {
    AccessToken: accessToken
  }

  try {
    await cognito.getUser(params).promise()
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Authorized',
      }),
    };
  } catch (error) {
    const { message } = error as Error
    return {
      statusCode: 401,
      body: JSON.stringify({ message }),
    };
  }
}

export const authenticate = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  if (!event.body) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: 'Missing body',
      }),
    };
  }

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

  try {
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
  } catch (error) {
    const { message } = error as Error
    return {
      statusCode: 400,
      body: JSON.stringify({ message }),
    };
  }
}

export const register = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  if (!event.body) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: 'Missing body',
      }),
    };
  }

  const { email, username, password } = JSON.parse(event.body)
  if (!email || !username || !password) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: 'Missing email, username or password',
      }),
    };
  }

  const secretHash = calculateSecretHash(username)
  const params = {
    ClientId: cognitoClientId,
    Password: password,
    Username: username,
    UserAttributes: [
      { Name: 'email', Value: email }
    ],
    SecretHash: secretHash
  }

  try {
    await cognito.signUp(params).promise()
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'User created',
      }),
    };
  } catch (error) {
    const { message } = error as Error
    return {
      statusCode: 400,
      body: JSON.stringify({ message }),
    };
  }
}

export const confirm = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  if (!event.body) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: 'Missing body',
      }),
    };
  }

  const { username, code } = JSON.parse(event.body)
  if (!username || !code) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: 'Missing username or code',
      }),
    };
  }

  const secretHash = calculateSecretHash(username)
  const params = {
    ClientId: cognitoClientId,
    ConfirmationCode: code,
    Username: username,
    SecretHash: secretHash
  }

  try {
    await cognito.confirmSignUp(params).promise()
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'User confirmed',
      }),
    };
  } catch (error) {
    const { message } = error as Error
    return {
      statusCode: 400,
      body: JSON.stringify({ message }),
    };
  }
}

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

// const confirmCode = '864798'
// executeConfirm(username, confirmCode)

// const accessToken = 'eyJraWQiOiI5eHVGNlpmY2pyZGp5WEZzV2xubnM1ZjdtTXVXejVVc0M0R25xdXplam5jPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI5YmI4ZTUwOC0zZjUwLTQzMDUtYjFmNC0wM2JjMTZiMTcwZGIiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9JYjBUbzhkVEoiLCJjbGllbnRfaWQiOiJvbjUzdm92aW1rMzZsZm5oMG9jMXJ0NzgiLCJvcmlnaW5fanRpIjoiNDAzMjNkY2YtYTdiOS00YTVjLTg1YTEtYzEwY2M5YTEwYjI1IiwiZXZlbnRfaWQiOiJiN2E1ZDQ1Ni01ZDgwLTQzNjEtOWM1Ny1hZjdkY2Q5NjNmZDMiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiYXV0aF90aW1lIjoxNjk4MTkyNzA4LCJleHAiOjE2OTgxOTYzMDgsImlhdCI6MTY5ODE5MjcwOCwianRpIjoiZjUwNzZkNWEtOTBjZS00ZTA2LWJlYTgtNTE2OWQxMjFiZWFlIiwidXNlcm5hbWUiOiIwMDAxMTEyMjIzMyJ9.lT4aXbqqaLE2HNGtwgp39hka8naMPvyDHeFoSqsxWbyQvDDL20Ncctfx1L-FElAl2h2GeMZOGe0wmOIk3rsH__hIAniYXaWXSfJNafsQCJTRy3o9bLARKwRZcQgSpN1Ermmdt_XXOcmaJzX5joms1sePeTJbp7Proc_L8TT8b6l4X4gxFVh3jrwmRXz7bBDYYLkPJBE4PgiWRsHYsE9N3BKhrsDAmNazrvSl_L4lMd0Gu0mMtsAVZvFZ-oBncYqdHiRhgbtNpIlm5LPLu3oGCxLVWeQ2U_gQlqrN73uALu4UJN_7PGpILh4G6LVvULQRXnh75IRN7mcYB6ikNNntNw'
// executeAuthorize(accessToken)
