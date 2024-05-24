import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'https://dev-44e0qupvzvr656x1.us.auth0.com/.well-known/jwks.json'
// const certificate = `-----BEGIN CERTIFICATE-----
// MIIDHTCCAgWgAwIBAgIJRoi/FtXfL6T4MA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
// BAMTIWRldi00NGUwcXVwdnp2cjY1NngxLnVzLmF1dGgwLmNvbTAeFw0yNDA1MjQw
// MzM3NTdaFw0zODAxMzEwMzM3NTdaMCwxKjAoBgNVBAMTIWRldi00NGUwcXVwdnp2
// cjY1NngxLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
// ggEBAL7NV8HWx2Lbwc5aCVjjrdHdZYIW4MciFtAq53ewHXk6DNo+HplJr4Uzla4J
// t4EIvj+UTyUvEyRqhuAGHhoS3KlnZt1rZXmyJupaAFUa/HRbkhj7Zew7rXPjg9sz
// 6kgTe0sdXZcTs9UxGDowKKwjZGwJ2JcYwuvuy7P8vYtQkHFBOn0hDdQ0bDdGjzdD
// TTNUhcY64xV6LS/Wq8m/4CNX2GyiBvqwDq4qes+Ltd+8+DfdcxhgVPhVG/l3VUmr
// 4XEtBg3xesfz+b6BrZayhCxJgC1lS/x6KaM8ou5Ec4iko5bxka9mAdIeHe6SPbLz
// hrww/akllaRwRfotUNICH/VoaI8CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
// BgNVHQ4EFgQUFh0y6VlYUXTZPhBc503WbgBT/lwwDgYDVR0PAQH/BAQDAgKEMA0G
// CSqGSIb3DQEBCwUAA4IBAQA5Gl1t1pmq/1rF4gFLGU8tRvurtWO/6XLJQsPZkVFZ
// 6BZne3PyhsFFeeeFhhpdrnx0mazfFqgP5NqgX5cV5z1BKrjYIzGItRs2dZZPQ6I1
// zC6e4aznA0oO4dbSUBBcK+ml18fDa9PQ0ajLe4ewUvl3wRbsR5ku6WnRqc/kjHCC
// 1xpXxtbuFQFGHTP4lluxf8nq+tniI8buphmqMbM15OoD/DkUa0NHSMg9FgoI1JSo
// Bd2B5/zDTr6OUsrtf1aBB9IMt3XF6LbjkKILr35praIRbXwjeBP8bgaPeDX8aCbw
// ZdkleBdn/eoxruiZGbcjFa8oIEus2oW88Xj2FujJKw24
// -----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  const res = await Axios.get(jwksUrl);
  const keys = res.data.keys;
  const signKeys = keys.find(key => key.kid === jwt.header.kid);

  
  if (!signKeys) throw new Error("Invalid signature Keys");
  const key = signKeys.x5c[0];
  const certificate = `-----BEGIN CERTIFICATE-----\n${key}\n-----END CERTIFICATE-----\n`;
  
  const verifyToken = jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] });

  logger.info('Token', verifyToken);

  return verifyToken;
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
