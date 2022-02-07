import { request, RequestOptions } from 'https'
import { AuthChain, AuthLinkType } from 'dcl-crypto/dist/types'
import { Authenticator } from 'dcl-crypto/dist/Authenticator'
import {
  AUTH_CHAIN_HEADER_PREFIX,
  AUTH_METADATA_HEADER,
  AUTH_TIMESTAMP_HEADER,
  DecentralandSignatureData,
  DEFAULT_CATALYST,
  DEFAULT_EXPIRATION,
  VerifyAuthChainHeadersOptions,
} from './types'
import RequestError from './errors'

export function isEIP1664AuthChain(authChain: AuthChain) {
  switch (authChain.length) {
    case 2:
    case 3:
      return (
        authChain[0].type === AuthLinkType.SIGNER &&
        authChain[1].type === AuthLinkType.ECDSA_EIP_1654_EPHEMERAL
      )
    default:
      return false
  }
}

export function extractAuthChain(
  headers: Record<string, string | string[] | undefined>
) {
  let index = 0
  let chain: AuthChain = []
  while (headers[AUTH_CHAIN_HEADER_PREFIX + index]) {
    try {
      const item = Array.isArray(headers[AUTH_CHAIN_HEADER_PREFIX + index])
        ? (headers[AUTH_CHAIN_HEADER_PREFIX + index] as string[])[0]
        : (headers[AUTH_CHAIN_HEADER_PREFIX + index] as string)

      chain.push(JSON.parse(item))
    } catch (err) {
      throw new RequestError(`Invalid chain format: ${err.message}`, 400)
    }

    index++
  }

  if (chain.length <= 1) {
    throw new RequestError(`Invalid Auth Chain`, 400)
  }

  return chain
}

export async function verifyPersonalSign(
  authChain: AuthChain,
  payload: string
) {
  const verification = await Authenticator.validateSignature(
    payload,
    authChain,
    null as any
  )

  if (!verification.ok) {
    throw new RequestError(`Invalid signature: ${verification.message}`, 401)
  }

  return Authenticator.ownerAddress(authChain).toLowerCase()
}

export async function verifyEIP1654Sign(
  authChain: AuthChain,
  payload: string,
  options: Pick<VerifyAuthChainHeadersOptions, 'catalyst'> = {}
) {
  const catalyst = new URL(options.catalyst ?? DEFAULT_CATALYST)
  const ownerAddress = Authenticator.ownerAddress(authChain).toLowerCase()
  const verification: { ownerAddress: string; valid: boolean } =
    await new Promise((resolve, reject) => {
      const body = JSON.stringify({ authChain, timestamp: payload })
      const options: RequestOptions = {
        method: 'POST',
        port: 443,
        hostname: catalyst.host,
        path: '/lambdas/crypto/validate-signature',
        headers: {
          'accept-type': 'application/json',
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      }
      const req = request(options, (res) => {
        let json = ''
        res.setEncoding('utf-8')
        res.on('data', (chunk: string) => {
          json += chunk
        })
        res.on('end', () => {
          try {
            const verification = JSON.parse(json)
            resolve(verification)
          } catch (err) {
            reject(
              new RequestError(
                `Invalid response from catalyst "https://${catalyst.host}": ${json}`,
                503
              )
            )
          }
        })
      })

      req.on('error', (err) => {
        reject(
          new RequestError(
            `Error connecting to catalyst "https://${catalyst.host}": ${err.message}`,
            503
          )
        )
      })

      req.write(body)
      req.end()
    })

  if (
    !verification.valid ||
    verification.ownerAddress.toLowerCase() !== ownerAddress
  ) {
    throw new RequestError(`Invalid signature`, 401)
  }

  return ownerAddress
}

export function verifySign(
  authChain: AuthChain,
  payload: string,
  options: Pick<VerifyAuthChainHeadersOptions, 'catalyst'> = {}
) {
  if (isEIP1664AuthChain(authChain)) {
    return verifyEIP1654Sign(authChain, payload, options)
  }

  return verifyPersonalSign(authChain, payload)
}

export function verifyTimestamp(value?: string | string[]) {
  const timestamp = Number(value || '0')
  if (value && !Number.isFinite(timestamp)) {
    throw new RequestError(`Invalid chain timestamp: ${value}`, 400)
  }

  return timestamp
}

export function verifyMetadata(value?: string | string[]): Record<string, any> {
  try {
    return JSON.parse(value ? String(value) : '{}')
  } catch (err) {
    throw new RequestError(`Invalid chain metadata: "${value}"`, 400)
  }
}

export function verifyExpiration(
  timestamp: number,
  options: VerifyAuthChainHeadersOptions = {}
) {
  const expiration = options.expiration ?? DEFAULT_EXPIRATION
  if (timestamp + expiration < Date.now()) {
    throw new RequestError(`Expired signature`, 401)
  }

  return true
}

export function createPayload(
  method: string,
  path: string,
  rawTimestamp: string | string[] | undefined,
  rawMetadata: string | string[] | undefined
) {
  return [method, path, rawTimestamp, rawMetadata].join(':').toLowerCase()
}

export default async function verify<P extends {} = {}>(
  method: string,
  path: string,
  headers: Record<string, string | string[] | undefined>,
  options: VerifyAuthChainHeadersOptions = {}
): Promise<DecentralandSignatureData<P>> {
  const authChain = extractAuthChain(headers)
  const timestamp = verifyTimestamp(headers[AUTH_TIMESTAMP_HEADER])
  const metadata = verifyMetadata(headers[AUTH_METADATA_HEADER])

  const payload = createPayload(
    method,
    path,
    headers[AUTH_TIMESTAMP_HEADER],
    headers[AUTH_METADATA_HEADER]
  )
  const ownerAddress = await verifySign(authChain, payload, options)
  await verifyExpiration(timestamp)

  return {
    auth: ownerAddress,
    authMetadata: metadata as P,
  }
}
