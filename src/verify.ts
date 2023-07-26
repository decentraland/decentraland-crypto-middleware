import { Authenticator, AuthChain, AuthLinkType } from '@dcl/crypto'
import {
  AUTH_CHAIN_HEADER_PREFIX,
  AUTH_METADATA_HEADER,
  AUTH_TIMESTAMP_HEADER,
  DecentralandSignatureData,
  DEFAULT_CATALYST,
  DEFAULT_EXPIRATION,
  VerifyAuthChainHeadersOptions
} from './types'
import RequestError from './errors'

export function isEIP1664AuthChain(authChain: AuthChain) {
  switch (authChain.length) {
    case 2:
    case 3:
      return authChain[0].type === AuthLinkType.SIGNER && authChain[1].type === AuthLinkType.ECDSA_EIP_1654_EPHEMERAL
    default:
      return false
  }
}

export function extractAuthChain(headers: Record<string, string | string[] | undefined>) {
  let index = 0
  const chain: AuthChain = []
  while (headers[AUTH_CHAIN_HEADER_PREFIX + index]) {
    try {
      const item = Array.isArray(headers[AUTH_CHAIN_HEADER_PREFIX + index])
        ? (headers[AUTH_CHAIN_HEADER_PREFIX + index] as string[])[0]
        : (headers[AUTH_CHAIN_HEADER_PREFIX + index] as string)

      chain.push(JSON.parse(item))
    } catch (err: any) {
      throw new RequestError(`Invalid chain format: ${err.message}`, 400)
    }

    index++
  }

  if (chain.length <= 1) {
    throw new RequestError(`Invalid Auth Chain`, 400)
  }

  return chain
}

export async function verifyPersonalSign(authChain: AuthChain, payload: string) {
  const verification = await Authenticator.validateSignature(payload, authChain, null as any)

  if (!verification.ok) {
    throw new RequestError(`Invalid signature: ${verification.message}`, 401)
  }

  return Authenticator.ownerAddress(authChain).toLowerCase()
}

export async function verifyEIP1654Sign(
  authChain: AuthChain,
  payload: string,
  options: Pick<VerifyAuthChainHeadersOptions, 'catalyst' | 'fetcher'>
) {
  const catalyst = new URL(options.catalyst ?? DEFAULT_CATALYST)
  const ownerAddress = Authenticator.ownerAddress(authChain).toLowerCase()
  let verification: { ownerAddress: string; valid: boolean }

  let response
  try {
    response = await options.fetcher.fetch(`https://${catalyst.host}/lambdas/crypto/validate-signature`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'accept-type': 'application/json'
      },
      body: JSON.stringify({ authChain, timestamp: payload })
    })
  } catch (err: any) {
    throw new RequestError(`Error connecting to catalyst "https://${catalyst.host}"`, 503)
  }

  let body = ''
  try {
    body = await response!.text()
    verification = JSON.parse(body)
  } catch (err: any) {
    throw new RequestError(`Invalid response from catalyst "https://${catalyst.host}": ${body}`, 503)
  }

  if (!verification.valid || verification.ownerAddress.toLowerCase() !== ownerAddress) {
    throw new RequestError(`Invalid signature`, 401)
  }

  return ownerAddress
}

export function verifySign(
  authChain: AuthChain,
  payload: string,
  options: Pick<VerifyAuthChainHeadersOptions, 'catalyst' | 'fetcher'>
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

export function verifyExpiration(timestamp: number, options: VerifyAuthChainHeadersOptions) {
  const expiration = options.expiration ?? DEFAULT_EXPIRATION
  const now = Date.now()
  if (timestamp + expiration < now) {
    throw new RequestError(
      `Expired signature: signature timestamp: ${timestamp}, timestamp expiration: ${
        timestamp + expiration
      }, local timestamp: ${now}`,
      401
    )
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

export default async function verify<P>(
  method: string,
  path: string,
  headers: Record<string, string | string[] | undefined>,
  options: VerifyAuthChainHeadersOptions
): Promise<DecentralandSignatureData<P>> {
  const authChain = extractAuthChain(headers)
  const timestamp = verifyTimestamp(headers[AUTH_TIMESTAMP_HEADER])
  const metadata = verifyMetadata(headers[AUTH_METADATA_HEADER])

  const payload = createPayload(method, path, headers[AUTH_TIMESTAMP_HEADER], headers[AUTH_METADATA_HEADER])
  const ownerAddress = await verifySign(authChain, payload, options)
  verifyExpiration(timestamp, options)

  return {
    auth: ownerAddress,
    authMetadata: metadata as P
  }
}
