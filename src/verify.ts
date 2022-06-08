import { AuthChain } from '@dcl/crypto/dist/types'
import { Authenticator } from '@dcl/crypto/dist/Authenticator'
import {
  AUTH_CHAIN_HEADER_PREFIX,
  AUTH_METADATA_HEADER,
  AUTH_TIMESTAMP_HEADER,
  DecentralandSignatureData,
  DEFAULT_EXPIRATION,
  DEFAULT_PROVIDER_URL,
  VerifyAuthChainHeadersOptions,
} from './types'
import RequestError from './errors'
import { HTTPProvider } from 'eth-connect'

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

export async function verifySignature(
  authChain: AuthChain,
  payload: string,
  options: VerifyAuthChainHeadersOptions = {}
) {
  const provider =
    options.ethereumProvider || new HTTPProvider(DEFAULT_PROVIDER_URL)

  const verification = await Authenticator.validateSignature(
    payload,
    authChain,
    provider
  )

  if (!verification.ok) {
    throw new RequestError(`Invalid signature: ${verification.message}`, 401)
  }

  return Authenticator.ownerAddress(authChain).toLowerCase()
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
  const ownerAddress = await verifySignature(authChain, payload, options)
  await verifyExpiration(timestamp)

  return {
    auth: ownerAddress,
    authMetadata: metadata as P,
  }
}
