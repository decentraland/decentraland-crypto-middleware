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
import 'isomorphic-fetch'

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
      if (typeof headers[AUTH_CHAIN_HEADER_PREFIX + index] === 'string') {
        chain.push(
          JSON.parse(headers[AUTH_CHAIN_HEADER_PREFIX + index] as string)
        )
      } else {
        throw new RequestError(`Invalid chain format`, 400)
      }
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
  let response: Response
  let verification: { ownerAddress: string; valid: boolean }

  try {
    response = await fetch(
      `https://${catalyst.host}/lambdas/crypto/validate-signature`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'accept-type': 'application/json',
        },
        body: JSON.stringify({ authChain, timestamp: payload }),
      }
    )
  } catch (err) {
    throw new RequestError(
      `Error connecting to catalyst "https://${catalyst.host}"`,
      503
    )
  }

  let body = ''
  try {
    body = await response!.text()
    verification = JSON.parse(body)
  } catch (err) {
    throw new RequestError(
      `Invalid response from catalyst "https://${catalyst.host}": ${body}`,
      503
    )
  }

  if (
    !verification.valid ||
    verification.ownerAddress.toLowerCase() !== ownerAddress
  ) {
    throw new RequestError(`Invalid signature`, 401)
  }

  return ownerAddress
}

export default async function verify<P extends {} = {}>(
  method: string,
  path: string,
  headers: Record<string, string | string[] | undefined>,
  options: VerifyAuthChainHeadersOptions = {}
): Promise<DecentralandSignatureData<P>> {
  let authChain = extractAuthChain(headers)
  const timestamp = Number(headers[AUTH_TIMESTAMP_HEADER] || '0')
  if (headers[AUTH_TIMESTAMP_HEADER] && !Number.isFinite(timestamp)) {
    throw new RequestError(
      `Invalid chain timestamp: ${headers[AUTH_TIMESTAMP_HEADER]}`,
      400
    )
  }

  let metadata: any
  try {
    metadata = JSON.parse(String(headers[AUTH_METADATA_HEADER]) || '{}')
  } catch (err) {
    throw new RequestError(
      `Invalid chain metadata: "${headers[AUTH_METADATA_HEADER]}"`,
      400
    )
  }

  let ownerAddress: string
  const payload = [
    method,
    path,
    headers[AUTH_TIMESTAMP_HEADER],
    headers[AUTH_METADATA_HEADER],
  ]
    .join(',')
    .toLowerCase()
  if (isEIP1664AuthChain(authChain)) {
    ownerAddress = await verifyEIP1654Sign(authChain, payload, options)
  } else {
    ownerAddress = await verifyPersonalSign(authChain, payload)
  }

  const expiration = options.expiration ?? DEFAULT_EXPIRATION
  if (timestamp + expiration < Date.now()) {
    throw new RequestError(`Expired signature`, 401)
  }

  return {
    auth: ownerAddress,
    authMetadata: metadata,
  }
}
