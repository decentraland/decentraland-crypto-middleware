export const DEFAULT_CATALYST = 'https://peer-lb.decentraland.org'
export const DEFAULT_EXPIRATION = (1000 * 60) | 0
export const AUTH_CHAIN_HEADER_PREFIX = 'x-identity-auth-chain-'
export const AUTH_TIMESTAMP_HEADER = 'x-identity-timestamp'
export const AUTH_METADATA_HEADER = 'x-identity-metadata'

export type DecentralandSignatureData<P extends {} = {}> = {
  auth: string
  authMetadata: P
}

export type VerifyAuthChainHeadersOptions = {
  catalyst?: string
  expiration?: number
}

export type SessionOptions = {
  optinal?: boolean
}

export type Options = VerifyAuthChainHeadersOptions & SessionOptions
