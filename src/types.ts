import RequestError from './errors'

export const AUTH_CHAIN_HEADER_PREFIX = 'x-identity-auth-chain-'
export const AUTH_TIMESTAMP_HEADER = 'x-identity-timestamp'
export const AUTH_METADATA_HEADER = 'x-identity-metadata'

export const DEFAULT_CATALYST = 'https://peer-lb.decentraland.org'
export const DEFAULT_EXPIRATION = (1000 * 60) | 0
export const DEFAULT_ERROR_FORMAT = (err: RequestError) => ({
  ok: false,
  message: err.message,
})

export type DecentralandSignatureData<P extends {} = {}> = {
  auth: string
  authMetadata: P
}

export type DecentralandSignatureContext<P extends {} = {}> = {
  verification?: DecentralandSignatureData<P>
}

export type DecentralandSignatureRequiredContext<P extends {} = {}> = {
  verification: DecentralandSignatureData<P>
}

export type VerifyAuthChainHeadersOptions<
  P extends Record<string, any> = Record<string, any>
> = {
  catalyst?: string
  expiration?: number
  verifyMetadataContent?: (authMetadata: P | undefined) => boolean
}

export type SessionOptions = {
  optional?: boolean
  onError?: (err: RequestError) => any
}

export type Options<P extends Record<string, any> = Record<string, any>> =
  VerifyAuthChainHeadersOptions<P> & SessionOptions
