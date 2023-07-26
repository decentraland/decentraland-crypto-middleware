import { AuthChain } from '@dcl/crypto'
import { AUTH_CHAIN_HEADER_PREFIX, AUTH_METADATA_HEADER, AUTH_TIMESTAMP_HEADER } from './types'

export default function createAuthChainHeaders(authChain: AuthChain, timetamp: number, metadata: any = {}) {
  const headers = {} as Record<string, string>

  authChain.forEach((item, index) => {
    headers[AUTH_CHAIN_HEADER_PREFIX + index] = JSON.stringify(item)
  })

  headers[AUTH_TIMESTAMP_HEADER] = String(timetamp)
  headers[AUTH_METADATA_HEADER] = JSON.stringify(metadata)

  return headers
}
