import { AuthChain, AuthIdentity, AuthLinkType, Authenticator } from '@dcl/crypto'
import { createFetchComponent } from '@well-known-components/fetch-component'
import createAuthChainHeaders from '../src/createAuthChainHeader'
import { AUTH_CHAIN_HEADER_PREFIX, AUTH_METADATA_HEADER, AUTH_TIMESTAMP_HEADER, DEFAULT_EXPIRATION } from '../src/types'
import verifyAuthChainHeaders, { isEIP1664AuthChain, verifyEIP1654Sign, verifyPersonalSign } from '../src/verify'

const identity: AuthIdentity = {
  ephemeralIdentity: {
    address: '0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34',
    publicKey:
      '0x0420c548d960b06dac035d1daf826472eded46b8b9d123294f1199c56fa235c89f2515158b1e3be0874bfb15b42d1551db8c276787a654d0b8d7b4d4356e70fe42',
    privateKey: '0xbc453a92d9baeb3d10294cbc1d48ef6738f718fd31b4eb8085efe7b311299399'
  },
  expiration: new Date('3021-10-16T22:32:29.626Z'),
  authChain: [
    {
      type: AuthLinkType.SIGNER,
      payload: '0x7949f9f239d1a0816ce5eb364a1f588ae9cc1bf5',
      signature: ''
    },
    {
      type: AuthLinkType.ECDSA_PERSONAL_EPHEMERAL,
      payload: `Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z`,
      signature:
        '0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b'
    }
  ]
}

const authChainEIP1664: AuthChain = [
  {
    type: AuthLinkType.SIGNER,
    payload: '',
    signature: ''
  },
  {
    type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
    payload: ``,
    signature: ''
  },
  {
    type: AuthLinkType.ECDSA_EIP_1654_SIGNED_ENTITY,
    payload: ``,
    signature: ''
  }
]

describe(`src/verifyAuthChainHeaders`, () => {
  const fetcher = createFetchComponent()
  describe(`isEIP1664AuthChain`, () => {
    it(`should return true if the  Auth Chain is a EIP 1654`, () => {
      expect(isEIP1664AuthChain(authChainEIP1664)).toBe(true)
    })

    it(`should return false if the Auth Chain is not  a EIP 1654`, () => {
      expect(isEIP1664AuthChain(identity.authChain)).toBe(false)
    })

    it(`should return false if the Auth Chain is invalud`, () => {
      expect(isEIP1664AuthChain([])).toBe(false)
    })
  })

  describe(`verifyEIP1654Sign`, () => {
    it(`should return the owner address of the sign`, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      expect(await verifyEIP1654Sign(chain, payload, { fetcher })).toBe(identity.authChain[0].payload.toLowerCase())
    })

    it(`should accept a catalyst url`, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      expect(
        await verifyEIP1654Sign(chain, payload, {
          catalyst: 'https://peer.decentraland.zone',
          fetcher
        })
      ).toBe(identity.authChain[0].payload.toLowerCase())
    })

    it(`should throw an error with an invalid signature`, async () => {
      const payload = '0123456789'
      await expect(() => verifyEIP1654Sign([], payload, { fetcher })).rejects.toThrowError('Invalid signature')
    })

    it(`should throw an error if catalyst does not respond`, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      await expect(() =>
        verifyEIP1654Sign(chain, payload, {
          catalyst: 'https://no-peer.decentraland.zone',
          fetcher
        })
      ).rejects.toThrowError('Error connecting to catalyst')
    })
  })

  describe(`verifyPersonalSign`, () => {
    it(`should return the owner address of the sign`, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      expect(await verifyPersonalSign(chain, payload)).toBe(identity.authChain[0].payload.toLowerCase())
    })

    it(`should throw an error with an invalid signature`, async () => {
      const payload = '0123456789'
      await expect(() => verifyPersonalSign([], payload)).rejects.toThrowError('Invalid signature')
    })
  })

  describe(`verifyAuthChainHeaders`, () => {
    it(`should return all the information about a header signature `, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)].join(':').toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)

      expect(await verifyAuthChainHeaders(method, path, headers, { fetcher })).toEqual({
        auth: identity.authChain[0].payload.toLowerCase(),
        authMetadata: {}
      })
    })

    it(`should throw an error if there is not an auth chain`, async () => {
      await expect(() => verifyAuthChainHeaders('', '', {}, { fetcher })).rejects.toThrowError('Invalid Auth Chain')
    })

    it(`should throw an error if the auth chain is invalid`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)].join(':').toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)
      headers[AUTH_CHAIN_HEADER_PREFIX + '1'] = '{'

      await expect(() => verifyAuthChainHeaders(method, path, headers, { fetcher })).rejects.toThrowError(
        'Invalid chain format:'
      )
    })

    it(`should throw an error if timestamp is invalid`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)].join(':').toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)
      headers[AUTH_TIMESTAMP_HEADER] = 'abc'

      await expect(() => verifyAuthChainHeaders(method, path, headers, { fetcher })).rejects.toThrowError(
        'Invalid chain timestamp:'
      )
    })

    it(`should throw an error if timestamp is expired`, async () => {
      const timestamp = 0
      const now = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)].join(':').toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)
      jest.spyOn(Date, 'now').mockReturnValue(now)

      await expect(() => verifyAuthChainHeaders(method, path, headers, { fetcher })).rejects.toThrowError(
        `Expired signature: signature timestamp: ${timestamp}, timestamp expiration: ${
          timestamp + DEFAULT_EXPIRATION
        }, local timestamp: ${now}`
      )
    })

    it(`should throw an error if timestamp header wasn't signed`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)].join(':').toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp + 1, metadata)

      await expect(() => verifyAuthChainHeaders(method, path, headers, { fetcher })).rejects.toThrowError(
        'Invalid signature:'
      )
    })

    it(`should throw an error if metadata is invalid`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)].join(':').toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)
      headers[AUTH_METADATA_HEADER] = '{'

      await expect(() => verifyAuthChainHeaders(method, path, headers, { fetcher })).rejects.toThrowError(
        'Invalid chain metadata:'
      )
    })

    it(`should throw an error if metadata wasn't signed`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)].join(':').toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, {
        extra: 'data'
      })

      await expect(() => verifyAuthChainHeaders(method, path, headers, { fetcher })).rejects.toThrowError(
        'Invalid signature:'
      )
    })
  })
})
