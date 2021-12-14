import { Authenticator } from 'dcl-crypto'
import { AuthChain, AuthIdentity, AuthLinkType } from 'dcl-crypto/dist/types'
import createAuthChainHeaders from './createAuthChainHeader'
import {
  AUTH_CHAIN_HEADER_PREFIX,
  AUTH_METADATA_HEADER,
  AUTH_TIMESTAMP_HEADER,
} from './types'
import verifyAuthChainHeaders, {
  isEIP1664AuthChain,
  verifyEIP1654Sign,
  verifyPersonalSign,
} from './verify'

const identity: AuthIdentity = {
  ephemeralIdentity: {
    address: '0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34',
    publicKey:
      '0x0420c548d960b06dac035d1daf826472eded46b8b9d123294f1199c56fa235c89f2515158b1e3be0874bfb15b42d1551db8c276787a654d0b8d7b4d4356e70fe42',
    privateKey:
      '0xbc453a92d9baeb3d10294cbc1d48ef6738f718fd31b4eb8085efe7b311299399',
  },
  expiration: new Date('3021-10-16T22:32:29.626Z'),
  authChain: [
    {
      type: AuthLinkType.SIGNER,
      payload: '0x7949f9f239d1a0816ce5eb364a1f588ae9cc1bf5',
      signature: '',
    },
    {
      type: AuthLinkType.ECDSA_PERSONAL_EPHEMERAL,
      payload: `Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z`,
      signature:
        '0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b',
    },
  ],
}

const authChainEIP1664: AuthChain = [
  {
    type: AuthLinkType.SIGNER,
    payload: '',
    signature: '',
  },
  {
    type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
    payload: ``,
    signature: '',
  },
  {
    type: AuthLinkType.ECDSA_EIP_1654_SIGNED_ENTITY,
    payload: ``,
    signature: '',
  },
]

describe(`src/verifyAuthChainHeaders`, () => {
  describe(`isEIP1664AuthChain`, () => {
    test(`should return true if the  Auth Chain is a EIP 1654`, () => {
      expect(isEIP1664AuthChain(authChainEIP1664)).toBe(true)
    })

    test(`should return false if the Auth Chain is not  a EIP 1654`, () => {
      expect(isEIP1664AuthChain(identity.authChain)).toBe(false)
    })

    test(`should return false if the Auth Chain is invalud`, () => {
      expect(isEIP1664AuthChain([])).toBe(false)
    })
  })

  describe(`verifyEIP1654Sign`, () => {
    test(`should return the owner address of the sign`, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      expect(await verifyEIP1654Sign(chain, payload)).toBe(
        identity.authChain[0].payload.toLowerCase()
      )
    })

    test(`should accept a catalyst url`, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      expect(
        await verifyEIP1654Sign(chain, payload, {
          catalyst: 'https://peer.decentraland.zone',
        })
      ).toBe(identity.authChain[0].payload.toLowerCase())
    })

    test(`should throw an error with an invalid signature`, async () => {
      const payload = '0123456789'
      await expect(() => verifyEIP1654Sign([], payload)).rejects.toThrowError(
        'Invalid signature'
      )
    })

    test(`should throw an error if catalyst does not respond`, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      await expect(() =>
        verifyEIP1654Sign(chain, payload, {
          catalyst: 'https://no-peer.decentraland.zone',
        })
      ).rejects.toThrowError('Error connecting to catalyst')
    })

    test(`should throw an error if catalyst `, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      await expect(() =>
        verifyEIP1654Sign(chain, payload, { catalyst: 'https://httpbin.org/' })
      ).rejects.toThrowError('Invalid response from catalyst')
    })
  })

  describe(`verifyPersonalSign`, () => {
    test(`should return the owner address of the sign`, async () => {
      const payload = '0123456789'
      const chain = Authenticator.signPayload(identity, payload)
      expect(await verifyPersonalSign(chain, payload)).toBe(
        identity.authChain[0].payload.toLowerCase()
      )
    })

    test(`should throw an error with an invalid signature`, async () => {
      const payload = '0123456789'
      await expect(() => verifyPersonalSign([], payload)).rejects.toThrowError(
        'Invalid signature'
      )
    })
  })

  describe(`verifyAuthChainHeaders`, () => {
    test(`should return all the information about a header signature `, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)]
        .join(':')
        .toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)

      expect(await verifyAuthChainHeaders(method, path, headers)).toEqual({
        auth: identity.authChain[0].payload.toLowerCase(),
        authMetadata: {},
      })
    })

    test(`should throw an error if there is not an auth chain`, async () => {
      await expect(() =>
        verifyAuthChainHeaders('', '', {})
      ).rejects.toThrowError('Invalid Auth Chain')
    })

    test(`should throw an error if the auth chain is invalid`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)]
        .join(':')
        .toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)
      headers[AUTH_CHAIN_HEADER_PREFIX + '1'] = '{'

      await expect(() =>
        verifyAuthChainHeaders(method, path, headers)
      ).rejects.toThrowError('Invalid chain format:')
    })

    test(`should throw an error if timestamp is invalid`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)]
        .join(':')
        .toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)
      headers[AUTH_TIMESTAMP_HEADER] = 'abc'

      await expect(() =>
        verifyAuthChainHeaders(method, path, headers)
      ).rejects.toThrowError('Invalid chain timestamp:')
    })

    test(`should throw an error if timestamp is expired`, async () => {
      const timestamp = 0
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)]
        .join(':')
        .toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)

      await expect(() =>
        verifyAuthChainHeaders(method, path, headers)
      ).rejects.toThrowError('Expired signature')
    })

    test(`should throw an error if timestamp header wasn't signed`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)]
        .join(':')
        .toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp + 1, metadata)

      await expect(() =>
        verifyAuthChainHeaders(method, path, headers)
      ).rejects.toThrowError('Invalid signature:')
    })

    test(`should throw an error if metadata is invalid`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)]
        .join(':')
        .toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, metadata)
      headers[AUTH_METADATA_HEADER] = '{'

      await expect(() =>
        verifyAuthChainHeaders(method, path, headers)
      ).rejects.toThrowError('Invalid chain metadata:')
    })

    test(`should throw an error if metadata wasn't signed`, async () => {
      const timestamp = Date.now()
      const metadata = {}
      const method = 'get'
      const path = '/path/to/resource'
      const payload = [method, path, timestamp, JSON.stringify(metadata)]
        .join(':')
        .toLowerCase()
      const chain = Authenticator.signPayload(identity, payload)
      const headers = createAuthChainHeaders(chain, timestamp, {
        extra: 'data',
      })

      await expect(() =>
        verifyAuthChainHeaders(method, path, headers)
      ).rejects.toThrowError('Invalid signature:')
    })
  })
})
