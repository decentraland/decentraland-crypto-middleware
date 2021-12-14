import { AuthChain, AuthLinkType } from 'dcl-crypto'
import { red, gray, green, blue } from 'colors/safe'
import {
  verifyTimestamp,
  verifyMetadata,
  verifySign,
  createPayload,
  verifyExpiration,
} from '../src/verify'

const [_runtime, _file, rawAuthChain] = process.argv

class Logger {
  items: any[][] = []
  constructor(public prefix: string = '') {}

  skip(message: string, ...extra: any[]) {
    this.items.push([this.prefix + gray(`❔ ${message}`), ...extra])
  }

  ok(message: string, ...extra: any[]) {
    this.items.push([this.prefix + green(`✅ ${message}`), ...extra])
  }

  error(message: string, ...extra: any[]) {
    this.items.push([this.prefix + red(`❌ ${message}:`), ...extra])
  }

  flush() {
    for (const item of this.items) {
      console.log(...item)
    }
    this.items = []
  }
}

const logger = new Logger()

let failed = false
async function step<F extends (logger: Logger) => Record<string, any>>(
  name: string,
  fun: F
): Promise<ReturnType<F>> {
  if (failed) {
    logger.skip(name)
    logger.flush()
    return {} as any
  }

  const l = new Logger('  ')
  try {
    const result = await fun(l)
    logger.ok(name)
    logger.flush()
    l.flush()
    return result as any
  } catch (err) {
    failed = true
    logger.error(name, blue(err.message))
    logger.flush()
    l.flush()
    return {} as any
  }
}

Promise.resolve().then(async () => {
  const { authChain, method, pathname, timestamp, metadata } = await step(
    'Verify authChain',
    async (logger) => {
      const authChain: AuthChain = JSON.parse(rawAuthChain)

      if (authChain.length !== 3) {
        throw new Error(`Malformed Auth Chain: must have 3 items`)
      }

      const signatureItem = authChain[2]
      if (
        signatureItem.type !== AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY &&
        signatureItem.type !== AuthLinkType.ECDSA_EIP_1654_SIGNED_ENTITY
      ) {
        throw new Error(
          `Malformed Auth Chain: unsupported type "${signatureItem.type}". Expected ${AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY} or ${AuthLinkType.ECDSA_EIP_1654_SIGNED_ENTITY}`
        )
      }

      let isValidPayload = true
      let payload = signatureItem.payload
      const method = payload.slice(0, payload.indexOf(':'))
      payload = payload.slice(payload.indexOf(':') + 1)

      const pathname = payload.slice(0, payload.indexOf(':'))
      payload = payload.slice(payload.indexOf(':') + 1)

      const rawTimestamp = payload.slice(0, payload.indexOf(':'))
      payload = payload.slice(payload.indexOf(':') + 1)

      const rawMetadata = payload
      const methods = [
        'get',
        'head',
        'post',
        'put',
        'delete',
        'connect',
        'options',
        'trace',
        'patch',
      ]
      if (methods.includes(method)) {
        logger.ok(`http method: ${blue(method)}`)
      } else {
        logger.error(
          `Invalud chain method: "${method}" (expected: "${methods.join(
            '", "'
          )})"`
        )
        isValidPayload = false
      }

      if (pathname.startsWith('/')) {
        logger.ok(`http pathname: ${blue(pathname)}`)
      } else {
        logger.error(
          `Invalid chain pathname: "${pathname}", (expected: /${pathname})`
        )
        isValidPayload = false
      }

      let timestamp: number = 0
      try {
        timestamp = verifyTimestamp(rawTimestamp)
        logger.ok(`timestamp: ${blue(String(timestamp))}`)
      } catch (err) {
        logger.error(err.message)
        isValidPayload = false
      }

      let metadata: any
      try {
        metadata = verifyMetadata(rawMetadata)
        logger.ok(`metadata: ${blue(rawMetadata)}`)
      } catch (err) {
        logger.error(err.message)
        isValidPayload = false
      }

      if (!isValidPayload) {
        throw new Error(`Malformed Auth Chain: invalid payload`)
      }

      return { authChain, method, pathname, timestamp, metadata }
    }
  )

  await step('Verify signature', async (logger) => {
    const payload = createPayload(
      method,
      pathname,
      String(timestamp),
      JSON.stringify(metadata)
    )
    const ownerAddress = await verifySign(authChain, payload)
    logger.ok(`ownerAddress: ${blue(ownerAddress)}`)
    return { ownerAddress }
  })

  await step(`Verify expiration`, async () => {
    verifyExpiration(timestamp)
    return {}
  })

  console.log()
})

// const authChain = extractAuthChain(headers)
// const timestamp = verifyTimestamp(headers[AUTH_TIMESTAMP_HEADER])
// const metadata = verifyMetadata(headers[AUTH_METADATA_HEADER])

// const payload = createPayload(
//   method,
//   path,
//   headers[AUTH_TIMESTAMP_HEADER],
//   headers[AUTH_METADATA_HEADER]
// )
// const ownerAddress = await verifySign(authChain, payload, options)
// await verifyExpiration(timestamp)
