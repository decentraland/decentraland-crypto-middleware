import type { Request } from 'express'
import { Strategy } from 'passport-strategy'
import RequestError from './errors'
import { SessionOptions, VerifyAuthChainHeadersOptions } from './types'
import verify from './verify'

export class DecentralandStrategy extends Strategy {
  name = 'decentraland'

  constructor(private options: VerifyAuthChainHeadersOptions) {
    super()
  }

  authenticate(req: Request, options: SessionOptions) {
    verify(req.method, req.baseUrl + req.path, req.headers, this.options)
      .then((data) => {
        Object.assign(req, data)
        this.pass()
      })
      .catch((err: RequestError) => {
        if (!options.optinal) {
          this.fail(err.message, err.statusCode)
        } else {
          this.pass()
        }
      })
  }
}
