import type * as e from 'express'
import type * as k from 'koa'
import type {
  Options,
  VerifyAuthChainHeadersOptions,
  DecentralandSignatureData,
} from './types'
import { DecentralandStrategy } from './strategy'
import verify from './verify'

export { Options, DecentralandSignatureData }

/**
 * Express middleware
 */
export function express(options: Options) {
  return (req: e.Request, _res: e.Response, next: e.NextFunction) => {
    verify(req.method, req.baseUrl + req.path, req.headers, options)
      .then((data) => {
        Object.assign(req, data)
        next(null)
      })
      .catch((err) => next(!options.optinal ? err : null))
  }
}

/**
 * Koa middleware
 */
export function koa(options: Options): k.Middleware {
  return async (ctx, next) => {
    try {
      const data = await verify(ctx.method, ctx.path, ctx.headers, options)
      Object.assign(ctx, data)
    } catch (err) {
      if (!options.optinal) {
        err.status = err.statusCode || err.status || 500
        throw err
      }
    }

    return next()
  }
}

/**
 * Passport Strategy
 */
export function passport(options: VerifyAuthChainHeadersOptions) {
  return new DecentralandStrategy(options)
}

/**
 * Well Known Components
 * @todo
 */
export function wellKnownComponents(options: Options) {
  return () => {}
}
