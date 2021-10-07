import type * as e from 'express'
import type * as k from 'koa'
import type * as w from '@well-known-components/interfaces'
import {
  Options,
  VerifyAuthChainHeadersOptions,
  DecentralandSignatureData,
  DEFAULT_ERROR_FORMAT,
} from './types'
import { DecentralandStrategy } from './strategy'
import verify from './verify'

export { Options, DecentralandSignatureData }

/**
 * Express middleware
 */
export function express(options: Options) {
  return (req: e.Request, res: e.Response, next: e.NextFunction) => {
    verify(req.method, req.baseUrl + req.path, req.headers, options)
      .then((data) => {
        Object.assign(req, data)
        next(null)
      })
      .catch((err) => {
        if (!options.optinal) {
          const status = err.statusCode || err.status || 500
          const onError = options.onError ?? DEFAULT_ERROR_FORMAT
          res.status(status).send(onError(err))
        } else {
          next(null)
        }
      })
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
        const status = err.statusCode || err.status || 500
        const onError = options.onError ?? DEFAULT_ERROR_FORMAT
        ctx.status = status
        ctx.body = onError(err)
        return
      }
    }

    return next()
  }
}

/**
 * Passport Strategy
 */
export function passport(defaultOptions: VerifyAuthChainHeadersOptions) {
  return new DecentralandStrategy(defaultOptions)
}

/**
 * Well Known Components
 */
export function wellKnownComponents(
  options: Options
): w.IHttpServerComponent.IRequestHandler<
  w.IHttpServerComponent.PathAwareContext<{}, string>
> {
  return async (ctx, next) => {
    try {
      const data = await verify(
        ctx.request.method,
        ctx.url.pathname,
        ctx.request.headers.raw(),
        options
      )
      Object.assign(ctx, data)
    } catch (err) {
      if (!options.optinal) {
        const onError = options.onError ?? DEFAULT_ERROR_FORMAT
        const status = err.statusCode || err.status || 500
        return { status, body: onError(err) }
      }
    }

    return next()
  }
}
