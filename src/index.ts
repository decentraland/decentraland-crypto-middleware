import { IHttpServerComponent } from '@well-known-components/interfaces'
import {
  Options,
  DecentralandSignatureData,
  DEFAULT_ERROR_FORMAT,
  DecentralandSignatureContext,
  DecentralandSignatureRequiredContext
} from './types'
import verify from './verify'

export { Options, DecentralandSignatureData, DecentralandSignatureContext, DecentralandSignatureRequiredContext }
/**
 * Well Known Components
 */
export function wellKnownComponents(
  options: Options
): IHttpServerComponent.IRequestHandler<
  IHttpServerComponent.PathAwareContext<DecentralandSignatureContext<any>, string>
> {
  return async (ctx, next) => {
    try {
      const data = await verify(ctx.request.method, ctx.url.pathname, ctx.request.headers.raw(), options)

      ctx.verification = data
    } catch (err) {
      if (!options.optional) {
        const onError = options.onError ?? DEFAULT_ERROR_FORMAT
        const status = err.statusCode || err.status || 500
        return { status, body: onError(err) }
      }
    }

    return next()
  }
}
