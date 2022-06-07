# Decentraland Authentication Middleware

[![Coverage Status](https://coveralls.io/repos/github/decentraland/decentraland-crypto-middleware/badge.svg?branch=main)](https://coveralls.io/github/decentraland/decentraland-crypto-middleware?branch=main)

A multi framework middleware to authenticate request signed with `@decentraland/SignedFetch`

## Index

- [Install](#install)
- [Use with Express](#use-with-express)
- [Use with Koa](#use-with-koa)
- [Use with Well Known Components](#use-with-well-known-components)
- [Use with PassportJS](#use-with-passportjs)
- [Options](#options)
- [Auth Chain Generator](#auth-chain-generator)
- [Develop](#develop)

## Install

```bash
  npm install -s decentraland-crypto-middleware
```

## Use with [Express](https://expressjs.com/)

```typescript
import { Request } from 'express'
import * as dcl from 'decentraland-crypto-middleware'

app.get(
  '/user/required',
  dcl.express(),
  (req: Request & dcl.DecentralandSignatureData) => {
    const address: string = req.auth
    const metadata: Record<string, any> = req.authMetadata
  }
)

app.get(
  '/user/optional',
  dcl.express({ optional: true }),
  (req: Request & dcl.DecentralandSignatureData) => {
    const address: string | undefined = req.auth
    const metadata: Record<string, any> | undefined = req.authMetadata
  }
)
```

## Use with [Koa](https://koajs.com/)

```typescript
import { Context } from 'koa'
import * as dcl from 'decentraland-crypto-middleware'

app.get(
  '/user/required',
  dcl.koa(),
  (ctx: Context & dcl.DecentralandSignatureData) => {
    const address: string = ctx.auth
    const metadata: Record<string, any> = ctx.authMetadata
  }
)

app.get(
  '/user/optional',
  dcl.koa({ optional: true }),
  (ctx: Context & dcl.DecentralandSignatureData) => {
    const address: string | undefined = ctx.auth
    const metadata: Record<string, any> | undefined = ctx.authMetadata
  }
)
```

## Use with [Well Known Components](https://github.com/well-known-components)

```typescript
import type { IHttpServerComponent } from '@well-known-components/interfaces'
import * as dcl from 'decentraland-crypto-middleware'

app.use('/user/required', dcl.wellKnownComponents())
app.get('/user/required', (ctx: dcl.DecentralandSignatureRequiredContext) => {
  const address: string = ctx.verification.auth
  const metadata: Record<string, any> = ctx.verification.authMetadata
})

app.use('/user/optional', dcl.wellKnownComponents({ optional: true })
app.get('/user/optional', (ctx: dcl.DecentralandSignatureContext<{}>) => {
  const address: string | undefined= ctx.verification?.auth
  const metadata: Record<string, any> | undefined = ctx.verification?.authMetadata
})
```

## Use with [PassportJS](http://www.passportjs.org/)

```typescript
import { Context } from 'koa'
import * as dcl from 'decentraland-crypto-middleware'

passport.use(dcl.passport())

app.get(
  '/user/required',
  passport.authenticate('decentraland'),
  (req: Request & dcl.DecentralandSignatureData) => {
    const address: string = req.auth
    const metadata: Record<string, any> = req.authMetadata
  }
)

app.get(
  '/user/required',
  passport.authenticate('decentraland', { optional: true }),
  (req: Request & dcl.DecentralandSignatureData) => {
    const address: string | undefined = req.auth
    const metadata: Record<string, any> | undefined = req.authMetadata
  }
)
```

## Options

| `name`       | `type`                                         | `description`                                                                                                |
| ------------ | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `optional`   | `boolean`                                      | if `false` request will fail if there is no signature or if is invalid (default: `false`)                    |
| `expiration` | `number`                                       | time in milliseconds where a signature is considered valid (default: `60_000`)                               |
| `catalyst`   | `string`                                       | catalyst url to validate contract wallet signatures (default: `https://peer-lb.decentraland.org/`)           |
| `onError`    | `(err: Error & { statusCode: number }) => any` | formats the response body when an error occurred (default: `(err) => ({ ok: false, message: err.message })`) |

### Auth Chain Generator

If you want to simulate signed headers you can use the [`Auth Chain Generator`](https://git.io/Jimns)

## Develop

If you want to contribute make you will need to setup `husky` otherwise your commit may fail because is not following the format standard

```bash
  npm run husky-setup
```
