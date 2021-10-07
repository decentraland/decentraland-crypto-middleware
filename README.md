# Decentraland Authentication Middleware

[![Coverage Status](https://coveralls.io/repos/github/decentraland/decentraland-crypto-middleware/badge.svg?branch=main)](https://coveralls.io/github/decentraland/decentraland-crypto-middleware?branch=main)

A multi framework middleware to authenticate request signed with `@decentraland/SignedFetch`

## Install

```bash
  npm install -s decentraland-crypto-middleware
```

## Use with [Express](https://expressjs.com/)

```typescript
import { Request } from 'express'
import * as dcl from 'decentraland-crypto-middleware'

app.get(
  '/user/data',
  dcl.express(),
  (req: Request & dcl.DecentralandSignatureData) => {
    const address = req.auth
    const metadata = req.authMetadata
  }
)
```

## Use with [Koa](https://koajs.com/)

```typescript
import { Context } from 'koa'
import * as dcl from 'decentraland-crypto-middleware'

app.get(
  '/user/data',
  dcl.koa(),
  (ctx: Context & dcl.DecentralandSignatureData) => {
    const address = ctx.auth
    const metadata = ctx.authMetadata
  }
)
```

## Use with [PassportJS](http://www.passportjs.org/)

```typescript
import { Context } from 'koa'
import * as dcl from 'decentraland-crypto-middleware'

passport.use(dcl.passport())

app.get(
  '/user/data',
  passport.authenticate('decentraland'),
  (req: Request & dcl.DecentralandSignatureData) => {
    const address = req.auth
    const metadata = req.authMetadata
  }
)
```

## Use with [Well Known Components](https://github.com/well-known-components)

// TODO
