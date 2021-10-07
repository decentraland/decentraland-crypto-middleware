export default class RequestError extends Error {
  constructor(message: string, public statusCode: number = 500) {
    super(message)
  }
}
