'use strict'
/* eslint-disable  @typescript-eslint/strict-boolean-expressions */
/* eslint-disable  @typescript-eslint/restrict-template-expressions */
/* eslint-disable  @typescript-eslint/no-var-requires */
/* eslint-disable  @typescript-eslint/explicit-function-return-type */
/* eslint-disable  @typescript-eslint/prefer-nullish-coalescing */
/* eslint-disable  @typescript-eslint/no-floating-promises */

const assert = require('assert')
const removeSlash = require('remove-trailing-slash')
const looselyValidate = require('@segment/loosely-validate-event')
const axios = require('axios')
const axiosRetry = require('axios-retry')
const ms = require('ms')
const { v4: uuid } = require('uuid')
const md5 = require('md5')
const version = require('../package.json').version
const isString = require('lodash.isstring')

const globalAny: any = global
const noop = () => {}

const setImmediateFunc = globalAny.setImmediate || process.nextTick.bind(process)

interface Options {
  flushAt?: any // [flushAt] (default: 20)
  flushInterval?: number // [flushInterval] (default: 10000)
  host?: string // [host] (default: 'https://api.segment.io')
  enable?: boolean // [ enable] (default: true)
  axiosConfig?: object // [axiosConfig] (optional)
  axiosInstance?: any // [axiosInstance] (default: axios.create(options.axiosConfig))
  axiosRetryConfig?: object // [axiosRetryConfig] (optional)
  retryCount?: number // [retryCount] (default: 3)
  errorHandler?: Function // [errorHandler] (optional)
  maxQueueSize?: number
  path?: string
  timeout?: any
}

class Analytics {
  writeKey: string
  flushAt: number
  flushInterval: number
  errorHandler: any
  axiosInstance: any
  host: string
  queue: any
  path: string
  timeout: boolean
  pendingFlush: any
  timer: any
  flushed: boolean
  maxQueueSize: number
  enable: any

  constructor (writeKey, options: Options) {
    assert(writeKey, 'You must pass your Segment project\'s write key.')
    options = options || {}

    this.queue = []
    this.writeKey = writeKey
    this.host = removeSlash(options.host || 'https://api.segment.io')
    this.path = removeSlash(options.path || '/v1/batch')
    let axiosInstance = options.axiosInstance
    if (axiosInstance == null) {
      axiosInstance = axios.create(options.axiosConfig)
    }
    this.axiosInstance = axiosInstance
    this.timeout = options.timeout || false
    this.flushAt = Math.max(options.flushAt, 1) || 20
    this.maxQueueSize = options.maxQueueSize || 1024 * 450 // 500kb is the API limit, if we approach the limit i.e., 450kb, we'll flush
    this.flushInterval = options.flushInterval || 10000
    this.flushed = false
    this.errorHandler = options.errorHandler
    this.pendingFlush = null
    Object.defineProperty(this, 'enable', {
      configurable: false,
      writable: false,
      enumerable: true,
      value: typeof options.enable === 'boolean' ? options.enable : true
    })
    if (options.retryCount !== 0) {
      axiosRetry(this.axiosInstance, {
        retries: options.retryCount || 3,
        retryDelay: axiosRetry.exponentialDelay,
        ...options.axiosRetryConfig,
        // retryCondition is below optional config to ensure it does not get overridden
        retryCondition: this._isErrorRetryable
      })
    }
  }

  _validate (message, type) {
    looselyValidate(message, type)
  }

  /**
   * Send an identify `message`.
   *
   * @param {Object} message
   * @param {Function} [callback] (optional)
   * @return {Analytics}
   */

  identify (message, callback) {
    this._validate(message, 'identify')
    this.enqueue('identify', message, callback)
    return this
  }

  /**
   * Send a group `message`.
   *
   * @param {Object} message
   * @param {Function} [callback] (optional)
   * @return {Analytics}
   */

  group (message, callback) {
    this._validate(message, 'group')
    this.enqueue('group', message, callback)
    return this
  }

  /**
   * Send a track `message`.
   *
   * @param {Object} message
   * @param {Function} [callback] (optional)
   * @return {Analytics}
   */

  track (message, callback) {
    this._validate(message, 'track')
    this.enqueue('track', message, callback)
    return this
  }

  /**
   * Send a page `message`.
   *
   * @param {Object} message
   * @param {Function} [callback] (optional)
   * @return {Analytics}
   */

  page (message, callback) {
    this._validate(message, 'page')
    this.enqueue('page', message, callback)
    return this
  }

  /**
   * Send a screen `message`.
   *
   * @param {Object} message
   * @param {Function} [callback] (optional)
   * @return {Analytics}
   */

  screen (message, callback) {
    this._validate(message, 'screen')
    this.enqueue('screen', message, callback)
    return this
  }

  /**
   * Send an alias `message`.
   *
   * @param {Object} message
   * @param {Function} [callback] (optional)
   * @return {Analytics}
   */

  alias (message, callback) {
    this._validate(message, 'alias')
    this.enqueue('alias', message, callback)
    return this
  }

  /**
   * Add a `message` of type `type` to the queue and
   * check whether it should be flushed.
   *
   * @param {String} type
   * @param {Object} message
   * @param {Function} [callback] (optional)
   * @api private
   */

  enqueue (type, message, callback) {
    callback = callback || noop

    if (!this.enable) {
      return setImmediateFunc(callback)
    }

    message = Object.assign({}, message)
    message.type = type
    message.context = Object.assign({
      library: {
        name: 'analytics-node',
        version
      }
    }, message.context)

    message._metadata = Object.assign({
      nodeVersion: process.versions.node
    }, message._metadata)

    if (!message.timestamp) {
      message.timestamp = new Date()
    }

    if (!message.messageId) {
      // We md5 the messaage to add more randomness. This is primarily meant
      // for use in the browser where the uuid package falls back to Math.random()
      // which is not a great source of randomness.
      // Borrowed from analytics.js (https://github.com/segment-integrations/analytics.js-integration-segmentio/blob/a20d2a2d222aeb3ab2a8c7e72280f1df2618440e/lib/index.js#L255-L256).
      const encodedStringifiedMessage = md5(JSON.stringify(message))
      const uuidStr = uuid()
      message.messageId = `node-${encodedStringifiedMessage}-${uuidStr}`
    }

    // Historically this library has accepted strings and numbers as IDs.
    // However, our spec only allows strings. To avoid breaking compatibility,
    // we'll coerce these to strings if they aren't already.
    if (message.anonymousId && !isString(message.anonymousId)) {
      message.anonymousId = JSON.stringify(message.anonymousId)
    }
    if (message.userId && !isString(message.userId)) {
      message.userId = JSON.stringify(message.userId)
    }

    this.queue.push({ message, callback })

    if (!this.flushed) {
      this.flushed = true
      this.flush()
      return
    }

    const hasReachedFlushAt = this.queue.length >= this.flushAt
    const hasReachedQueueSize = this.queue.reduce((acc: number, item: object) => acc + JSON.stringify(item).length, 0) >= this.maxQueueSize
    if (hasReachedFlushAt || hasReachedQueueSize) {
      this.flush()
      return
    }

    if (this.flushInterval && !this.timer) {
      this.timer = setTimeout(this.flush.bind(this), this.flushInterval)
    }
  }

  /**
   * Flush the current queue
   *
   * @param {Function} [callback] (optional)
   * @return {Analytics}
   */

  async flush (callback?): Promise<any> {
    callback = callback || noop

    if (!this.enable) {
      setImmediateFunc(callback)
      return await Promise.resolve()
    }

    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }

    if (!this.queue.length) {
      setImmediateFunc(callback)
      return await Promise.resolve()
    }

    try {
      if (this.pendingFlush) { await this.pendingFlush }
    } catch (err) {
      this.pendingFlush = null
      throw err
    }

    const items = this.queue.splice(0, this.flushAt)
    const callbacks = items.map(item => item.callback)
    const messages = items.map(item => item.message)

    const data = {
      batch: messages,
      timestamp: new Date(),
      sentAt: new Date()
    }

    const done = (err?): any => {
      setImmediateFunc(() => {
        callbacks.forEach(callback => callback(err, data))
        callback(err, data)
      })
    }

    // Don't set the user agent if we're on a browser. The latest spec allows
    // the User-Agent header (see https://fetch.spec.whatwg.org/#terminology-headers
    // and https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/setRequestHeader),
    // but browsers such as Chrome and Safari have not caught up.
    const headers = {}
    if (typeof window === 'undefined') {
      headers['user-agent'] = `analytics-node/${version}`
    }

    interface Req {
      auth: {
        username: string
      }
      headers: object
      timeout?: any
    }

    const req: Req = {
      auth: {
        username: this.writeKey
      },
      headers
    }

    if (this.timeout) {
      req.timeout = typeof this.timeout === 'string' ? ms(this.timeout) : this.timeout
    }

    return (this.pendingFlush = this.axiosInstance
      .post(`${this.host}${this.path}`, data, req)
      .then(async () => {
        done()
        return await Promise.resolve(data)
      })
      .catch(err => {
        if (typeof this.errorHandler === 'function') {
          done(err)
          return this.errorHandler(err)
        }

        if (err.response) {
          const error = new Error(err.response.statusText)
          done(error)
          throw error
        }

        done(err)
        throw err
      }))
  }

  _isErrorRetryable (error): boolean {
    // Retry Network Errors.
    if (axiosRetry.isNetworkError(error)) {
      return true
    }

    if (!error.response) {
      // Cannot determine if the request can be retried
      return false
    }

    // Retry Server Errors (5xx).
    if (error.response.status >= 500 && error.response.status <= 599) {
      return true
    }

    // Retry if rate limited.
    if (error.response.status === 429) {
      return true
    }

    return false
  }
}

module.exports = Analytics
