const http = require('http');
const https = require('https');
// const http2 = require('http2');
const path = require('path');
const util = require('util');
const zlib = require('zlib');

const Boom = require('@hapi/boom');
const CSRF = require('koa-csrf');
const Cabin = require('cabin');
const CacheResponses = require('@ladjs/koa-cache-responses');
const I18N = require('@ladjs/i18n');
const Koa = require('koa');
const Meta = require('koa-meta');
const RedirectLoop = require('koa-redirect-loop');
const Redis = require('@ladjs/redis');
const StateHelper = require('@ladjs/state-helper');
const StoreIPAddress = require('@ladjs/store-ip-address');
const Timeout = require('koa-better-timeout');
const _ = require('lodash');
const auth = require('koa-basic-auth');
const bodyParser = require('koa-bodyparser');
const compress = require('koa-compress');
const conditional = require('koa-conditional-get');
const cors = require('kcors');
const cryptoRandomString = require('crypto-random-string');
const errorHandler = require('koa-better-error-handler');
const etag = require('koa-etag');
const favicon = require('koa-favicon');
const flash = require('koa-better-flash');
const helmet = require('koa-helmet');
const isSANB = require('is-string-and-not-blank');
const isajax = require('koa-isajax');
const json = require('koa-json');
const koa404Handler = require('koa-404-handler');
const koaCash = require('koa-cash');
const koaConnect = require('koa-connect');
const methodOverride = require('koa-methodoverride');
const ms = require('ms');
const multimatch = require('multimatch');
const proxyWrap = require('findhit-proxywrap');
const redisStore = require('koa-redis');
const removeTrailingSlashes = require('koa-no-trailing-slash');
const requestId = require('express-request-id');
const requestReceived = require('request-received');
const responseTime = require('response-time');
const serveStatic = require('@ladjs/koa-better-static');
const session = require('koa-generic-session');
const sharedConfig = require('@ladjs/shared-config');
const views = require('koa-views');
const { boolean } = require('boolean');
const { ratelimit } = require('koa-simple-ratelimit');

const proxiedHttp = proxyWrap.proxy(http);
const proxiedHttps = proxyWrap.proxy(https);

const defaultSrc = isSANB(process.env.WEB_HOST)
  ? [
      "'self'",
      'data:',
      `*.${process.env.WEB_HOST}`,
      `*.${process.env.WEB_HOST}:*`,
      process.env.WEB_HOST,
      `${process.env.WEB_HOST}:*`
    ]
  : null;
const reportUri = isSANB(process.env.WEB_URL)
  ? `${process.env.WEB_URL}/report`
  : null;

class Web {
  // eslint-disable-next-line complexity
  constructor(config) {
    this.config = {
      ...sharedConfig('WEB'),
      meta: {},
      views: {
        root: path.resolve('./app/views'),
        locals: {},
        options: {
          extension: 'pug'
        }
      },
      csrf: {},
      csrfIgnoredGlobs: ['/report'],
      sessionKeys: process.env.SESSION_KEYS
        ? process.env.SESSION_KEYS.split(',')
        : ['lad'],
      cookiesKey: process.env.COOKIES_KEY || 'lad.sid',
      favicon: {
        path: path.resolve('./assets/img/favicon.ico'),
        options: {}
      },
      buildDir: path.resolve('./build'),

      // <https://github.com/niftylettuce/koa-better-static#options>
      serveStatic: {},

      // <https://github.com/niftylettuce/koa-redirect-loop>
      redirectLoop: {},

      // <https://github.com/koajs/cash>
      koaCash: false,

      // <https://github.com/ladjs/koa-cache-responses>
      cacheResponses: false,

      genSid() {
        return cryptoRandomString.async({ length: 32 });
      },

      methodOverride: [
        (request) => {
          const { _method } = request.body;
          if (_method && typeof _method === 'string') return _method;
        }
      ],

      helmet: {
        contentSecurityPolicy: defaultSrc
          ? {
              directives: {
                defaultSrc,
                connectSrc: defaultSrc,
                fontSrc: defaultSrc,
                imgSrc: defaultSrc,
                styleSrc: [...defaultSrc, "'unsafe-inline'"],
                scriptSrc: [...defaultSrc, "'unsafe-inline'"],
                reportUri: reportUri ? reportUri : null
              }
            }
          : null,
        expectCt: {
          enforce: true,
          // https://httpwg.org/http-extensions/expect-ct.html#maximum-max-age
          maxAge: ms('30d') / 1000,
          reportUri
        },
        // <https://hstspreload.org/>
        // <https://helmetjs.github.io/docs/hsts/#preloading-hsts-in-chrome>
        hsts: {
          // must be at least 1 year to be approved
          maxAge: ms('1y') / 1000,
          // must be enabled to be approved
          includeSubDomains: true,
          preload: true
        },
        // <https://helmetjs.github.io/docs/referrer-policy>
        // <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>
        referrerPolicy: {
          policy: 'same-origin'
        },
        xssFilter: {
          reportUri
        }
      },

      // https://github.com/koajs/compress
      compress: {
        br: {
          params: {
            [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
            [zlib.constants.BROTLI_PARAM_QUALITY]: 4
          }
        }
      },

      ...config
    };

    const cabin = new Cabin({
      logger: this.config.logger,
      ...this.config.cabin
    });

    // initialize the app
    const app = new Koa();

    // listen for error and log events emitted by app
    app.on('error', (err, ctx) => {
      const level = err.status && err.status < 500 ? 'warn' : 'error';
      if (ctx.logger) ctx.logger[level](err);
      else cabin[level](err);
    });
    app.on('log', cabin.log);

    // initialize redis
    const client = new Redis(
      this.config.redis,
      cabin,
      this.config.redisMonitor
    );

    // allow middleware to access redis client
    app.context.client = client;

    // override koa's undocumented error handler
    app.context.onerror = errorHandler(this.config.cookiesKey, cabin);

    // only trust proxy if enabled
    app.proxy = boolean(process.env.TRUST_PROXY);

    // inherit cache variable for cache-pug-templates
    app.cache = boolean(this.config.views.locals.cache);

    // adds request received hrtime and date symbols to request object
    // (which is used by Cabin internally to add `request.timestamp` to logs
    app.use(requestReceived);

    // configure timeout
    if (this.config.timeout) {
      const timeout = new Timeout(this.config.timeout);
      app.use(timeout.middleware);
    }

    // adds `X-Response-Time` header to responses
    app.use(koaConnect(responseTime()));

    // adds or re-uses `X-Request-Id` header
    app.use(koaConnect(requestId()));

    // add cabin middleware
    app.use(cabin.middleware);

    // allow before hooks to get setup
    if (_.isFunction(this.config.hookBeforeSetup))
      this.config.hookBeforeSetup(app);

    // basic auth
    if (this.config.auth) app.use(auth(this.config.auth));

    // rate limiting
    if (this.config.rateLimit)
      app.use(
        ratelimit({
          ...this.config.rateLimit,
          db: client
        })
      );

    // remove trailing slashes
    app.use(removeTrailingSlashes());

    // security
    // (needs to come before i18n so HSTS header gets added)
    if (this.config.helmet) app.use(helmet(this.config.helmet));

    // i18n
    if (this.config.i18n) {
      // create new @ladjs/i18n instance
      const i18n = this.config.i18n.config
        ? this.config.i18n
        : new I18N({ ...this.config.i18n, logger: cabin });

      // setup localization (must come before `i18n.redirect`)
      app.use(i18n.middleware);

      // detect or redirect based off locale url
      app.use(i18n.redirect);
    }

    // conditional-get
    app.use(conditional());

    // etag
    app.use(etag());

    // cors
    if (this.config.cors) app.use(cors(this.config.cors));

    // compress/gzip
    if (this.config.compress) app.use(compress(this.config.compress));

    // cache support
    if (this.config.koaCash) app.use(koaCash(this.config.koaCash));

    // cache responses
    if (this.config.cacheResponses) {
      this.cacheResponses = new CacheResponses(this.config.cacheResponses);
      app.use(this.cacheResponses.middleware);
    }

    // favicons
    if (this.config.favicon)
      app.use(favicon(this.config.favicon.path, this.config.favicon.options));

    // serve static assets
    if (this.config.buildDir && this.config.serveStatic)
      app.use(serveStatic(this.config.buildDir, this.config.serveStatic));

    // set template rendering engine
    app.use(
      views(
        this.config.views.root,
        _.extend(this.config.views.options, this.config.views.locals)
      )
    );

    // ajax request detection (sets `ctx.state.xhr` boolean)
    app.use(isajax());

    //
    // add support for SEO <title> and <meta name="description">
    //
    // NOTE: this must come after ctx.render is added (via koa-views)
    //
    if (this.config.meta) {
      const meta = new Meta(this.config.meta, cabin);
      app.use(meta.middleware);
    }

    // add dynamic view helpers
    const stateHelper = new StateHelper(this.config.views.locals);
    app.use(stateHelper.middleware);

    // session store
    app.keys = this.config.sessionKeys;
    app.use(
      session({
        store: redisStore({ client }),
        key: this.config.cookiesKey,
        cookie: this.config.cookies,
        genSid: this.config.genSid
      })
    );

    // redirect loop (must come after sessions added)
    if (this.config.redirectLoop) {
      const redirectLoop = new RedirectLoop(this.config.redirectLoop);
      app.use(redirectLoop.middleware);
    }

    // flash messages (must come after sessions added)
    app.use(flash());

    // body parser
    app.use(bodyParser());

    // pretty-printed json responses
    app.use(json());

    // method override
    // (e.g. `<input type="hidden" name="_method" value="PUT" />`)
    if (this.config.methodOverride)
      app.use(methodOverride(...this.config.methodOverride));

    // TODO: move this into `@ladjs/csrf`
    // csrf (with added localization support)
    if (this.config.csrf && process.env.NODE_ENV !== 'test') {
      const csrf = new CSRF({
        ...this.config.csrf,
        invalidTokenMessage: (ctx) => ctx.request.t('Invalid CSRF token')
      });
      app.use(async (ctx, next) => {
        // check against ignored/whitelisted redirect middleware paths
        if (
          Array.isArray(this.config.csrfIgnoredGlobs) &&
          this.config.csrfIgnoredGlobs.length > 0
        ) {
          const match = multimatch(ctx.path, this.config.csrfIgnoredGlobs);
          if (Array.isArray(match) && match.length > 0) return next();
        }

        try {
          await csrf(ctx, next);
        } catch (err) {
          let error = err;
          if (err.name && err.name === 'ForbiddenError') {
            error = Boom.forbidden(err.message);
            if (err.stack) error.stack = err.stack;
          }

          ctx.throw(error);
        }
      });
    }

    // passport
    if (this.config.passport) {
      app.use(this.config.passport.initialize());
      app.use(this.config.passport.session());
    }

    // store the user's last ip address in the background
    if (this.config.storeIPAddress) {
      const storeIPAddress = new StoreIPAddress({
        logger: cabin,
        ...this.config.storeIPAddress
      });
      app.use(storeIPAddress.middleware);
    }

    // 404 handler
    app.use(koa404Handler);

    // allow before hooks to get setup
    if (_.isFunction(this.config.hookBeforeRoutes))
      this.config.hookBeforeRoutes(app);

    // mount the app's defined and nested routes
    if (this.config.routes) {
      if (_.isFunction(this.config.routes.routes))
        app.use(this.config.routes.routes());
      else app.use(this.config.routes);
    }

    const createServer =
      this.config.protocol === 'https'
        ? this.config.proxyProtocol
          ? proxiedHttps.createServer
          : https.createServer
        : this.config.proxyProtocol
        ? proxiedHttp.createServer
        : http.createServer;

    // start server on either http or https
    const server =
      this.config.protocol === 'https'
        ? createServer(this.config.ssl, app.callback())
        : createServer(app.callback());

    // expose app, server, client
    this.app = app;
    this.server = server;
    this.client = client;

    // bind listen/close to this
    this.listen = this.listen.bind(this);
    this.close = this.close.bind(this);
  }

  async listen(port) {
    await util.promisify(this.server.listen).bind(this.server)(port);
  }

  async close() {
    await util.promisify(this.server.close).bind(this.server);
  }
}

module.exports = Web;
