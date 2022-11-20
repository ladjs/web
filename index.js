const process = require('node:process');
const http = require('node:http');
const http2 = require('node:http2');
const path = require('node:path');
const util = require('node:util');
const zlib = require('node:zlib');

const Boom = require('@hapi/boom');
const CSRF = require('koa-csrf');
const Cabin = require('cabin');
const CacheResponses = require('@ladjs/koa-cache-responses');
const I18N = require('@ladjs/i18n');
const Koa = require('koa');
const Meta = require('koa-meta');
const Passport = require('@ladjs/passport');
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
const isajax = require('@ladjs/koa-isajax');
const json = require('koa-json');
const koa404Handler = require('koa-404-handler');
const koaCash = require('koa-cash');
const koaConnect = require('koa-connect');
const methodOverride = require('koa-methodoverride');
const ms = require('ms');
const ratelimit = require('@ladjs/koa-simple-ratelimit');
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

const INVALID_TOKEN_MESSAGE = 'Invalid CSRF token.';

class Web {
  // eslint-disable-next-line complexity
  constructor(config, Users) {
    const sharedWebConfig = sharedConfig('WEB');
    this.config = {
      ...sharedWebConfig,
      meta: {},
      views: {
        root: path.resolve('./app/views'),
        locals: {},
        options: {
          extension: 'pug'
        }
      },
      csrf: {
        ...sharedWebConfig.csrf,
        ignoredPathGlobs: ['/report'],
        errorHandler(ctx) {
          return ctx.throw(
            Boom.forbidden(
              typeof ctx.request.t === 'function'
                ? ctx.request.t(INVALID_TOKEN_MESSAGE)
                : INVALID_TOKEN_MESSAGE
            )
          );
        }
      },
      rateLimit: {
        ...sharedWebConfig.rateLimit,
        ignoredPathGlobs: ['/report']
      },
      sessionKeys: process.env.SESSION_KEYS
        ? process.env.SESSION_KEYS.split(',')
        : ['lad'],
      cookiesKey: process.env.COOKIES_KEY || 'lad.sid',
      favicon: {
        path: path.resolve('./assets/img/favicon.ico'),
        options: {}
      },
      buildDir: path.resolve('./build'),

      // <https://github.com/ladjs/koa-better-static#options>
      serveStatic: {},

      // <https://github.com/ladjs/koa-redirect-loop>
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
                reportUri: reportUri || null
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

    // initialize the app
    const app = new Koa();

    // only trust proxy if enabled
    app.proxy = boolean(process.env.TRUST_PROXY);

    // inherit cache variable for cache-pug-templates
    app.cache = boolean(this.config.views.locals.cache);

    // initialize cabin
    this.logger = _.isPlainObject(this.config.logger)
      ? new Cabin(this.config.logger)
      : this.config.logger instanceof Cabin
      ? this.config.logger
      : new Cabin({
          logger: this.config.logger || console
        });
    app.context.logger = this.logger;

    // initialize redis
    this.client =
      this.config.redis === false
        ? false
        : _.isPlainObject(this.config.redis)
        ? new Redis(this.config.redis, this.logger, this.config.redisMonitor)
        : this.config.redis;
    app.context.client = this.client;

    // expose passport
    this.passport =
      this.config.passport === false
        ? false
        : _.isPlainObject(this.config.passport)
        ? new Passport(this.config.passport, Users)
        : this.config.passport;
    app.context.passport = this.passport;

    // listen for errors emitted by app
    app.on('error', (err, ctx) => {
      ctx.logger[err.status && err.status < 500 ? 'warn' : 'error'](err);
    });

    // override koa's undocumented error handler
    app.context.onerror = errorHandler(this.config.cookiesKey);

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
    app.use(this.logger.middleware);

    // allow before hooks to get setup
    if (_.isFunction(this.config.hookBeforeSetup))
      this.config.hookBeforeSetup(app);

    // basic auth
    if (this.config.auth) app.use(auth(this.config.auth));

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
        : new I18N({ ...this.config.i18n, logger: this.logger });

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
      const meta = new Meta(this.config.meta, this.logger);
      app.use(meta.middleware);
    }

    // add dynamic view helpers
    const stateHelper = new StateHelper(this.config.views.locals);
    app.use(stateHelper.middleware);

    // session store
    app.keys = this.config.sessionKeys;
    app.use(
      session({
        ...this.config.session,
        ...(this.client
          ? {
              store: redisStore({ client: this.client })
            }
          : {}),
        key: this.config.cookiesKey,
        cookie: this.config.cookies,
        genSid: this.config.genSid
      })
    );

    // redirect loop (must come after sessions added)
    if (this.config.redirectLoop) {
      const redirectLoop = new RedirectLoop({
        ...this.config.redirectLoop,
        logger: this.logger
      });
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

    // csrf (with added localization support)
    if (this.config.csrf && process.env.NODE_ENV !== 'test') {
      const csrf = new CSRF(this.config.csrf);
      app.use(async (ctx, next) => {
        try {
          await csrf(ctx, next);
        } catch (err) {
          let error = err;
          if (err.name && err.name === 'ForbiddenError')
            error = Boom.forbidden(err.message);

          ctx.throw(error);
        }
      });
    }

    // passport
    if (this.passport) {
      app.use(this.passport.initialize());
      app.use(this.passport.session());
    }

    // add specific locals
    app.use((ctx, next) => {
      // passport-related helpers (e.g. for rendering log in with X buttons)
      ctx.state.passport = ctx.passport ? {} : false;
      if (
        ctx.passport &&
        ctx.passport.config &&
        ctx.passport.config.providers
      ) {
        for (const key of Object.keys(ctx.passport.config.providers)) {
          ctx.state.passport[key] = boolean(ctx.passport.config.providers[key]);
        }
      }

      // add limited `ctx` object to the state for views
      ctx.state.ctx = {};
      ctx.state.ctx.get = ctx.get.bind(ctx);
      ctx.state.ctx.locale = ctx.locale;
      ctx.state.ctx.path = ctx.path;
      ctx.state.ctx.pathWithoutLocale = ctx.pathWithoutLocale;
      ctx.state.ctx.query = ctx.query;
      ctx.state.ctx.sessionId = ctx.sessionId;
      ctx.state.ctx.url = ctx.url;

      return next();
    });

    // rate limiting
    if (this.client && this.config.rateLimit)
      app.use(
        ratelimit({
          ...this.config.rateLimit,
          db: this.client,
          logger: this.logger
        })
      );

    // store the user's last ip address in the background
    if (this.config.storeIPAddress) {
      const storeIPAddress = new StoreIPAddress({
        ...this.config.storeIPAddress,
        logger: this.logger
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

    // start server on either http or http2
    this.server =
      this.config.protocol === 'https'
        ? http2.createSecureServer(this.config.ssl, app.callback())
        : http.createServer(app.callback());

    // expose the app
    this.app = app;

    // bind listen/close to this
    this.listen = this.listen.bind(this);
    this.close = this.close.bind(this);
  }

  async listen(
    port = this.config.port,
    host = this.config.serverHost,
    ...args
  ) {
    await util.promisify(this.server.listen).bind(this.server)(
      port,
      host,
      ...args
    );
  }

  async close() {
    await util.promisify(this.server.close).bind(this.server);
  }
}

module.exports = Web;
