const http = require('http');
const http2 = require('http2');
const path = require('path');
const util = require('util');

// const RedirectLoop = require('koa-redirect-loop');
const Boom = require('@hapi/boom');
const CSRF = require('koa-csrf');
const Cabin = require('cabin');
const CacheResponses = require('@ladjs/koa-cache-responses');
const I18N = require('@ladjs/i18n');
const Koa = require('koa');
const Meta = require('koa-meta');
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
const isajax = require('koa-isajax');
const json = require('koa-json');
const koa404Handler = require('koa-404-handler');
const koaCash = require('koa-cash');
const koaConnect = require('koa-connect');
const livereload = require('koa-livereload');
const methodOverride = require('koa-methodoverride');
const multimatch = require('multimatch');
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
      livereload: {
        port: process.env.LIVERELOAD_PORT
          ? parseInt(process.env.LIVERELOAD_PORT, 10)
          : 35729
      },
      favicon: {
        path: path.resolve('./assets/img/favicon.ico'),
        options: {}
      },
      buildDir: path.resolve('./build'),

      // <https://github.com/niftylettuce/koa-better-static#options>
      serveStatic: {},

      // <https://github.com/niftylettuce/koa-redirect-loop>
      // redirectLoop: {},

      // <https://github.com/koajs/cash>
      koaCash: false,

      // <https://github.com/ladjs/koa-cache-responses>
      cacheResponses: false,

      // <https://github.com/ladjs/bull>
      // this is an instance of bull passed to context
      // so users can use it in routes, e.g. `ctx.bull`
      bull: false,

      genSid() {
        return cryptoRandomString({ length: 32 });
      },

      ...config
    };

    const { logger } = this.config;

    let storeIPAddress = false;

    if (this.config.storeIPAddress)
      storeIPAddress = new StoreIPAddress({
        logger,
        ...this.config.storeIPAddress
      });

    const meta = new Meta(this.config.meta, logger);
    const stateHelper = new StateHelper(this.config.views.locals);
    let i18n = false;
    if (this.config.i18n) {
      i18n = this.config.i18n.config
        ? this.config.i18n
        : new I18N({ ...this.config.i18n, logger });
    }

    const cabin = new Cabin({
      logger,
      ...this.config.cabin
    });

    // initialize the app
    const app = new Koa();

    // initialize redis
    const client = new Redis(
      this.config.redis,
      logger,
      this.config.redisMonitor
    );

    // redirect loop
    // let redirectLoop = false;
    // if (this.config.redirectLoop)
    //   redirectLoop = new RedirectLoop(this.config.redirectLoop);

    // store the server initialization
    // so that we can gracefully exit
    // later on with `server.close()`
    let server;

    // override koa's undocumented error handler
    // <https://github.com/sindresorhus/eslint-plugin-unicorn/issues/174>
    app.context.onerror = errorHandler;

    // set bull to be shared throughout app context
    // (very useful for not creating additional connections)
    if (this.config.bull) app.context.bull = this.config.bull;

    // listen for error and log events emitted by app
    app.on('error', (err, ctx) => ctx.logger.error(err));
    app.on('log', logger.log);

    // allow before hooks to get setup
    if (_.isFunction(this.config.hookBeforeSetup))
      this.config.hookBeforeSetup(app);

    // inherit cache variable for cache-pug-templates
    app.cache = boolean(this.config.views.locals.cache);

    // only trust proxy if enabled
    app.proxy = boolean(process.env.TRUST_PROXY);

    // adds request received hrtime and date symbols to request object
    // (which is used by Cabin internally to add `request.timestamp` to logs
    app.use(requestReceived);

    // adds `X-Response-Time` header to responses
    app.use(koaConnect(responseTime()));

    // adds or re-uses `X-Request-Id` header
    app.use(koaConnect(requestId()));

    // add cabin middleware
    app.use(cabin.middleware);

    // compress/gzip
    app.use(compress());

    // cache support
    if (this.config.koaCash) app.use(koaCash(this.config.koaCash));

    // cache responses
    if (this.config.cacheResponses) {
      this.cacheResponses = new CacheResponses(this.config.cacheResponses);
      app.use(this.cacheResponses.middleware);
    }

    // favicons
    app.use(favicon(this.config.favicon.path, this.config.favicon.options));

    // serve static assets
    app.use(serveStatic(this.config.buildDir, this.config.serveStatic));

    // set template rendering engine
    app.use(
      views(
        this.config.views.root,
        _.extend(this.config.views.options, this.config.views.locals)
      )
    );

    // setup localization
    if (i18n) app.use(i18n.middleware);

    // livereload if we're in dev mode
    if (process.env.NODE_ENV === 'development')
      app.use(livereload(this.config.livereload));

    if (this.config.auth) app.use(auth(this.config.auth));

    // rate limiting
    if (this.config.rateLimit)
      app.use(
        ratelimit({
          ...this.config.rateLimit,
          db: client
        })
      );

    // conditional-get
    app.use(conditional());

    // etag
    app.use(etag());

    // cors
    if (this.config.cors) app.use(cors(this.config.cors));

    // security
    if (this.config.helmet) app.use(helmet(this.config.helmet));

    // remove trailing slashes
    app.use(removeTrailingSlashes());

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

    // redirect loop
    // if (redirectLoop) app.use(redirectLoop.middleware);

    // flash messages
    app.use(flash());

    // method override
    // (e.g. `<input type="hidden" name="_method" value="PUT" />`)
    app.use(methodOverride());

    // body parser
    app.use(bodyParser());

    // pretty-printed json responses
    app.use(json());

    // ajax request detection (sets `ctx.state.xhr` boolean)
    app.use(isajax());

    // 404 handler
    app.use(koa404Handler);

    app.use((ctx, next) => {
      // TODO: add cookies key until koa-better-error-handler issue is resolved
      // <https://github.com/koajs/generic-session/pull/95#issuecomment-246308544>
      ctx.state.cookiesKey = this.config.cookiesKey;
      return next();
    });

    // TODO: move this into `@ladjs/csrf`
    // csrf (with added localization support)
    if (this.config.csrf && process.env.NODE_ENV !== 'test') {
      const csrf = new CSRF({
        ...this.config.csrf,
        invalidTokenMessage: ctx => ctx.request.t('Invalid CSRF token')
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
          let e = err;
          if (err.name && err.name === 'ForbiddenError') {
            e = Boom.forbidden(err.message);
            if (err.stack) e.stack = err.stack;
          }

          ctx.throw(e);
        }
      });
    }

    // passport
    if (this.config.passport) {
      app.use(this.config.passport.initialize());
      app.use(this.config.passport.session());
    }

    // add dynamic view helpers
    app.use(stateHelper.middleware);

    // add support for SEO <title> and <meta name="description">
    app.use(meta.middleware);

    // configure timeout
    if (this.config.timeout) {
      const timeout = new Timeout(this.config.timeout);
      app.use(timeout.middleware);
    }

    // detect or redirect based off locale url
    if (i18n) app.use(i18n.redirect);

    // store the user's last ip address in the background
    if (storeIPAddress) app.use(storeIPAddress.middleware);

    // allow before hooks to get setup
    if (_.isFunction(this.config.hookBeforeRoutes))
      this.config.hookBeforeRoutes(app);

    // mount the app's defined and nested routes
    if (this.config.routes) {
      if (_.isFunction(this.config.routes.routes))
        app.use(this.config.routes.routes());
      else app.use(this.config.routes);
    }

    // start server on either http or https
    if (this.config.protocol === 'https')
      server = http2.createSecureServer(this.config.ssl, app.callback());
    else server = http.createServer(app.callback());

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
