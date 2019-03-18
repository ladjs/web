const http = require('http');
const https = require('https');
const path = require('path');

const Boom = require('boom');
const CSRF = require('koa-csrf');
const Cabin = require('cabin');
const I18N = require('@ladjs/i18n');
const Koa = require('koa');
const Meta = require('koa-meta');
const RedisStore = require('koa-redis');
const StateHelper = require('@ladjs/state-helper');
const StoreIPAddress = require('@ladjs/store-ip-address');
const Timeout = require('koa-better-timeout');
const _ = require('lodash');
const auth = require('koa-basic-auth');
const autoBind = require('auto-bind');
const bodyParser = require('koa-bodyparser');
const boolean = require('boolean');
const compress = require('koa-compress');
const conditional = require('koa-conditional-get');
const cors = require('kcors');
const errorHandler = require('koa-better-error-handler');
const etag = require('koa-etag');
const favicon = require('koa-favicon');
const flash = require('koa-better-flash');
const helmet = require('koa-helmet');
const ip = require('ip');
const isajax = require('koa-isajax');
const json = require('koa-json');
const koa404Handler = require('koa-404-handler');
const koaConnect = require('koa-connect');
const koaManifestRev = require('koa-manifest-rev');
const livereload = require('koa-livereload');
const methodOverride = require('koa-methodoverride');
const rateLimiter = require('koa-simple-ratelimit');
const redis = require('redis');
const removeTrailingSlashes = require('koa-no-trailing-slash');
const requestId = require('express-request-id');
const responseTime = require('response-time');
const serveStatic = require('@ladjs/koa-better-static');
const session = require('koa-generic-session');
const views = require('koa-views');
const sharedConfig = require('@ladjs/shared-config');

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
      sessionKeys: process.env.SESSION_KEYS
        ? process.env.SESSION_KEYS.split(',')
        : ['lad'],
      cookiesKey: process.env.COOKIES_KEY || 'lad.sid',
      // <https://github.com/pillarjs/cookies#cookiesset-name--value---options-->
      // <https://github.com/koajs/generic-session/blob/master/src/session.js#L32-L38>
      cookies: {
        httpOnly: true,
        path: '/',
        overwrite: true,
        signed: true,
        maxAge: 24 * 60 * 60 * 1000,
        secure: process.env.WEB_PROTOCOL === 'https',
        // we use SameSite cookie support as an alternative to CSRF
        // <https://scotthelme.co.uk/csrf-is-dead/>
        sameSite: 'lax'
      },
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
      koaManifestRev: {
        manifest: path.resolve('../build/rev-manifest.json'),
        prepend:
          process.env.AWS_CF_DOMAIN && process.env.NODE_ENV === 'production'
            ? `//${process.env.AWS_CF_DOMAIN}/`
            : '/'
      },
      ...config
    };

    const { logger } = this.config;
    const storeIPAddress = new StoreIPAddress({ logger });
    const meta = new Meta(this.config.meta);
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

    // connect to redis
    const redisClient = redis.createClient(
      process.env.REDIS_URL || 'redis://localhost:6379'
    );
    // handle connect and error events
    redisClient.on('connect', () =>
      app.emit('log', 'debug', 'redis connected')
    );
    redisClient.on('error', err => app.emit('error', err));

    // initialize redis store
    const redisStore = new RedisStore({
      client: redisClient
    });

    // store the server initialization
    // so that we can gracefully exit
    // later on with `server.close()`
    let server;

    // override koa's undocumented error handler
    // <https://github.com/sindresorhus/eslint-plugin-unicorn/issues/174>
    // eslint-disable-next-line unicorn/prefer-add-event-listener
    app.context.onerror = errorHandler;

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

    // adds `X-Response-Time` header to responses
    app.use(koaConnect(responseTime));

    // adds or re-uses `X-Request-Id` header
    app.use(koaConnect(requestId()));

    // add cabin middleware
    app.use(cabin.middleware);

    // compress/gzip
    app.use(compress());

    // favicons
    app.use(favicon(this.config.favicon.path, this.config.favicon.options));

    // serve static assets
    app.use(serveStatic(this.config.buildDir, this.config.serveStatic));

    // koa-manifest-rev
    app.use(koaManifestRev(this.config.koaManifestRev));

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
        rateLimiter({
          ...this.config.rateLimit,
          db: redisClient
        })
      );

    // conditional-get
    app.use(conditional());

    // etag
    app.use(etag());

    // cors
    if (this.config.cors) app.use(cors(this.config.cors));

    // security
    app.use(helmet());

    // remove trailing slashes
    app.use(removeTrailingSlashes());

    // session store
    app.keys = this.config.sessionKeys;
    app.use(
      session({
        store: redisStore,
        key: this.config.cookiesKey,
        cookie: this.config.cookies
      })
    );

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

    // csrf (with added localization support)
    if (this.config.csrf && process.env.NODE_ENV !== 'test') {
      const csrf = new CSRF({
        ...this.config.csrf,
        invalidTokenMessage: ctx => ctx.request.t('Invalid CSRF token')
      });
      app.use(async (ctx, next) => {
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
    app.use(storeIPAddress.middleware);

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
      server = https.createServer(this.config.ssl, app.callback());
    else server = http.createServer(app.callback());

    // expose app and server
    this.app = app;
    this.server = server;

    autoBind(this);
  }

  listen(port, fn) {
    if (_.isFunction(port)) {
      fn = port;
      port = null;
    }

    const { logger } = this.config;
    if (!_.isFunction(fn))
      fn = function() {
        const { port } = this.address();
        logger.info(
          `Lad web server listening on ${port} (LAN: ${ip.address()}:${port})`
        );
      };

    this.server = this.server.listen(port, fn);
    return this.server;
  }

  close(fn) {
    this.server.close(fn);
    return this;
  }
}

module.exports = Web;
