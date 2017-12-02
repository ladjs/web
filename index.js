const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const autoBind = require('auto-bind');
const _ = require('lodash');
const Boom = require('boom');
const Koa = require('koa');
const Cabin = require('cabin');
const livereload = require('koa-livereload');
const boolean = require('boolean');
const favicon = require('koa-favicon');
const koaManifestRev = require('koa-manifest-rev');
const serveStatic = require('@ladjs/koa-better-static');
const conditional = require('koa-conditional-get');
const etag = require('koa-etag');
const compress = require('koa-compress');
const responseTime = require('koa-response-time');
const rateLimit = require('koa-simple-ratelimit');
const views = require('koa-views');
const koaLogger = require('koa-logger');
const methodOverride = require('koa-methodoverride');
const bodyParser = require('koa-bodyparser');
const koa404Handler = require('koa-404-handler');
const json = require('koa-json');
const errorHandler = require('koa-better-error-handler');
const helmet = require('koa-helmet');
const cors = require('kcors');
const removeTrailingSlashes = require('koa-no-trailing-slash');
const redis = require('redis');
const RedisStore = require('koa-redis');
const session = require('koa-generic-session');
const flash = require('koa-better-flash');
const CSRF = require('koa-csrf');
const StoreIPAddress = require('@ladjs/store-ip-address');
const isajax = require('koa-isajax');
const ip = require('ip');
const Meta = require('koa-meta');
const Timeout = require('koa-better-timeout');
const I18N = require('@ladjs/i18n');
const Auth = require('@ladjs/auth');
const StateHelper = require('@ladjs/state-helper');

class Server {
  // eslint-disable-next-line complexity
  constructor(config) {
    this.config = Object.assign(
      {
        cabin: {},
        protocol: process.env.WEB_PROTOCOL || 'http',
        ssl: {
          key: process.env.WEB_SSL_KEY_PATH
            ? fs.readFileSync(process.env.WEB_SSL_KEY_PATH)
            : null,
          cert: process.env.WEB_SSL_CERT_PATH
            ? fs.readFileSync(process.env.WEB_SSL_CERT_PATH)
            : null,
          ca: process.env.WEB_SSL_CA_PATH
            ? fs.readFileSync(process.env.WEB_SSL_CA_PATH)
            : null
        },
        Users: false,
        routes: false,
        logger: console,
        i18n: {},
        meta: {},
        auth: {},
        rateLimit: {
          duration: 60000,
          max: process.env.RATELIMIT_MAX || 100,
          id: ctx => ctx.ip
        },
        // <https://github.com/koajs/cors#corsoptions>
        cors: {},
        timeoutMs: process.env.WEB_TIMEOUT_MS || 3000,
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
        livereload: {
          port: process.env.LIVERELOAD_PORT || 35729
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
        }
      },
      config
    );

    const { logger } = this.config;
    const storeIPAddress = new StoreIPAddress({ logger });
    const meta = new Meta(this.config.meta);
    const stateHelper = new StateHelper(this.config.views.locals);
    const i18n = this.config.i18n.config
      ? this.config.i18n
      : new I18N({ ...this.config.i18n, logger });
    const cabin = new Cabin(this.config.cabin);

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

    app.on('error', logger.contextError || logger.error);
    app.on('log', logger.log);

    // inherit cache variable for cache-pug-templates
    app.cache = boolean(this.config.views.locals.cache);

    // only trust proxy if enabled
    app.proxy = boolean(process.env.TRUST_PROXY);

    // compress/gzip
    app.use(compress());

    // favicons
    app.use(favicon(this.config.favicon.path, this.config.favicon.options));

    // serve static assets
    // TODO: <https://github.com/tunnckoCore/koa-better-serve/issues/13>
    app.use(serveStatic(this.config.buildDir, this.config.serveStatic));

    // koa-manifest-rev
    app.use(koaManifestRev(this.config.koaManifestRev));

    // setup localization
    app.use(i18n.middleware);

    // set template rendering engine
    app.use(
      views(
        this.config.views.root,
        _.extend(this.config.views.options, this.config.views.locals)
      )
    );

    // livereload if we're in dev mode
    if (process.env.NODE_ENV === 'development')
      app.use(livereload(this.config.livereload));

    // override koa's undocumented error handler
    app.context.onerror = errorHandler;

    // response time
    app.use(responseTime());

    // add the logger for development environment only
    // TODO: there's a weird logger issue, see this GH issue
    // <https://github.com/koajs/logger/issues/49>
    if (process.env.NODE_ENV === 'development') app.use(koaLogger());

    // rate limiting
    app.use(
      rateLimit({
        ...this.config.rateLimit,
        db: redisClient
      })
    );

    // conditional-get
    app.use(conditional());

    // etag
    app.use(etag());

    // cors
    app.use(cors(this.config.cors));

    // TODO: add `cors-gate`
    // <https://github.com/mixmaxhq/cors-gate/issues/6>

    // security
    app.use(helmet());

    // remove trailing slashes
    app.use(removeTrailingSlashes());

    // session store
    app.keys = this.config.sessionKeys;
    app.use(session({ store: redisStore, key: this.config.cookiesKey }));

    // flash messages
    app.use(flash());

    // method override
    // (e.g. `<input type="hidden" name="_method" value="PUT" />`)
    app.use(methodOverride());

    // body parser
    app.use(bodyParser());

    // pretty-printed json responses
    app.use(json());

    // add cabin middleware
    app.use(cabin.middleware);

    // ajax request detection (sets `ctx.state.xhr` boolean)
    app.use(isajax());

    // 404 handler
    app.use(koa404Handler);

    // csrf (with added localization support)
    app.use((ctx, next) => {
      // TODO: add cookies key until koa-better-error-handler issue is resolved
      // <https://github.com/koajs/generic-session/pull/95#issuecomment-246308544>
      ctx.state.cookiesKey = this.config.cookiesKey;
      return next();
    });
    app.use(async (ctx, next) => {
      if (process.env.NODE_ENV === 'test') {
        logger.debug(`Skipping CSRF`);
        return next();
      }

      try {
        await new CSRF({
          ...this.config.csrf,
          invalidSessionSecretMessage: ctx.translate('INVALID_SESSION_SECRET'),
          invalidTokenMessage: ctx.translate('INVALID_TOKEN')
        })(ctx, next);
      } catch (err) {
        let e = err;
        if (err.name && err.name === 'ForbiddenError') {
          e = Boom.forbidden(err.message);
          if (err.stack) e.stack = err.stack;
        }
        ctx.throw(e);
      }
    });

    // auth
    if (this.config.Users) {
      const auth = new Auth(this.config.Users, this.config.auth);
      app.use(auth.passport.initialize());
      app.use(auth.passport.session());
    }

    // add dynamic view helpers
    app.use(stateHelper.middleware);

    // add support for SEO <title> and <meta name="description">
    app.use(meta.middleware);

    // configure timeout
    app.use(async (ctx, next) => {
      try {
        const timeout = new Timeout({
          ms: this.config.timeoutMs,
          message: ctx.translate('REQUEST_TIMED_OUT')
        });
        await timeout.middleware(ctx, next);
      } catch (err) {
        ctx.throw(err);
      }
    });

    // detect or redirect based off locale url
    app.use(i18n.redirect);

    // store the user's last ip address in the background
    app.use(storeIPAddress.middleware);

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
          `web server listening on ${port} (LAN: ${ip.address()}:${port})`
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

module.exports = Server;
