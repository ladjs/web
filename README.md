# [**@ladjs/web**](https://github.com/ladjs/web)

[![build status](https://img.shields.io/travis/ladjs/web.svg)](https://travis-ci.org/ladjs/web)
[![code coverage](https://img.shields.io/codecov/c/github/ladjs/web.svg)](https://codecov.io/gh/ladjs/web)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/ladjs/web.svg)](LICENSE)

> Web server for Lad


## Table of Contents

* [Install](#install)
* [Usage](#usage)
* [Contributors](#contributors)
* [License](#license)


## Install

[npm][]:

```sh
npm install @ladjs/web
```

[yarn][]:

```sh
yarn add @ladjs/web
```


## Usage

```js
#!/usr/bin/env node
const Server = require('@ladjs/web');
const Graceful = require('@ladjs/graceful');

const config = require('./config');
const routes = require('./routes');
const { i18n, logger } = require('./helpers');
const { Users } = require('./app/models');

const server = new Server({
  Users,
  routes: routes.web,
  logger,
  i18n,
  meta: config.meta,
  views: config.views
});

if (!module.parent) {
  server.listen();
  const graceful = new Graceful({ server, logger });
  graceful.listen();
}

module.exports = server;
```


## Contributors

| Name           | Website                    |
| -------------- | -------------------------- |
| **Nick Baugh** | <http://niftylettuce.com/> |


## License

[MIT](LICENSE) © [Nick Baugh](http://niftylettuce.com/)


## 

[npm]: https://www.npmjs.com/

[yarn]: https://yarnpkg.com/
