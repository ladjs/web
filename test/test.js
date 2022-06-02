const Passport = require('@ladjs/passport');
const Router = require('@koa/router');
const request = require('supertest');
const test = require('ava');

const Web = require('..');

test('allows custom routes', async (t) => {
  const router = new Router({ prefix: '/:locale' });

  router.get('/', (ctx) => {
    ctx.body = { ok: 'ok' };
  });

  const web = new Web({
    routes: router.routes()
  });

  const response = await request(web.server).get('/en');
  t.is(response.status, 200);
  t.is(response.body.ok, 'ok');
});

test('default method override', async (t) => {
  const router = new Router();

  router.post('/', (ctx) => {
    ctx.body = { method: 'post' };
  });

  router.put('/', (ctx) => {
    ctx.body = { method: 'put' };
  });

  const web = new Web({
    routes: router.routes()
  });

  const response = await request(web.server)
    .post('/')
    .send({ _method: 'PUT' })
    .set('Accept', 'application/json');
  t.is(response.status, 200);
  t.is(response.body.method, 'put');
  t.is(response.request.method, 'POST');
});

test('with redis instance', (t) => {
  const api = new Web();
  t.is(typeof api.client, 'object');
  t.is(typeof api.app.context.client, 'object');
});

test('without redis instance', (t) => {
  const api = new Web({ redis: false });
  t.is(api.client, false);
  t.is(api.app.context.client, false);
});

test('with passport instance', (t) => {
  const passport = new Passport({});
  const api = new Web({ passport });
  t.is(typeof api.passport, 'object');
  t.is(typeof api.app.context.passport, 'object');
});

test('without passport instance', (t) => {
  const api = new Web();
  t.is(api.passport, false);
  t.is(api.app.context.passport, false);
});
