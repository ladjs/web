const test = require('ava');
const request = require('supertest');
const Router = require('@koa/router');
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
