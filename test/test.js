const test = require('ava');
const request = require('supertest');
const Router = require('koa-router');
const Web = require('..');

test('allows custom routes', async t => {
  const router = new Router({ prefix: '/:locale' });

  router.get('/', ctx => {
    ctx.body = { ok: 'ok' };
  });

  const web = new Web({
    routes: router.routes()
  });

  const res = await request(web.server).get('/en');
  t.is(res.status, 200);
  t.is(res.body.ok, 'ok');
});
