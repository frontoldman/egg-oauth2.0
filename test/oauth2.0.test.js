'use strict';

const mock = require('egg-mock');

describe('test/oauth2.0.test.js', () => {
  let app;
  before(() => {
    app = mock.app({
      baseDir: 'apps/oauth2.0-test',
    });
    return app.ready();
  });

  after(() => app.close());
  afterEach(mock.restore);

  it('should GET /', () => {
    return app.httpRequest()
      .get('/')
      .expect('hi, oauth20')
      .expect(200);
  });
});
