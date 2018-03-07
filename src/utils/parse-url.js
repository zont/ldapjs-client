const querystring = require('querystring');
const { parse } = require('url');
const assert = require('assert-plus');

const PROTOCOLS = ['ldap:', 'ldaps:'];
const SCOPES = ['base', 'one', 'sub'];

module.exports = str => {
  const u = parse(str);

  assert.ok(PROTOCOLS.includes(u.protocol), `Unsupported protocol: ${u.protocol}`);

  u.secure = u.protocol === 'ldaps:';
  u.host = u.hostname || 'localhost';
  u.port = u.port ? parseInt(u.port, 10) : u.secure ? 636 : 389;
  u.pathname = u.pathname ? querystring.unescape(u.pathname.substr(1)) : u.pathname;

  if (u.search) {
    const tmp = u.search.substr(1).split('?');
    if (tmp[0]) {
      u.attributes = tmp[0].split(',').map(a => querystring.unescape(a.trim()));
    }
    if (tmp[1]) {
      assert.ok(SCOPES.includes(tmp[1]), `Unsupported scope: ${tmp[1]}`);
      u.scope = tmp[1];
    }
    if (tmp[2]) {
      u.filter = querystring.unescape(tmp[2]);
    }
    if (tmp[3]) {
      u.extensions = querystring.unescape(tmp[3]);
    }

    u.attributes = u.attributes || [];
    u.scope = u.scope || 'base';
    u.filter = u.filter || '(objectclass=*)';
  }

  return u;
};
