const assert = require('assert-plus');
const LDAPMessage = require('./message');
const { LDAP_REP_SEARCH_REF } = require('../protocol');
const { DN } = require('../dn');
const parseUrl = require('../utils/parse-url');

module.exports = class SearchReference extends LDAPMessage {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REP_SEARCH_REF}));

    this.uris = options.uris || [];
  }

  get type() {
    return 'SearchReference';
  }

  get _dn() {
    return new DN('');
  }

  get object() {
    return {
      dn: this.dn.toString(),
      uris: this.uris.slice()
    };
  }

  get urls() {
    return this.uris;
  }

  set ulrs(val) {
    assert.ok(val);
    assert.ok(Array.isArray(val));
    this.uris = val.slice();
  }

  toObject() {
    return this.object;
  }

  fromObject(obj) {
    assert.object(obj);

    this.uris = obj.uris ? obj.uris.slice() : [];

    return true;
  }

  _parse(ber, length) {
    assert.ok(ber);

    while (ber.offset < length) {
      const _url = ber.readString();
      parseUrl(_url);
      this.uris.push(_url);
    }

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    this.uris.forEach(u => ber.writeString(u.href || u));

    return ber;
  }
};
