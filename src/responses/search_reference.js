const assert = require('assert-plus');
const Response = require('./response');
const { LDAP_REP_SEARCH_REF } = require('../utils/protocol');
const { DN } = require('../dn');
const parseUrl = require('../utils/parse-url');

module.exports = class extends Response {
  constructor(options) {
    super(Object.assign({ protocolOp: LDAP_REP_SEARCH_REF, uris: [], type: 'SearchReference' }, options));
  }

  get dn() {
    return new DN();
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

  parse(ber) {
    const length = ber.length;

    while (ber.offset < length) {
      const _url = ber.readString();
      parseUrl(_url);
      this.uris.push(_url);
    }

    return true;
  }
};
