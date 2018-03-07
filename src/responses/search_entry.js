const assert = require('assert-plus');
const Response = require('./response');
const Attribute = require('../attribute');
const { LDAP_REP_SEARCH_ENTRY } = require('../utils/protocol');

module.exports = class extends Response {
  constructor(options) {
    super(Object.assign({ protocolOp: LDAP_REP_SEARCH_ENTRY, type: 'SearchEntry', attributes: [] }, options));
  }

  get object() {
    return this.attributes.reduce((obj, a) => {
      obj[a.type] = a.vals && a.vals.length ? a.vals.length > 1 ? a.vals.slice() : a.vals[0] : [];
      return obj;
    }, { dn: this.objectName });
  }

  parse(ber) {
    this.objectName = ber.readString();

    assert.ok(ber.readSequence());

    const end = ber.offset + ber.length;
    while (ber.offset < end) {
      const a = new Attribute();
      a.parse(ber);
      this.attributes.push(a);
    }

    return true;
  }
};
