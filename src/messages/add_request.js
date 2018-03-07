const assert = require('assert-plus');
const LDAPMessage = require('./message');
const Attribute = require('../attribute');
const { LDAP_REQ_ADD } = require('../protocol');
const lassert = require('../utils/assert');

module.exports = class AddRequest extends LDAPMessage {
  constructor(options) {
    lassert.optionalStringDN(options.entry);
    lassert.optionalArrayOfAttribute(options.attributes);

    super(Object.assign({ protocolOp: LDAP_REQ_ADD }, options));
  }

  get type() {
    return 'AddRequest';
  }

  get _dn() {
    return this.entry;
  }

  _parse(ber) {
    assert.ok(ber);

    this.entry = ber.readString();

    ber.readSequence();

    const end = ber.offset + ber.length;
    while (ber.offset < end) {
      const a = new Attribute();
      a.parse(ber);
      a.type = a.type.toLowerCase();
      if (a.type === 'objectclass') {
        a.vals = a.vals.map(i => i.toLowerCase());
      }
      this.attributes.push(a);
    }

    this.attributes.sort(Attribute.compare);
    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.entry.toString());
    ber.startSequence();
    this.attributes.forEach(a => a.toBer(ber));
    ber.endSequence();

    return ber;
  }
};
