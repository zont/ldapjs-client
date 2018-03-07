const assert = require('assert-plus');
const LDAPMessage = require('./message');
const Change = require('../change');
const { LDAP_REQ_MODIFY } = require('../utils/protocol');
const lassert = require('../utils/assert');

module.exports = class ModifyRequest extends LDAPMessage {
  constructor(options) {
    lassert.optionalStringDN(options.object);
    lassert.optionalArrayOfAttribute(options.attributes);

    super(Object.assign({ protocolOp: LDAP_REQ_MODIFY }, options));
  }

  get type() {
    return 'ModifyRequest';
  }

  get _dn() {
    return this.object;
  }

  _parse(ber) {
    assert.ok(ber);

    this.object = ber.readString();

    ber.readSequence();
    const end = ber.offset + ber.length;
    while (ber.offset < end) {
      const c = new Change();
      c.parse(ber);
      c.modification.type = c.modification.type.toLowerCase();
      this.changes.push(c);
    }

    this.changes.sort(Change.compare);
    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.object.toString());
    ber.startSequence();
    this.changes.forEach(c => c.toBer(ber));
    ber.endSequence();

    return ber;
  }
};
