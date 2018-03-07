const assert = require('assert-plus');
const LDAPMessage = require('./message');
const { LDAP_REQ_DELETE } = require('../utils/protocol');
const lassert = require('../utils/assert');

module.exports = class DeleteRequest extends LDAPMessage {
  constructor(options) {
    lassert.optionalStringDN(options.entry);

    super(Object.assign({ protocolOp: LDAP_REQ_DELETE }, options));
  }

  get type() {
    return 'DeleteRequest';
  }

  get _dn() {
    return this.entry;
  }

  _parse(ber, length) {
    assert.ok(ber);

    this.entry = ber.buffer.slice(0, length).toString('utf8');
    ber._offset += ber.length;

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    new Buffer(this.entry.toString()).forEach(i => ber.writeByte(i));

    return ber;
  }
};
