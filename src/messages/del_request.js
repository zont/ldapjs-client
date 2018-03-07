const assert = require('assert-plus');
const LDAPMessage = require('./message');
const { LDAP_REQ_DELETE } = require('../protocol');
const lassert = require('../assert');

module.exports = class DeleteRequest extends LDAPMessage {
  constructor(options) {
    options = options || {};
    assert.object(options);
    lassert.optionalStringDN(options.entry);

    options.protocolOp = LDAP_REQ_DELETE;
    super(options);

    this.entry = options.entry || null;
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
