const Request = require('./request');
const { LDAP_REQ_MODIFY } = require('../utils/protocol');
const lassert = require('../utils/assert');

module.exports = class extends Request {
  constructor(options) {
    lassert.optionalStringDN(options.entry);
    lassert.optionalArrayOfAttribute(options.attributes);

    super(Object.assign({ protocolOp: LDAP_REQ_MODIFY, type: 'ModifyRequest' }, options));
  }

  _toBer(ber) {
    ber.writeString(this.entry);
    ber.startSequence();
    this.changes.forEach(c => c.toBer(ber));
    ber.endSequence();

    return ber;
  }
};
