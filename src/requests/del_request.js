const Request = require('./request');
const { LDAP_REQ_DELETE } = require('../utils/protocol');
const lassert = require('../utils/assert');

module.exports = class extends Request {
  constructor(options) {
    lassert.optionalStringDN(options.entry);

    super(Object.assign({ protocolOp: LDAP_REQ_DELETE, type: 'DeleteRequest' }, options));
  }

  _toBer(ber) {
    new Buffer(this.entry).forEach(i => ber.writeByte(i));

    return ber;
  }
};
