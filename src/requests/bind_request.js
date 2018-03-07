const { Ber: { Context } } = require('asn1');
const Request = require('./request');
const { LDAP_REQ_BIND, LDAP_VERSION_3 } = require('../utils/protocol');

module.exports = class extends Request {
  constructor(options) {
    super(Object.assign({ protocolOp: LDAP_REQ_BIND, credentials: '', type: 'BindRequest' }, options));
  }

  _toBer(ber) {
    ber.writeInt(LDAP_VERSION_3);
    ber.writeString(this.name);
    ber.writeString(this.credentials, Context);

    return ber;
  }
};
