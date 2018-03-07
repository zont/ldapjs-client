const Request = require('./request');
const { LDAP_REQ_MODRDN } = require('../utils/protocol');
const lassert = require('../utils/assert');

module.exports = class extends Request {
  constructor(options) {
    lassert.optionalStringDN(options.entry);
    lassert.optionalDN(options.newRdn);
    lassert.optionalDN(options.newSuperior);

    super(Object.assign({ protocolOp: LDAP_REQ_MODRDN, deleteOldRdn: true, type: 'ModifyDNRequest' }, options));
  }

  _toBer(ber) {
    ber.writeString(this.entry);
    ber.writeString(this.newRdn.toString());
    ber.writeBoolean(this.deleteOldRdn);
    if (this.newSuperior) {
      const s = this.newSuperior.toString();
      const len = Buffer.byteLength(s);

      ber.writeByte(0x80); // MODIFY_DN_REQUEST_NEW_SUPERIOR_TAG
      ber.writeByte(len);
      ber._ensure(len);
      ber._buf.write(s, ber._offset);
      ber._offset += len;
    }

    return ber;
  }
};
