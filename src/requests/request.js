const { BerWriter } = require('asn1');
const { LDAP_CONTROLS } = require('../utils/protocol');
const { SIMPLE_PAGED_RESULTS } = require('../utils/ldapoid');

const MAX_INT = 2147483647; // 2**31-1
let id = 0;
const nextID = () => {
  id = Math.max(1, (id + 1) % MAX_INT);
  return id;
};

module.exports = class {
  constructor(options) {
    Object.assign(this, options, { id: nextID() });
  }

  toBer() {
    let writer = new BerWriter();
    writer.startSequence();
    writer.writeInt(this.id);
    writer.startSequence(this.protocolOp);
    writer = this._toBer(writer);
    writer.endSequence();
    // add pagination control if sizeLimit is set
    if (this.sizeLimit > 0 && this.sizeLimit <= MAX_INT) {
      writer.startSequence(LDAP_CONTROLS);
      writer.startSequence(); // Control
      writer.writeString(SIMPLE_PAGED_RESULTS);

      // search control value
      // reference https://docs.ldap.com/specs/rfc2696.txt
      let tmpWriter = new BerWriter();
      tmpWriter.startSequence();
      tmpWriter.writeInt(this.sizeLimit); // might need to assert this is a number
      tmpWriter.writeString(this.cookie);

      tmpWriter.endSequence(); // end control value
      let controlValue = tmpWriter.buffer.toString('binary'); // control value is a BER encoded string
      writer.writeString(controlValue);

      writer.endSequence(); // End of Control
      writer.endSequence(); // End of LDAP Controls
    }
    writer.endSequence();
    return writer.buffer;
  }

  _toBer(ber) {
    return ber;
  }
};
