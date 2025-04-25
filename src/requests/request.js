const asn1 = require('asn1');
const BerWriter = asn1.BerWriter;
const { LDAP_CONTROLS } = require('../utils/protocol');
const OID = require('../utils/OID');

let id = 0;
const nextID = () => {
  id = Math.max(1, (id + 1) % 2147483647);
  return id;
};

const controlToBer = (control, writer) => {
  writer.startSequence();
  writer.writeString(control.OID);
  writer.writeBoolean(control.criticality);

  const ber = new BerWriter();
  ber.startSequence();
  switch (control.OID) {
    case OID.PagedResults:
      ber.writeInt(control.value.size);
      if (control.value.cookie === '') {
        ber.writeString('');
      } else {
        ber.writeBuffer(control.value.cookie, asn1.Ber.OctetString);
      }
      break;
    // Add New OID controls here
    default:
  }

  ber.endSequence();
  writer.writeBuffer(ber.buffer, 0x04);

  writer.endSequence();
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

    if (this.controls.length > 0) {
      writer.startSequence(LDAP_CONTROLS);
      this.controls.array.forEach((control) => {
        controlToBer(control, writer);
      });
      writer.endSequence();
    }

    writer.endSequence();
    return writer.buffer;
  }

  _toBer(ber) {
    return ber;
  }
};
