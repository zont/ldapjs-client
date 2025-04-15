const { BerWriter } = require('asn1');
const controlToBer = require('../controls/controlToBer');
const { LDAP_CONTROLS } = require('../utils/protocol');

let id = 0;
const nextID = () => {
  id = Math.max(1, (id + 1) % 2147483647);
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
    
    if (this.controls.length > 0) {
      writer.startSequence(LDAP_CONTROLS);
      this.controls.forEach((control) => {
        controlToBer(control, writer);
      })
      writer.endSequence();
    }
    
    writer.endSequence();
    return writer.buffer;
  }

  _toBer(ber) {
    return ber;
  }
};
