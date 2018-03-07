const { BerWriter } = require('asn1');

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
    writer.endSequence();
    return writer.buffer;
  }

  _toBer(ber) {
    return ber;
  }
};
