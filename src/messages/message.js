const assert = require('assert-plus');
const { BerWriter } = require('asn1');

let id = 0;
const nextID = () => {
  id = Math.max(1, (id + 1) % 2147483647);
  return id;
};

module.exports = class LDAPMessage {
  constructor(options) {
    assert.object(options);

    Object.assign(this, options, { messageID: options.messageID || nextID() });
  }

  get id() {
    return this.messageID;
  }

  get dn() {
    return this._dn || '';
  }

  get type() {
    return 'LDAPMessage';
  }

  parse(ber) {
    assert.ok(ber);

    this._parse(ber, ber.length);

    return true;
  }

  toBer() {
    let writer = new BerWriter();
    writer.startSequence();
    writer.writeInt(this.id);
    writer.startSequence(this.protocolOp);
    if (this._toBer) {
      writer = this._toBer(writer);
    }
    writer.endSequence();
    writer.endSequence();
    return writer.buffer;
  }
};
