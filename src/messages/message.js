const assert = require('assert-plus');
const { BerWriter } = require('asn1');

module.exports = class LDAPMessage {
  constructor(options) {
    assert.object(options);

    this.messageID = options.messageID || 0;
    this.protocolOp = options.protocolOp || undefined;
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
    writer.writeInt(this.messageID);
    writer.startSequence(this.protocolOp);
    if (this._toBer) {
      writer = this._toBer(writer);
    }
    writer.endSequence();
    writer.endSequence();
    return writer.buffer;
  }
};
