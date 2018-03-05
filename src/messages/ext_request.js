const assert = require('assert-plus');
const LDAPMessage = require('./message');
const Protocol = require('../protocol');

module.exports = class ExtendedRequest extends LDAPMessage {
  constructor(options) {
    options = options || {};
    assert.object(options);
    assert.optionalString(options.requestName);
    assert.optionalBuffer(options.requestValue);
    assert.optionalString(options.requestValue);

    options.protocolOp = Protocol.LDAP_REQ_EXTENSION;
    super(options);

    this.requestName = options.requestName || '';
    this.requestValue = options.requestValue;
  }

  get type() {
    return 'ExtendedRequest';
  }

  get _dn() {
    return this.requestName;
  }

  get name() {
    return this.requestName;
  }

  set name(val) {
    assert.string(val);
    this.requestName = val;
  }

  get value() {
    return this.requestValue;
  }

  set value(val) {
    assert.ok(Buffer.isBuffer(val) || typeof val === 'string', 'value must be a buffer or a string');
    this.requestValue = val;
  }

  _parse(ber) {
    assert.ok(ber);

    this.requestName = ber.readString(0x80);
    if (ber.peek() === 0x81)
      try {
        this.requestValue = ber.readString(0x81);
      } catch (e) {
        this.requestValue = ber.readBuffer(0x81);
      }

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.requestName, 0x80);
    if (Buffer.isBuffer(this.requestValue)) {
      ber.writeBuffer(this.requestValue, 0x81);
    } else if (typeof (this.requestValue) === 'string') {
      ber.writeString(this.requestValue, 0x81);
    }

    return ber;
  }

  _json(j) {
    assert.ok(j);

    j.requestName = this.requestName;
    j.requestValue = (Buffer.isBuffer(this.requestValue)) ? this.requestValue.toString('hex') : this.requestValue;

    return j;
  }
};
