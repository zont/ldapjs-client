const assert = require('assert-plus');
const LDAPMessage = require('./message');
const { LDAP_REQ_ABANDON } = require('../protocol');

module.exports = class AbandonRequest extends LDAPMessage {
  constructor(options) {
    options = options || {};
    assert.object(options);
    assert.optionalNumber(options.abandonID);

    options.protocolOp = LDAP_REQ_ABANDON;
    super(options);

    this.abandonID = options.abandonID || 0;
  }

  get type() {
    return 'AbandonRequest';
  }

  _parse(ber, length) {
    assert.ok(ber);
    assert.ok(length);

    const buf = ber.buffer;
    let offset = 0;
    let value = 0;

    const fb = buf[offset++];
    value = fb & 0x7F;
    for (let i = 1; i < length; ++i) {
      value <<= 8;
      value |= (buf[offset++] & 0xff);
    }
    if ((fb & 0x80) == 0x80)
      value = -value;

    ber._offset += length;

    this.abandonID = value;

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    let i = this.abandonID;
    let sz = 4;

    while ((((i & 0xff800000) === 0) || ((i & 0xff800000) === 0xff800000)) && sz > 1) {
      sz--;
      i <<= 8;
    }
    assert.ok(sz <= 4);

    while (sz-- > 0) {
      ber.writeByte((i & 0xff000000) >> 24);
      i <<= 8;
    }

    return ber;
  }

  _json(j) {
    assert.ok(j);

    j.abandonID = this.abandonID;

    return j;
  }
};
