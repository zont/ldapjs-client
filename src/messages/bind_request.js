const assert = require('assert-plus');
const { Ber: { Context } } = require('asn1');
const LDAPMessage = require('./message');
const { LDAP_REQ_BIND } = require('../protocol');
const LDAP_BIND_SIMPLE = 'simple';

module.exports = class BindRequest extends LDAPMessage {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REQ_BIND}));

    this.version = options.version || 0x03;
    this.name = options.name || null;
    this.authentication = options.authentication || LDAP_BIND_SIMPLE;
    this.credentials = options.credentials || '';
  }

  get type() {
    return 'BindRequest';
  }

  get _dn() {
    return this.name;
  }

  _parse(ber) {
    assert.ok(ber);

    this.version = ber.readInt();
    this.name = ber.readString();

    const t = ber.peek();

    assert.ok(t === Context, `Authentication 0x${t.toString(16)} not supported`);

    this.authentication = LDAP_BIND_SIMPLE;
    this.credentials = ber.readString(Context);

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeInt(this.version);
    ber.writeString((this.name || '').toString());
    ber.writeString((this.credentials || ''), Context);

    return ber;
  }
};
