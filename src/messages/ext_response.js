const assert = require('assert-plus');
const LDAPResult = require('./result');
const { LDAP_REP_EXTENSION } = require('../protocol');

module.exports = class ExtendedResponse extends LDAPResult {
  constructor(options) {
    options = options || {};
    assert.object(options);
    assert.optionalString(options.responseName);
    assert.optionalString(options.responsevalue);
    options.protocolOp = LDAP_REP_EXTENSION;

    super(options);

    this.responseName = options.responseName || undefined;
    this.responseValue = options.responseValue || undefined;
  }

  get type() {
    return 'ExtendedResponse';
  }

  get _dn() {
    return this.responseName;
  }

  get name() {
    return this.responseName;
  }

  set name(val) {
    assert.string(val);
    this.responseName = val;
  }

  get value() {
    return this.responseValue;
  }

  set value(val) {
    assert.string(val);
    this.responseValue = val;
  }

  _parse(ber) {
    assert.ok(ber);

    if (!super._parse(ber))
      return false;

    if (ber.peek() === 0x8a)
      this.responseName = ber.readString(0x8a);
    if (ber.peek() === 0x8b)
      this.responseValue = ber.readString(0x8b);

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    if (!super._toBer(ber))
      return false;

    if (this.responseName)
      ber.writeString(this.responseName, 0x8a);
    if (this.responseValue)
      ber.writeString(this.responseValue, 0x8b);

    return ber;
  }

  _json (j) {
    assert.ok(j);

    j = super._json(j);
    j.responseName = this.responseName;
    j.responseValue = this.responseValue;

    return j;
  }
};
