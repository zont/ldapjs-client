const assert = require('assert-plus');
const LDAPMessage = require('./message');
const { LDAP_REQ_COMPARE } = require('../protocol');
const lassert = require('../assert');

module.exports = class CompareRequest extends LDAPMessage {
  constructor(options) {
    options = options || {};
    assert.object(options);
    assert.optionalString(options.attribute);
    assert.optionalString(options.value);
    lassert.optionalStringDN(options.entry);

    options.protocolOp = LDAP_REQ_COMPARE;
    super(options);

    this.entry = options.entry || null;
    this.attribute = options.attribute || '';
    this.value = options.value || '';
  }

  get type() {
    return 'CompareRequest';
  }

  get _dn() {
    return this.entry;
  }

  _parse(ber) {
    assert.ok(ber);

    this.entry = ber.readString();

    ber.readSequence();
    this.attribute = ber.readString().toLowerCase();
    this.value = ber.readString();

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.entry.toString());
    ber.startSequence();
    ber.writeString(this.attribute);
    ber.writeString(this.value);
    ber.endSequence();

    return ber;
  }

  _json(j) {
    assert.ok(j);

    j.entry = this.entry.toString();
    j.attribute = this.attribute;
    j.value = this.value;

    return j;
  }
};
