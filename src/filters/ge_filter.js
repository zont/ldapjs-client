const assert = require('assert');
const parents = require('ldap-filter');
const { BerWriter } = require('asn1');
const { FILTER_GE } = require('../utils/protocol');

module.exports = class GreaterThanEqualsFilter extends parents.GreaterThanEqualsFilter {
  parse(ber) {
    assert.ok(ber);

    this.attribute = ber.readString().toLowerCase();
    this.value = ber.readString();

    return true;
  }

  toBer(ber) {
    assert.ok(ber instanceof BerWriter, 'ber (BerWriter) required');

    ber.startSequence(FILTER_GE);
    ber.writeString(this.attribute);
    ber.writeString(this.value);
    ber.endSequence();

    return ber;
  }
};
