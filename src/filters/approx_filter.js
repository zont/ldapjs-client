const assert = require('assert-plus');
const parents = require('ldap-filter');
const { BerWriter } = require('asn1');
const { FILTER_APPROX } = require('../utils/protocol');

module.exports = class ApproximateFilter extends parents.ApproximateFilter {
  parse(ber) {
    assert.ok(ber);

    this.attribute = ber.readString().toLowerCase();
    this.value = ber.readString();

    return true;
  }

  toBer(ber) {
    assert.ok(ber instanceof BerWriter, 'ber (BerWriter) required');

    ber.startSequence(FILTER_APPROX);
    ber.writeString(this.attribute);
    ber.writeString(this.value);
    ber.endSequence();

    return ber;
  }
};
