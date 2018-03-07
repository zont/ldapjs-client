const assert = require('assert-plus');
const parents = require('ldap-filter');
const { BerWriter } = require('asn1');
const { FILTER_AND } = require('../utils/protocol');

module.exports = class AndFilter extends parents.AndFilter {
  toBer(ber) {
    assert.ok(ber instanceof BerWriter, 'ber (BerWriter) required');

    ber.startSequence(FILTER_AND);
    ber = this.filters.reduce((ber, f) => f.toBer(ber), ber);
    ber.endSequence();

    return ber;
  }
};
