const assert = require('assert');
const parents = require('ldap-filter');
const { BerWriter } = require('asn1');
const { FILTER_OR } = require('../utils/protocol');

module.exports = class OrFilter extends parents.OrFilter {
  toBer(ber) {
    assert.ok(ber instanceof BerWriter, 'ber (BerWriter) required');

    ber.startSequence(FILTER_OR);
    ber = this.filters.reduce((ber, f) => f.toBer(ber), ber);
    ber.endSequence();

    return ber;
  }
};
