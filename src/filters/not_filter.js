const assert = require('assert');
const parents = require('ldap-filter');
const { BerWriter } = require('asn1');
const { FILTER_NOT } = require('../utils/protocol');

module.exports = class NotFilter extends parents.NotFilter {
  toBer(ber) {
    assert.ok(ber instanceof BerWriter, 'ber (BerWriter) required');

    ber.startSequence(FILTER_NOT);
    ber = this.filter.toBer(ber);
    ber.endSequence();

    return ber;
  }
};
