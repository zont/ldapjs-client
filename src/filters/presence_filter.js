const assert = require('assert');
const parents = require('ldap-filter');
const { BerWriter } = require('asn1');
const { FILTER_PRESENT } = require('../utils/protocol');

module.exports = class PresenceFilter extends parents.PresenceFilter {
  parse(ber) {
    assert.ok(ber);

    this.attribute = ber.buffer.slice(0, ber.length).toString('utf8').toLowerCase();
    ber._offset += ber.length;

    return true;
  }

  toBer(ber) {
    assert.ok(ber instanceof BerWriter, 'ber (BerWriter) required');

    ber.startSequence(FILTER_PRESENT);
    new Buffer(this.attribute).forEach(i => ber.writeByte(i));
    ber.endSequence();

    return ber;
  }
};
