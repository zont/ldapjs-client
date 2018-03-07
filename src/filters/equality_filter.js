const assert = require('assert-plus');
const parents = require('ldap-filter');
const { Ber: { OctetString }, BerWriter } = require('asn1');
const { FILTER_EQUALITY } = require('../utils/protocol');

module.exports = class EqualityFilter extends parents.EqualityFilter {
  matches(target, strictAttrCase) {
    assert.object(target, 'target');

    const tv = parents.getAttrValue(target, this.attribute, strictAttrCase);
    const value = this.value;

    if (this.attribute.toLowerCase() === 'objectclass') {
      return parents.testValues(v => value.toLowerCase() === v.toLowerCase(), tv);
    } else {
      return parents.testValues(v => value === v, tv);
    }
  }

  parse(ber) {
    assert.ok(ber);

    this.attribute = ber.readString().toLowerCase();
    this.value = ber.readString(OctetString, true);

    if (this.attribute === 'objectclass') {
      this.value = this.value.toLowerCase();
    }

    return true;
  }

  toBer(ber) {
    assert.ok(ber instanceof BerWriter, 'ber (BerWriter) required');

    ber.startSequence(FILTER_EQUALITY);
    ber.writeString(this.attribute);
    ber.writeBuffer(this.raw, OctetString);
    ber.endSequence();

    return ber;
  }
};
