const assert = require('assert-plus');
const { Ber: { OctetString } } = require('asn1');
const parents = require('ldap-filter');
const Filter = require('./filter');

class EqualityFilter extends parents.EqualityFilter {
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

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.attribute);
    ber.writeBuffer(this.raw, OctetString);

    return ber;
  }
}

Filter.mixin(EqualityFilter);

module.exports = EqualityFilter;
