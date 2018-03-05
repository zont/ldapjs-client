const assert = require('assert');
const parents = require('ldap-filter');
const Filter = require('./filter');

class ApproximateFilter extends parents.ApproximateFilter {
  parse(ber) {
    assert.ok(ber);

    this.attribute = ber.readString().toLowerCase();
    this.value = ber.readString();

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.attribute);
    ber.writeString(this.value);

    return ber;
  }
}

Filter.mixin(ApproximateFilter);

module.exports = ApproximateFilter;
