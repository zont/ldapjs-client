const assert = require('assert');
const parents = require('ldap-filter');
const Filter = require('./filter');

class AndFilter extends parents.AndFilter {
  _toBer(ber) {
    assert.ok(ber);
    return this.filters.reduce((ber, f) => f.toBer(ber), ber);
  }
}

Filter.mixin(AndFilter);

module.exports = AndFilter;
