const assert = require('assert');
const parents = require('ldap-filter');
const Filter = require('./filter');

class OrFilter extends parents.OrFilter {
  _toBer(ber) {
    assert.ok(ber);
    return this.filters.reduce((ber, f) => f.toBer(ber), ber);
  }
}

Filter.mixin(OrFilter);

module.exports = OrFilter;
