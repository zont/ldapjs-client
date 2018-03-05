const assert = require('assert');
const parents = require('ldap-filter');
const Filter = require('./filter');

class NotFilter extends parents.NotFilter {
  _toBer(ber) {
    assert.ok(ber);
    return this.filter.toBer(ber);
  }
}

Filter.mixin(NotFilter);

module.exports = NotFilter;
