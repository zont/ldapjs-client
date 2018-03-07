const assert = require('assert');
const parents = require('ldap-filter');
const Filter = require('./filter');

class PresenceFilter extends parents.PresenceFilter {
  parse(ber) {
    assert.ok(ber);

    this.attribute = ber.buffer.slice(0, ber.length).toString('utf8').toLowerCase();

    ber._offset += ber.length;

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    new Buffer(this.attribute).forEach(i => ber.writeByte(i));

    return ber;
  }
}

Filter.mixin(PresenceFilter);

module.exports = PresenceFilter;
