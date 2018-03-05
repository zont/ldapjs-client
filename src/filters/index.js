var assert = require('assert');
var { BerReader } = require('asn1');
var parents = require('ldap-filter');
var Protocol = require('../protocol');
var Filter = require('./filter');
var AndFilter = require('./and_filter');
var ApproximateFilter = require('./approx_filter');
var EqualityFilter = require('./equality_filter');
var ExtensibleFilter = require('./ext_filter');
var GreaterThanEqualsFilter = require('./ge_filter');
var LessThanEqualsFilter = require('./le_filter');
var NotFilter = require('./not_filter');
var OrFilter = require('./or_filter');
var PresenceFilter = require('./presence_filter');
var SubstringFilter = require('./substr_filter');

function _parse(ber) {
  assert.ok(ber);

  function parseSet(f) {
    var end = ber.offset + ber.length;
    while (ber.offset < end)
      f.addFilter(_parse(ber));
  }

  var f;

  var type = ber.readSequence();
  switch (type) {

  case Protocol.FILTER_AND:
    f = new AndFilter();
    parseSet(f);
    break;

  case Protocol.FILTER_APPROX:
    f = new ApproximateFilter();
    f.parse(ber);
    break;

  case Protocol.FILTER_EQUALITY:
    f = new EqualityFilter();
    f.parse(ber);
    return f;

  case Protocol.FILTER_EXT:
    f = new ExtensibleFilter();
    f.parse(ber);
    return f;

  case Protocol.FILTER_GE:
    f = new GreaterThanEqualsFilter();
    f.parse(ber);
    return f;

  case Protocol.FILTER_LE:
    f = new LessThanEqualsFilter();
    f.parse(ber);
    return f;

  case Protocol.FILTER_NOT:
    var _f = _parse(ber);
    f = new NotFilter({
      filter: _f
    });
    break;

  case Protocol.FILTER_OR:
    f = new OrFilter();
    parseSet(f);
    break;

  case Protocol.FILTER_PRESENT:
    f = new PresenceFilter();
    f.parse(ber);
    break;

  case Protocol.FILTER_SUBSTRINGS:
    f = new SubstringFilter();
    f.parse(ber);
    break;

  default:
    throw new Error('Invalid search filter type: 0x' + type.toString(16));
  }


  assert.ok(f);
  return f;
}

function cloneFilter(input) {
  var child;
  if (input.type === 'and' || input.type === 'or') {
    child = input.filters.map(cloneFilter);
  } else if (input.type === 'not') {
    child = cloneFilter(input.filter);
  }
  switch (input.type) {
  case 'and':
    return new AndFilter({filters: child});
  case 'or':
    return new OrFilter({filters: child});
  case 'not':
    return new NotFilter({filter: child});
  case 'equal':
    return new EqualityFilter(input);
  case 'substring':
    return new SubstringFilter(input);
  case 'ge':
    return new GreaterThanEqualsFilter(input);
  case 'le':
    return new LessThanEqualsFilter(input);
  case 'present':
    return new PresenceFilter(input);
  case 'approx':
    return new ApproximateFilter(input);
  case 'ext':
    return new ExtensibleFilter(input);
  default:
    throw new Error('invalid filter type:' + input.type);
  }
}

module.exports = {
  parse(ber) {
    if (!ber || !(ber instanceof BerReader))
      throw new TypeError('ber (BerReader) required');

    return _parse(ber);
  },

  parseString(str) {
    return cloneFilter(parents.parse(str));
  },

  isFilter: Filter.isFilter,
  PresenceFilter
};
