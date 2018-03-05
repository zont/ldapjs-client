const assert = require('assert');
const { BerReader } = require('asn1');
const parents = require('ldap-filter');
const Protocol = require('../protocol');
const Filter = require('./filter');
const AndFilter = require('./and_filter');
const ApproximateFilter = require('./approx_filter');
const EqualityFilter = require('./equality_filter');
const ExtensibleFilter = require('./ext_filter');
const GreaterThanEqualsFilter = require('./ge_filter');
const LessThanEqualsFilter = require('./le_filter');
const NotFilter = require('./not_filter');
const OrFilter = require('./or_filter');
const PresenceFilter = require('./presence_filter');
const SubstringFilter = require('./substr_filter');

const _parse = ber => {
  assert.ok(ber);

  const parseSet = f => {
    const end = ber.offset + ber.length;
    while (ber.offset < end) {
      f.addFilter(_parse(ber));
    }
  };

  let f;

  const type = ber.readSequence();
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
      f = new NotFilter({
        filter: _parse(ber)
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
};

const cloneFilter = input => {
  let child;
  if (input.type === 'and' || input.type === 'or') {
    child = input.filters.map(cloneFilter);
  } else if (input.type === 'not') {
    child = cloneFilter(input.filter);
  }
  switch (input.type) {
    case 'and':
      return new AndFilter({ filters: child });
    case 'or':
      return new OrFilter({ filters: child });
    case 'not':
      return new NotFilter({ filter: child });
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
};

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
