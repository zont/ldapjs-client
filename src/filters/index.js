const ldapFilter = require('ldap-filter');
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

const cloneFilter = input => {
  switch (input.type) {
    case 'and':
      return new AndFilter({ filters: input.filters.map(cloneFilter) });
    case 'or':
      return new OrFilter({ filters: input.filters.map(cloneFilter) });
    case 'not':
      return new NotFilter({ filter: cloneFilter(input.filter) });
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
      throw new Error(`invalid filter type: ${input.type}`);
  }
};

module.exports = {
  parseString: str => cloneFilter(ldapFilter.parse(str))
};
