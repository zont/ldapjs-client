const { AssertionError } = require('assert');
const { DN: { isDN } } = require('../dn');
const { isAttribute } = require('../attribute');

const _assert = (arg, expected, name) => {
  throw new AssertionError({
    message: `${name || expected} (${expected}) required`,
    actual: typeof (arg),
    expected,
    operator: '===',
    stackStartFunction: _assert.caller
  });
};

module.exports = {
  optionalArrayOfAttribute(input, name) {
    if (typeof input !== 'undefined' && (!Array.isArray(input) || input.some(v => !isAttribute(v)))) {
      _assert(input, 'array of Attribute', name);
    }
  },

  optionalDN(input, name) {
    if (typeof input !== 'undefined' && !isDN(input)) {
      _assert(input, 'DN', name);
    }
  },

  optionalStringDN(input, name) {
    if (!(typeof input === 'undefined' || isDN(input) || typeof input === 'string')) {
      _assert(input, 'DN or string', name);
    }
  }
};
