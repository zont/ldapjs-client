const assert = require('assert-plus');
const { BerWriter } = require('asn1');
const Protocol = require('../protocol');

const TYPES = {
  'and': Protocol.FILTER_AND,
  'or': Protocol.FILTER_OR,
  'not': Protocol.FILTER_NOT,
  'equal': Protocol.FILTER_EQUALITY,
  'substring': Protocol.FILTER_SUBSTRINGS,
  'ge': Protocol.FILTER_GE,
  'le': Protocol.FILTER_LE,
  'present': Protocol.FILTER_PRESENT,
  'approx': Protocol.FILTER_APPROX,
  'ext': Protocol.FILTER_EXT
};

module.exports = {
  isFilter(filter) {
    if (!filter || typeof filter !== 'object') {
      return false;
    }

    // Do our best to duck-type it
    return typeof filter.toBer === 'function' && typeof filter.matches === 'function' && TYPES[filter.type] !== undefined;
  },

  mixin(target) {
    target.prototype.toBer = function(ber) {
      assert.ok(ber instanceof BerWriter, 'ber (BerWriter) required');

      ber.startSequence(TYPES[this.type]);
      ber = this._toBer(ber);
      ber.endSequence();

      return ber;
    };
  }
};
