const LDAPResult = require('./result');
const { LDAP_REP_SEARCH } = require('../protocol');

module.exports = class SearchResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({ attributes : [] }, options, { protocolOp: LDAP_REP_SEARCH }));
  }
};
