const LDAPResult = require('./result');
const { LDAP_REP_BIND } = require('../protocol');

module.exports = class BindResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REP_BIND}));
  }
};
