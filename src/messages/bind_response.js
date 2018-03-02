var LDAPResult = require('./result');
var { LDAP_REP_BIND } = require('../protocol');

module.exports = class BindResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REP_BIND}));
  }
};
