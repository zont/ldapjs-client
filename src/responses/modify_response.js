const LDAPResult = require('./result');
const { LDAP_REP_MODIFY } = require('../utils/protocol');

module.exports = class ModifyResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REP_MODIFY}));
  }
};
