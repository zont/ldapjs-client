const LDAPResult = require('./result');
const { LDAP_REP_DELETE } = require('../utils/protocol');

module.exports = class DeleteResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REP_DELETE}));
  }
};
