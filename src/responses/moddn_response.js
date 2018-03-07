const LDAPResult = require('./result');
const { LDAP_REP_MODRDN } = require('../utils/protocol');

module.exports = class ModifyDNResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REP_MODRDN}));
  }
};
