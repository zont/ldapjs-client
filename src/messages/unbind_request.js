const LDAPMessage = require('./message');
const { DN, RDN } = require('../dn');
const { LDAP_REQ_UNBIND } = require('../protocol');

module.exports = class UnbindRequest extends LDAPMessage {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REQ_UNBIND}));
  }

  get type() {
    return 'UnbindRequest';
  }

  get _dn() {
    return this.connection ? this.connection.ldap.bindDN : new DN([new RDN({cn: 'anonymous'})]);
  }

  _parse() {
    return true;
  }
};
