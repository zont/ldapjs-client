const LDAPResult = require('./result');
const { LDAP_REP_COMPARE } = require('../protocol');

module.exports = class CompareResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: LDAP_REP_COMPARE}));
  }

  end(matches) {
    let status = 0x06;
    if (typeof matches === 'boolean') {
      if (!matches)
        status = 0x05; // Compare false
    } else {
      status = matches;
    }

    return super.end(status);
  }
};
