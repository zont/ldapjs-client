const Response = require('./response');
const { LDAP_REP_SEARCH } = require('../utils/protocol');

module.exports = class extends Response {
  constructor(options) {
    super(Object.assign({ attributes: [] }, options, { protocolOp: LDAP_REP_SEARCH }));
  }
};
