const Request = require('./request');
const { LDAP_REQ_UNBIND } = require('../utils/protocol');

module.exports = class extends Request {
  constructor(options) {
    super(Object.assign({ protocolOp: LDAP_REQ_UNBIND, type: 'UnbindRequest' }, options));
  }
};
