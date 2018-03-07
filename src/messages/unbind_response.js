const LDAPResult = require('./result');

module.exports = class UnbindResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: 0}));
  }

  get type() {
    return 'UnbindResponse';
  }
};
