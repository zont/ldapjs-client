const assert = require('assert-plus');
const LDAPResult = require('./result');

module.exports = class UnbindResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, {protocolOp: 0}));
  }

  get type() {
    return 'UnbindResponse';
  }

  end() {
    assert.ok(this.connection);
    this.connection.end();
  }
};
