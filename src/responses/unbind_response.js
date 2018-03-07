const Response = require('./response');

module.exports = class extends Response {
  constructor(options) {
    super(Object.assign({}, options, { protocolOp: 0 }));
  }
};
