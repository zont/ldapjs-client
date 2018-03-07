const Response = require('./response');
const { LDAP_REP_SEARCH_REF } = require('../utils/protocol');
const { DN } = require('../dn');
const parseUrl = require('../utils/parse-url');

module.exports = class extends Response {
  constructor(options) {
    super(Object.assign({ protocolOp: LDAP_REP_SEARCH_REF, uris: [], type: 'SearchReference' }, options));
  }

  get object() {
    return {
      dn: new DN().toString(),
      uris: this.uris
    };
  }

  parse(ber) {
    const length = ber.length;

    while (ber.offset < length) {
      const _url = ber.readString();
      parseUrl(_url);
      this.uris.push(_url);
    }

    return true;
  }
};
