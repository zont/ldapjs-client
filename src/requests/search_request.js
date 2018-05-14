const { Ber } = require('asn1');
const Request = require('./request');
const { parseString } = require('../filters');
const { LDAP_REQ_SEARCH, NEVER_DEREF_ALIASES, SCOPE_BASE_OBJECT, SCOPE_ONE_LEVEL, SCOPE_SUBTREE } = require('../utils/protocol');

const SCOPES = {
  base: SCOPE_BASE_OBJECT,
  one: SCOPE_ONE_LEVEL,
  sub: SCOPE_SUBTREE
};

module.exports = class extends Request {
  constructor(options) {
    super(Object.assign({ protocolOp: LDAP_REQ_SEARCH, scope: 'base', sizeLimit: 0, timeLimit: 10, typesOnly: false, attributes: [], type: 'SearchRequest' }, options));
  }

  set scope(val) {
    if (!(val in SCOPES)) {
      throw new Error(`${val} is an invalid search scope`);
    }

    this._scope = SCOPES[val];
  }

  _toBer(ber) {
    ber.writeString(this.baseObject.toString());
    ber.writeEnumeration(this._scope);
    ber.writeEnumeration(NEVER_DEREF_ALIASES);
    ber.writeInt(this.sizeLimit);
    ber.writeInt(this.timeLimit);
    ber.writeBoolean(this.typesOnly);

    ber = parseString(this.filter || '(objectclass=*)').toBer(ber);

    ber.startSequence(Ber.Sequence | Ber.Constructor);
    if (this.attributes && this.attributes.length) {
      this.attributes.forEach(a => ber.writeString(a));
    }
    ber.endSequence();

    return ber;
  }
};
