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
    // If sizeLimit is between 0 and 2**31-1 this will cause server to return only that many results. 
    // However, if the server contains more records than the given size limit it will 
    // return EC 4 (SizeLimitExceeded).
    // Simialarly if sizeLimit is set to high value, but the server has a default max
    // sizeLimit that is smaller it will only return the max size limit set by the server again resulting
    // in EC 4.
    // To overcome this we need to use LDAP reqeust/response controls to be able to page the results.
    // Additionally if EC 4 is given, when a sizeLimit greater than 0 is given
    //  no response controls will be given and the request simply errs.
    ber.writeInt(0); // sizeLimit, set to ulimited and use sizeLimit to control page size via controls
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
