const assert = require('assert-plus');
const { Ber } = require('asn1');
const LDAPMessage = require('./message');
const { parse, parseString, PresenceFilter } = require('../filters');
const { LDAP_REQ_SEARCH, SCOPE_BASE_OBJECT, SCOPE_ONE_LEVEL, SCOPE_SUBTREE } = require('../protocol');

module.exports = class SearchRequest extends LDAPMessage {
  constructor(options) {
    super(Object.assign(options, { protocolOp: LDAP_REQ_SEARCH, filter: parseString(options.filter) }));
  }

  get type() {
    return 'SearchRequest';
  }

  get _dn() {
    return this.baseObject;
  }

  get scope() {
    switch (this._scope) {
      case SCOPE_BASE_OBJECT: return 'base';
      case SCOPE_ONE_LEVEL: return 'one';
      case SCOPE_SUBTREE: return 'sub';
      default:
        throw new Error(`${this._scope} is an invalid search scope`);
    }
  }

  set scope(val) {
    if (typeof (val) === 'string') {
      switch (val) {
        case 'base':
          this._scope = SCOPE_BASE_OBJECT;
          break;
        case 'one':
          this._scope = SCOPE_ONE_LEVEL;
          break;
        case 'sub':
          this._scope = SCOPE_SUBTREE;
          break;
        default:
          throw new Error(`${val} is an invalid search scope`);
      }
    } else {
      this._scope = val;
    }
  }

  _parse(ber) {
    assert.ok(ber);

    this.baseObject = ber.readString();
    this.scope = ber.readEnumeration();
    this.derefAliases = ber.readEnumeration();
    this.sizeLimit = ber.readInt();
    this.timeLimit = ber.readInt();
    this.typesOnly = ber.readBoolean();

    this.filter = parse(ber);

    if (ber.peek() === 0x30) {
      ber.readSequence();
      const end = ber.offset + ber.length;
      while (ber.offset < end)
        this.attributes.push(ber.readString().toLowerCase());
    }

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.baseObject.toString());
    ber.writeEnumeration(this._scope);
    ber.writeEnumeration(this.derefAliases);
    ber.writeInt(this.sizeLimit);
    ber.writeInt(this.timeLimit);
    ber.writeBoolean(this.typesOnly);

    const f = this.filter || new PresenceFilter({ attribute: 'objectclass' });
    ber = f.toBer(ber);

    ber.startSequence(Ber.Sequence | Ber.Constructor);
    if (this.attributes && this.attributes.length) {
      this.attributes.forEach(a => ber.writeString(a));
    }
    ber.endSequence();

    return ber;
  }
};
