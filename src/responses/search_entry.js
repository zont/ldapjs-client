const assert = require('assert-plus');
const Response = require('./response');
const Attribute = require('../attribute');
const { LDAP_REP_SEARCH_ENTRY } = require('../utils/protocol');
const lassert = require('../utils/assert');

module.exports = class extends Response {
  constructor(options) {
    options = options || {};
    assert.object(options);
    lassert.optionalStringDN(options.objectName);

    super(Object.assign({ protocolOp: LDAP_REP_SEARCH_ENTRY, objectName: null, type: 'SearchEntry' }, options));

    this._setAttributes(options.attributes || []);
  }

  get dn() {
    return this.objectName;
  }

  get object() {
    const obj = {
      dn: this.dn.toString()
    };
    this.attributes.forEach(a => {
      if (a.vals && a.vals.length) {
        obj[a.type] = a.vals.length > 1 ? a.vals.slice() : a.vals[0];
      } else {
        obj[a.type] = [];
      }
    });
    return obj;
  }

  parse(ber) {
    this.objectName = ber.readString();

    assert.ok(ber.readSequence());

    const end = ber.offset + ber.length;
    while (ber.offset < end) {
      const a = new Attribute();
      a.parse(ber);
      this.attributes.push(a);
    }

    return true;
  }

  _setAttributes(obj) {
    if (Array.isArray(obj)) {
      if (obj.some(a => !Attribute.isAttribute(a))) {
        throw new TypeError('entry must be an Array of Attributes');
      }
      this.attributes = obj;
    } else {
      this.attributes = [];
      Object.keys(obj).forEach(k => {
        const attr = new Attribute({ type: k });
        if (Array.isArray(obj[k])) {
          obj[k].forEach(v => attr.addValue(v.toString()));
        } else {
          attr.addValue(obj[k].toString());
        }
        this.attributes.push(attr);
      });
    }
  }
};
