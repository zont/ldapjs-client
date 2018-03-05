const assert = require('assert-plus');
const LDAPMessage = require('./message');
const Attribute = require('../attribute');
const { LDAP_REP_SEARCH_ENTRY } = require('../protocol');
const lassert = require('../assert');

module.exports = class SearchEntry extends LDAPMessage {
  constructor(options) {
    options = options || {};
    assert.object(options);
    lassert.optionalStringDN(options.objectName);

    options.protocolOp = LDAP_REP_SEARCH_ENTRY;
    super(options);

    this.objectName = options.objectName || null;
    this.setAttributes(options.attributes || []);
  }

  get type() {
    return 'SearchEntry';
  }

  get _dn() {
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

  get raw() {
    const obj = {
      dn: this.dn.toString()
    };

    this.attributes.forEach(a => {
      if (a.buffers && a.buffers.length) {
        obj[a.type] = a.buffers.length > 1 ? a.buffers.slice() : a.buffers[0];
      } else {
        obj[a.type] = [];
      }
    });
    return obj;
  }

  addAttribute(attr) {
    if (!attr || typeof attr !== 'object') {
      throw new TypeError('attr (attribute) required');
    }

    this.attributes.push(attr);
  }

  toObject() {
    return this.object;
  }

  fromObject(obj) {
    if (typeof obj !== 'object') {
      throw new TypeError('object required');
    }

    obj = obj.attributes || obj;
    this.attributes = Object.keys(obj).map(type => new Attribute({ type, vals: obj[type] }));

    return true;
  }

  setAttributes(obj) {
    if (typeof obj !== 'object') {
      throw new TypeError('object required');
    }

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

  _json(j) {
    assert.ok(j);

    j.objectName = this.objectName.toString();
    j.attributes = this.attributes.map(a => a.json || a);

    return j;
  }

  _parse(ber) {
    assert.ok(ber);

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

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.objectName.toString());
    ber.startSequence();
    ber = this.attributes.reduce((ber, a) => Attribute.toBer(a, ber), ber);
    ber.endSequence();

    return ber;
  }
};
