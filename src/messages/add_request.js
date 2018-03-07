const assert = require('assert-plus');
const LDAPMessage = require('./message');
const Attribute = require('../attribute');
const { LDAP_REQ_ADD } = require('../protocol');
const lassert = require('../assert');

module.exports = class AddRequest extends LDAPMessage {
  constructor(options) {
    options = options || {};
    assert.object(options);
    lassert.optionalStringDN(options.entry);
    lassert.optionalArrayOfAttribute(options.attributes);

    options.protocolOp = LDAP_REQ_ADD;
    super(options);

    this.entry = options.entry || null;
    this.attributes = options.attributes ? options.attributes.slice(0) : [];
  }

  get type() {
    return 'AddRequest';
  }

  get _dn() {
    return this.entry;
  }

  _parse(ber) {
    assert.ok(ber);

    this.entry = ber.readString();

    ber.readSequence();

    const end = ber.offset + ber.length;
    while (ber.offset < end) {
      const a = new Attribute();
      a.parse(ber);
      a.type = a.type.toLowerCase();
      if (a.type === 'objectclass') {
        a.vals = a.vals.map(i => i.toLowerCase());
      }
      this.attributes.push(a);
    }

    this.attributes.sort(Attribute.compare);
    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.entry.toString());
    ber.startSequence();
    this.attributes.forEach(a => a.toBer(ber));
    ber.endSequence();

    return ber;
  }

  indexOf(attr) {
    assert.string(attr, 'attr');
    return this.attributes.findIndex(i => i.type === attr);
  }

  attributeNames() {
    return this.attributes.map(i => i.type.toLowerCase());
  }

  getAttribute(name) {
    assert.string(name, 'attribute name');
    return this.attributes.find(i => i.type === name.toLowerCase()) || null;
  }

  addAttribute(attr) {
    assert.ok(attr instanceof Attribute, 'attribute (Attribute) required');
    return this.attributes.push(attr);
  }

  toObject() {
    const obj = {
      dn: this.entry ? this.entry.toString() : '',
      attributes: {}
    };

    if (!this.attributes || !this.attributes.length)
      return obj;

    this.attributes.forEach(a => {
      if (!obj.attributes[a.type])
        obj.attributes[a.type] = [];

      a.vals.forEach(v => {
        if (obj.attributes[a.type].indexOf(v) === -1)
          obj.attributes[a.type].push(v);
      });
    });

    return obj;
  }
};
