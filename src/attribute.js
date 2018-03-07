const assert = require('assert-plus');
const asn1 = require('asn1');
const Protocol = require('./utils/protocol');

const _bufferEncoding = type =>  /;binary$/.test(type) ? 'base64' : 'utf8';

class Attribute {
  constructor(options) {
    options = options || {};

    assert.object(options, 'options');
    assert.optionalString(options.type, 'options.type');

    this.type = options.type || '';
    this._vals = [];

    if (options.vals !== undefined && options.vals !== null)
      this.vals = options.vals;
  }

  get json() {
    return {
      type: this.type,
      vals: this.vals
    };
  }

  get vals() {
    const eType = _bufferEncoding(this.type);
    return this._vals.map(v => v.toString(eType));
  }

  set vals(vals) {
    this._vals = [];
    if (Array.isArray(vals)) {
      vals.forEach(v => this.addValue(v));
    } else {
      this.addValue(vals);
    }
  }

  addValue(val) {
    if (Buffer.isBuffer(val)) {
      this._vals.push(val);
    } else {
      this._vals.push(new Buffer(String(val), _bufferEncoding(this.type)));
    }
  }

  parse(ber) {
    assert.ok(ber);

    ber.readSequence();
    this.type = ber.readString();

    if (ber.peek() === Protocol.LBER_SET) {
      if (ber.readSequence(Protocol.LBER_SET)) {
        const end = ber.offset + ber.length;
        while (ber.offset < end)
          this._vals.push(ber.readString(asn1.Ber.OctetString, true));
      }
    }

    return true;
  }

  toBer(ber) {
    assert.ok(ber);

    ber.startSequence();
    ber.writeString(this.type);
    ber.startSequence(Protocol.LBER_SET);
    if (this._vals.length) {
      this._vals.forEach(b => {
        ber.writeByte(asn1.Ber.OctetString);
        ber.writeLength(b.length);
        b.forEach(i => ber.writeByte(i));
      });
    } else {
      ber.writeStringArray([]);
    }
    ber.endSequence();
    ber.endSequence();

    return ber;
  }

  toString() {
    return JSON.stringify(this.json);
  }

  static compare(a, b) {
    assert.ok(Attribute.isAttribute(a) && Attribute.isAttribute(b), 'can only compare Attributes');

    if (a.type < b.type) return -1;
    if (a.type > b.type) return 1;
    if (a.vals.length < b.vals.length) return -1;
    if (a.vals.length > b.vals.length) return 1;

    for (let i = 0; i < a.vals.length; ++i) {
      if (a.vals[i] < b.vals[i]) return -1;
      if (a.vals[i] > b.vals[i]) return 1;
    }

    return 0;
  }

  static toBer(attr, ber) {
    return Attribute.prototype.toBer.call(attr, ber);
  }

  static isAttribute(attr) {
    if (!attr || typeof (attr) !== 'object') {
      return false;
    }
    if (attr instanceof Attribute) {
      return true;
    }
    return typeof attr.toBer === 'function' && typeof attr.type === 'string' && Array.isArray(attr.vals)
      && attr.vals.filter(item => typeof item === 'string' || Buffer.isBuffer(item)).length === attr.vals.length;
  }

  static fromObject(attributes) {
    return Object.keys(attributes).map(k => {
      const attr = new Attribute({ type: k });

      if (Array.isArray(attributes[k])) {
        attributes[k].forEach(v => attr.addValue(v.toString()));
      } else {
        attr.addValue(attributes[k].toString());
      }

      return attr;
    });
  }
}

module.exports = Attribute;
