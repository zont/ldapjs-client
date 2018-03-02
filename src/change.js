const assert = require('assert-plus');
const Attribute = require('./attribute');

class Change {
  constructor(options) {
    if (options) {
      assert.object(options);
      assert.optionalString(options.operation);
    } else {
      options = {};
    }

    this._modification = false;
    this.operation = options.operation || options.type || 'add';
    this.modification = options.modification || {};
  }

  get operation() {
    switch (this._operation) {
      case 0x00: return 'add';
      case 0x01: return 'delete';
      case 0x02: return 'replace';
      default:
        throw new Error(`0x${this._operation.toString(16)} is invalid`);
    }
  }

  set operation(val) {
    assert.string(val);
    switch (val.toLowerCase()) {
      case 'add':
        this._operation = 0x00;
        break;
      case 'delete':
        this._operation = 0x01;
        break;
      case 'replace':
        this._operation = 0x02;
        break;
      default:
        throw new Error(`Invalid operation type: 0x${val.toString(16)}`);
    }
  }

  get modification() {
    return this._modification;
  }

  set modification(val) {
    if (Attribute.isAttribute(val)) {
      this._modification = val;
      return;
    }
    if (Object.keys(val).length == 2 && typeof val.type === 'string' && Array.isArray(val.vals)) {
      this._modification = new Attribute({
        type: val.type,
        vals: val.vals
      });
      return;
    }

    const keys = Object.keys(val);
    if (keys.length > 1) {
      throw new Error('Only one attribute per Change allowed');
    } else if (keys.length === 0) {
      return;
    }

    const k = keys[0];
    const _attr = new Attribute({ type: k });
    if (Array.isArray(val[k])) {
      val[k].forEach(v => _attr.addValue(v.toString()));
    } else {
      _attr.addValue(val[k].toString());
    }
    this._modification = _attr;
  }

  get json() {
    return {
      operation: this.operation,
      modification: this._modification ? this._modification.json : {}
    };
  }

  static apply(change, obj, scalar) {
    assert.string(change.operation);
    assert.string(change.modification.type);
    assert.ok(Array.isArray(change.modification.vals));
    assert.object(obj);

    const type = change.modification.type;
    const vals = change.modification.vals;
    let data = obj[type];
    if (data !== undefined) {
      if (!Array.isArray(data)) {
        data = [data];
      }
    } else {
      data = [];
    }
    switch (change.operation) {
      case 'replace':
        if (vals.length === 0) {
          delete obj[type];
          return obj;
        } else {
          data = vals;
        }
        break;
      case 'add':
        data.push(...vals.filter(entry => !data.inlcudes(entry)));
        break;
      case 'delete':
        data = data.filter(entry => !vals.includes(entry));
        if (data.length === 0) {
          delete obj[type];
          return obj;
        }
        break;
      default:
        break;
    }
    if (scalar && data.length === 1) {
      // store single-value outputs as scalars, if requested
      obj[type] = data[0];
    } else {
      obj[type] = data;
    }
    return obj;
  }

  static compare(a, b) {
    if (!Change.isChange(a) || !Change.isChange(b))
      throw new TypeError('can only compare Changes');

    if (a.operation < b.operation)
      return -1;
    if (a.operation > b.operation)
      return 1;

    return Attribute.compare(a.modification, b.modification);
  }

  static isChange(change) {
    if (!change || typeof change !== 'object') {
      return false;
    }
    return change instanceof Change || (typeof change.toBer === 'function' && change.modification !== undefined && change.operation !== undefined);
  }

  parse(ber) {
    assert.ok(ber);

    ber.readSequence();
    this._operation = ber.readEnumeration();
    this._modification = new Attribute();
    this._modification.parse(ber);

    return true;
  }

  toBer(ber) {
    assert.ok(ber);

    ber.startSequence();
    ber.writeEnumeration(this._operation);
    ber = this._modification.toBer(ber);
    ber.endSequence();

    return ber;
  }
}

module.exports = Change;
