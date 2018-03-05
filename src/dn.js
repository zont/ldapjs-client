const assert = require('assert-plus');

///--- Helpers

const invalidDN = name => {
  const e = new Error();
  e.name = 'InvalidDistinguishedNameError';
  e.message = name;
  return e;
};

const isAlphaNumeric = c => /[A-Za-z0-9]/.test(c);
const isWhitespace = c => /\s/.test(c);

const escapeValue = (val, forceQuote) => {
  let out = '';
  let cur = 0;
  const len = val.length;
  let quoted = false;
  const escaped = /[\\"]/;
  const special = /[,=+<>#;]/;

  if (len > 0) {
    quoted = forceQuote || (val[0] == ' ' || val[len-1] == ' ');
  }

  while (cur < len) {
    if (escaped.test(val[cur]) || (!quoted && special.test(val[cur]))) {
      out += '\\';
    }
    out += val[cur++];
  }
  if (quoted)
    out = '"' + out + '"';
  return out;
};

///--- API

class RDN {
  constructor(obj) {
    this.attrs = {};

    if (obj) {
      Object.keys(obj).forEach(k => this.set(k, obj[k]));
    }
  }

  set(name, value, opts) {
    assert.string(name, 'name (string) required');
    assert.string(value, 'value (string) required');

    const lname = name.toLowerCase();
    this.attrs[lname] = { name, value };

    if (opts && typeof opts === 'object') {
      Object.keys(opts).forEach(k => {
        if (k !== 'value')
          this.attrs[lname][k] = opts[k];
      });
    }
  }

  equals(rdn) {
    if (typeof rdn !== 'object') {
      return false;
    }

    const _1 = Object.keys(this.attrs).sort();
    const _2 = Object.keys(rdn.attrs).sort();

    return _1.length === _2.length && _1.join() === _2.join() && _1.map(i => this.attrs[i].value).join() === _2.map(i => rdn.attrs[i].value).join();
  }

  format(options = {}) {
    assert.optionalObject(options, 'options must be an object');

    const keys = Object.keys(this.attrs);
    if (options.keepOrder) {
      keys.sort((a, b) => this.attrs[a].order - this.attrs[b].order);
    } else {
      keys.sort((a, b) => a.localeCompare(b) || this.attrs[a].value.localeCompare(this.attrs[b].value));
    }

    return keys
      .map(key => {
        const { name, value, quoted } = this.attrs[key];
        return `${options.keepCase ? name : options.upperName ? key.toUpperCase() : key}=${escapeValue(value, options.keepQuote && quoted)}`;
      })
      .join('+');
  }

  toString() {
    return this.format();
  }
}

// Thank you OpenJDK!
const parse = name => {
  if (typeof (name) !== 'string')
    throw new TypeError('name (string) required');

  let cur = 0;
  const len = name.length;

  const parseRdn = () => {
    const rdn = new RDN();
    let order = 0;
    rdn.spLead = trim();
    while (cur < len) {
      const opts = {
        order: order
      };
      const attr = parseAttrType();
      trim();
      if (cur >= len || name[cur++] !== '=')
        throw invalidDN(name);

      trim();
      // Parameters about RDN value are set in 'opts' by parseAttrValue
      const value = parseAttrValue(opts);
      rdn.set(attr, value, opts);
      rdn.spTrail = trim();
      if (cur >= len || name[cur] !== '+')
        break;
      ++cur;
      ++order;
    }
    return rdn;
  };

  const trim = () => {
    let count = 0;
    while ((cur < len) && isWhitespace(name[cur])) {
      ++cur;
      ++count;
    }
    return count;
  };

  const parseAttrType = () => {
    const beg = cur;
    while (cur < len) {
      const c = name[cur];
      if (isAlphaNumeric(c) ||
          c == '.' ||
          c == '-' ||
          c == ' ') {
        ++cur;
      } else {
        break;
      }
    }
    // Back out any trailing spaces.
    while ((cur > beg) && (name[cur - 1] == ' '))
      --cur;

    if (beg == cur)
      throw invalidDN(name);

    return name.slice(beg, cur);
  };

  const parseAttrValue = opts => {
    if (cur < len && name[cur] == '#') {
      opts.binary = true;
      return parseBinaryAttrValue();
    } else if (cur < len && name[cur] == '"') {
      opts.quoted = true;
      return parseQuotedAttrValue();
    } else {
      return parseStringAttrValue();
    }
  };

  const parseBinaryAttrValue = () => {
    const beg = cur++;
    while (cur < len && isAlphaNumeric(name[cur]))
      ++cur;

    return name.slice(beg, cur);
  };

  const parseQuotedAttrValue = () => {
    let str = '';
    ++cur; // Consume the first quote

    while ((cur < len) && name[cur] != '"') {
      if (name[cur] === '\\')
        cur++;
      str += name[cur++];
    }
    if (cur++ >= len) // no closing quote
      throw invalidDN(name);

    return str;
  };

  const parseStringAttrValue = () => {
    const beg = cur;
    let str = '';
    let esc = -1;

    while ((cur < len) && !atTerminator()) {
      if (name[cur] === '\\') {
        // Consume the backslash and mark its place just in case it's escaping
        // whitespace which needs to be preserved.
        esc = cur++;
      }
      if (cur === len) // backslash followed by nothing
        throw invalidDN(name);
      str += name[cur++];
    }

    // Trim off (unescaped) trailing whitespace and rewind cursor to the end of
    // the AttrValue to record whitespace length.
    for (; cur > beg; cur--) {
      if (!isWhitespace(name[cur - 1]) || (esc === (cur - 1)))
        break;
    }
    return str.slice(0, cur - beg);
  };

  const atTerminator = () => cur < len && (name[cur] === ',' || name[cur] === ';' || name[cur] === '+');

  const rdns = [];

  // Short-circuit for empty DNs
  if (len === 0)
    return new DN(rdns);

  rdns.push(parseRdn());
  while (cur < len) {
    if (name[cur] === ',' || name[cur] === ';') {
      ++cur;
      rdns.push(parseRdn());
    } else {
      throw invalidDN(name);
    }
  }

  return new DN(rdns);
};

class DN {
  constructor(rdns) {
    assert.optionalArrayOfObject(rdns, '[object] required');

    this.rdns = rdns ? rdns.slice() : [];
    this._format = {};
  }

  get length() {
    return this.rdns.length;
  }

  static isDN(dn) {
    return dn instanceof DN || (dn && Array.isArray(dn.rdns));
  }

  format(options) {
    assert.optionalObject(options, 'options must be an object');
    options = options || this._format;

    let str = '';
    this.rdns.forEach(rdn => {
      const rdnString = rdn.format(options);
      if (str.length !== 0) {
        str += ',';
      }
      if (options.keepSpace) {
        str += ' '.repeat(rdn.spLead) + rdnString + ' '.repeat(rdn.spTrail);
      } else if (options.skipSpace === true || str.length === 0) {
        str += rdnString;
      } else {
        str += ' ' + rdnString;
      }
    });
    return str;
  }

  setFormat(options) {
    assert.object(options, 'options must be an object');

    this._format = options;
  }

  toString() {
    return this.format();
  }

  parentOf(dn) {
    if (typeof (dn) !== 'object') {
      dn = parse(dn);
    }

    if (this.rdns.length >= dn.rdns.length)
      return false;

    const diff = dn.rdns.length - this.rdns.length;
    for (let i = this.rdns.length - 1; i >= 0; --i) {
      const myRDN = this.rdns[i];
      const theirRDN = dn.rdns[i + diff];

      if (!myRDN.equals(theirRDN))
        return false;
    }

    return true;
  }

  childOf(dn) {
    if (typeof (dn) !== 'object') {
      dn = parse(dn);
    }
    return dn.parentOf(this);
  }

  isEmpty() {
    return (this.rdns.length === 0);
  }

  equals(dn) {
    if (typeof (dn) !== 'object') {
      dn = parse(dn);
    }

    if (this.rdns.length !== dn.rdns.length)
      return false;

    for (let i = 0; i < this.rdns.length; ++i) {
      if (!this.rdns[i].equals(dn.rdns[i]))
        return false;
    }

    return true;
  }

  parent() {
    if (this.rdns.length !== 0) {
      const save = this.rdns.shift();
      const dn = new DN(this.rdns);
      this.rdns.unshift(save);
      return dn;
    }

    return null;
  }

  clone() {
    const dn = new DN(this.rdns);
    dn._format = this._format;
    return dn;
  }

  reverse() {
    this.rdns.reverse();
    return this;
  }

  pop() {
    return this.rdns.pop();
  }

  push(rdn) {
    assert.object(rdn, 'rdn (RDN) required');

    return this.rdns.push(rdn);
  }

  shift() {
    return this.rdns.shift();
  }

  unshift(rdn) {
    assert.object(rdn, 'rdn (RDN) required');

    return this.rdns.unshift(rdn);
  }
}


module.exports = { parse, DN, RDN };
