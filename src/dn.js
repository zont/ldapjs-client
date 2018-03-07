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
    out = `"${  out  }"`;
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

  set(name, value) {
    assert.string(name, 'name (string) required');
    assert.string(value, 'value (string) required');

    const lname = name.toLowerCase();
    this.attrs[lname] = { name, value };
  }

  toString() {
    const keys = Object.keys(this.attrs);
    keys.sort((a, b) => a.localeCompare(b) || this.attrs[a].value.localeCompare(this.attrs[b].value));

    return keys
      .map(key => `${key}=${escapeValue(this.attrs[key].value)}`)
      .join('+');
  }
}

// Thank you OpenJDK!
const parse = name => {
  assert.string(name, 'name');

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
    assert.optionalArrayOfObject(rdns, 'rdns');

    this.rdns = rdns ? rdns.slice() : [];
  }

  static isDN(dn) {
    return dn instanceof DN || (dn && Array.isArray(dn.rdns));
  }

  toString() {
    return this.rdns.map(String).join(', ');
  }
}


module.exports = { parse, DN, RDN };
