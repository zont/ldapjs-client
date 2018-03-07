const assert = require('assert');
const parents = require('ldap-filter');
const Filter = require('./filter');

class SubstringFilter extends parents.SubstringFilter {
  parse(ber) {
    assert.ok(ber);

    this.attribute = ber.readString().toLowerCase();
    ber.readSequence();
    const end = ber.offset + ber.length;

    while (ber.offset < end) {
      const tag = ber.peek();
      switch (tag) {
        case 0x80: // Initial
          this.initial = this.attribute === 'objectclass' ? ber.readString(tag).toLowerCase() : ber.readString(tag);
          break;
        case 0x81: // Any
          this.any.push(this.attribute === 'objectclass' ? ber.readString(tag).toLowerCase() : ber.readString(tag));
          break;
        case 0x82: // Final
          this.final = this.attribute === 'objectclass' ? ber.readString(tag).toLowerCase() : ber.readString(tag);
          break;
        default:
          throw new Error(`Invalid substrings filter type: 0x${tag.toString(16)}`);
      }
    }

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeString(this.attribute);
    ber.startSequence();

    if (this.initial) {
      ber.writeString(this.initial, 0x80);
    }

    if (this.any && this.any.length)
      this.any.forEach(s => ber.writeString(s, 0x81));

    if (this.final) {
      ber.writeString(this.final, 0x82);
    }

    ber.endSequence();

    return ber;
  }
}

Filter.mixin(SubstringFilter);

module.exports = SubstringFilter;
