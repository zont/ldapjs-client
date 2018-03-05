const assert = require('assert');
const parents = require('ldap-filter');
const Filter = require('./filter');

class ExtensibleFilter extends parents.ExtensibleFilter {
  parse(ber) {
    const end = ber.offset + ber.length;
    while (ber.offset < end) {
      const tag = ber.peek();
      switch (tag) {
        case 0x81:
          this.rule = ber.readString(tag);
          break;
        case 0x82:
          this.matchType = ber.readString(tag);
          break;
        case 0x83:
          this.value = ber.readString(tag);
          break;
        case 0x84:
          this.dnAttributes = ber.readBoolean(tag);
          break;
        default:
          throw new Error('Invalid ext_match filter type: 0x' + tag.toString(16));
      }
    }

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    if (this.rule) {
      ber.writeString(this.rule, 0x81);
    }

    if (this.matchType) {
      ber.writeString(this.matchType, 0x82);
    }

    ber.writeString(this.value, 0x83);

    if (this.dnAttributes) {
      ber.writeBoolean(this.dnAttributes, 0x84);
    }

    return ber;
  }
}

Filter.mixin(ExtensibleFilter);

module.exports = ExtensibleFilter;
