const assert = require('assert-plus');
const { LDAP_REP_REFERRAL, LDAP_CONTROLS } = require('../utils/protocol');

module.exports = class {
  constructor(options) {
    assert.optionalNumber(options.status);
    assert.optionalString(options.matchedDN);
    assert.optionalString(options.errorMessage);
    assert.optionalArrayOfString(options.referrals);

    Object.assign(this, { status: 0, matchedDN: '', errorMessage: '', referrals: [], type: 'Response', controls: [] }, options);
  }

  get object() {
    return this;
  }

  parse(ber) {
    this.status = ber.readEnumeration();
    this.matchedDN = ber.readString();
    this.errorMessage = ber.readString();

    if (ber.peek() === LDAP_REP_REFERRAL) {
      const end = ber.offset + ber.length;
      while (ber.offset < end) {
        this.referrals.push(ber.readString());
      }
    }

    if (ber.peek() === LDAP_CONTROLS) {
      ber.readSequence();
      while (ber.remain > 0) {
        ber.readSequence();
        let control = {
          tag: ber.readString(),
          criticality: ber.peek() === 1 ? ber.readBoolean() : false,
          controlValue: ber.peek() === 4 ? ber.readString() : ''
        };
        this.controls.push(control);
      }

    }

    return true;
  }
};
