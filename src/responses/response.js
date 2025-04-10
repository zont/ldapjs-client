const assert = require('assert-plus');
const { LDAP_REP_REFERRAL } = require('../utils/protocol');
const getControl = require('../controls/getControl');

module.exports = class {
  constructor(options) {
    assert.optionalNumber(options.status);
    assert.optionalString(options.matchedDN);
    assert.optionalString(options.errorMessage);
    assert.optionalArrayOfString(options.referrals);

    Object.assign(this, { status: 0, matchedDN: '', errorMessage: '', referrals: [], type: 'Response' }, options);
    this.controls = [];
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
    
    if (ber.peek() === 0xa0) {
      ber.readSequence()
      const end = ber.offset + ber.length;
      while (ber.offset < end) {
        const c = getControl(ber);
        if (c) { this.controls.push(c); }
      }
    }

    return true;
  }
};