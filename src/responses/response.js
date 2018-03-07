const assert = require('assert-plus');
const { LDAP_REP_REFERRAL } = require('../utils/protocol');

module.exports = class {
  constructor(options) {
    assert.optionalNumber(options.status);
    assert.optionalString(options.matchedDN);
    assert.optionalString(options.errorMessage);
    assert.optionalArrayOfString(options.referrals);

    Object.assign(this, { status: 0, matchedDN: '', errorMessage: '', referrals: [], type: 'Response' }, options);
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

    return true;
  }
};
