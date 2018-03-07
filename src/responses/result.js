const assert = require('assert-plus');
const LDAPMessage = require('./message');
const { LDAP_REP_REFERRAL } = require('../utils/protocol');

module.exports = class LDAPResult extends LDAPMessage {
  constructor(options) {
    options = options || {};
    assert.object(options);
    assert.optionalNumber(options.status);
    assert.optionalString(options.matchedDN);
    assert.optionalString(options.errorMessage);
    assert.optionalArrayOfString(options.referrals);

    super(Object.assign({ status: 0, matchedDN: '', errorMessage: '', referrals: [] }, options));
  }

  get type() {
    return 'LDAPResult';
  }

  _parse(ber) {
    assert.ok(ber);

    this.status = ber.readEnumeration();
    this.matchedDN = ber.readString();
    this.errorMessage = ber.readString();

    if (ber.peek() === LDAP_REP_REFERRAL) {
      const end = ber.offset + ber.length;
      while (ber.offset < end)
        this.referrals.push(ber.readString());
    }

    return true;
  }

  _toBer(ber) {
    assert.ok(ber);

    ber.writeEnumeration(this.status);
    ber.writeString(this.matchedDN || '');
    ber.writeString(this.errorMessage || '');

    if (this.referrals.length) {
      ber.startSequence(LDAP_REP_REFERRAL);
      ber.writeStringArray(this.referrals);
      ber.endSequence();
    }

    return ber;
  }
};
