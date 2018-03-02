const assert = require('assert-plus');
const LDAPMessage = require('./message');
const { LDAP_REP_REFERRAL } = require('../protocol');

module.exports = class LDAPResult extends LDAPMessage {
  constructor(options) {
    options = options || {};
    assert.object(options);
    assert.optionalNumber(options.status);
    assert.optionalString(options.matchedDN);
    assert.optionalString(options.errorMessage);
    assert.optionalArrayOfString(options.referrals);

    super(options);

    this.status = options.status || 0; // LDAP SUCCESS
    this.matchedDN = options.matchedDN || '';
    this.errorMessage = options.errorMessage || '';
    this.referrals = options.referrals || [];
    this.connection = options.connection || null;
  }

  get type() {
    return 'LDAPResult';
  }

  end(status) {
    assert.ok(this.connection);

    if (typeof status === 'number') {
      this.status = status;
    }

    try {
      this.connection.write(this.toBer());
    } catch (e) {
      console.warn(e, '%s failure to write message %j', this.connection.ldap.id, this.json);
    }
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

  _json(j) {
    assert.ok(j);

    j.status = this.status;
    j.matchedDN = this.matchedDN;
    j.errorMessage = this.errorMessage;
    j.referrals = this.referrals;

    return j;
  }
};
