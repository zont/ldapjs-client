const assert = require('assert-plus');
const asn1 = require('asn1');
const Ber = asn1.Ber;
const BerReader = asn1.BerReader;
const { LDAP_REP_REFERRAL, LDAP_CONTROLS } = require('../utils/protocol');
const OID = require('../utils/OID');

const getControl = (ber) => {
  if (ber.readSequence() === null) { return null; }

  const control = {
    OID: '',
    criticality: false,
    value: null
  };

  if (ber.length) {
    const end = ber.offset + ber.length;

    control.OID = ber.readString();
    if (ber.offset < end && ber.peek() === Ber.Boolean) control.criticality = ber.readBoolean();

    if (ber.offset < end) control.value = ber.readString(Ber.OctetString, true);

    const controlBer = new BerReader(control.value);
    switch (control.OID) {
      case OID.PagedResults:
        controlBer.readSequence();
        control.value = {};
        control.value.size = controlBer.readInt();
        control.value.cookie = controlBer.readString(asn1.Ber.OctetString, true);
        if (control.value.cookie.length === 0) {
          control.value.cookie = '';
        }
        break;
      // Add New OID controls here
      default:
    }
  }

  return control;
};

module.exports = class {
  constructor(options) {
    assert.optionalNumber(options.status);
    assert.optionalString(options.matchedDN);
    assert.optionalString(options.errorMessage);
    assert.optionalArrayOfString(options.referrals);
    assert.optionalArrayOfObject(options.controls);

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
      const end = ber.offset + ber.length;
      while (ber.offset < end) {
        const c = getControl(ber);
        if (c) { this.controls.push(c); }
      }
    }

    return true;
  }
};
