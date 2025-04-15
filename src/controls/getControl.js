const asn1 = require('asn1');
const Ber = asn1.Ber;
const BerReader = asn1.BerReader;
const OID = require('./OID');

module.exports = (ber) => {
  if (ber.readSequence() === null) { return null; }

  const control = {
    OID: '',
    criticality: false,
    value: null
  }

  if (ber.length) {
    const end = ber.offset + ber.length;

    control.OID = ber.readString();
    if (ber.offset < end) {
      if (ber.peek() === Ber.Boolean) { control.criticality = ber.readBoolean(); }
    }

    if (ber.offset < end) { control.value = ber.readString(Ber.OctetString, true); }

    if (control.OID === OID.PagedResults) {
      const ber = new BerReader(control.value);
      if (ber.readSequence()) {
        control.value = {};
        control.value.size = ber.readInt();
        control.value.cookie = ber.readString(asn1.Ber.OctetString, true);
        if ( control.value.cookie.length === 0 ) {
          control.value.cookie = '';
        }
      }
    }
  }

  return control;
}
