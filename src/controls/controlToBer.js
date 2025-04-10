const OID = require('./OID');
const asn1 = require('asn1')
const BerWriter = asn1.BerWriter;

module.exports = (control, writer) => {
    writer.startSequence();
    writer.writeString(control.OID);
    writer.writeBoolean(control.criticality);

    if (control.OID === OID.PagedResults) {
        const ber = new BerWriter();
        ber.startSequence();
        ber.writeInt(control.value.size);
        if ( control.value.cookie === '' ) {
            ber.writeString('');
        } else {
            ber.writeBuffer(control.value.cookie, asn1.Ber.OctetString);
        }
        ber.endSequence();
        writer.writeBuffer(ber.buffer, 0x04);
	}
	
	writer.endSequence();
}