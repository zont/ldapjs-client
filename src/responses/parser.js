const EventEmitter = require('events').EventEmitter;
const assert = require('assert-plus');
const { BerReader } = require('asn1');
const { LDAP_REP_SEARCH_ENTRY, LDAP_REP_SEARCH_REF } = require('../utils/protocol');
const SearchEntry = require('./search_entry');
const SearchReference = require('./search_reference');
const Response = require('./response');

const getMessage = ber => {
  const id = ber.readInt() || 0;
  const type = ber.readSequence();
  const Message = type === LDAP_REP_SEARCH_ENTRY
    ? SearchEntry
    : type === LDAP_REP_SEARCH_REF
      ? SearchReference
      : Response;

  return new Message({ id });
};

class Parser extends EventEmitter {
  constructor() {
    super();
    this.buffer = null;
  }

  parse(data) {
    assert.buffer(data, 'data');

    this.buffer = this.buffer ? Buffer.concat([this.buffer, data]) : data;

    const ber = new BerReader(this.buffer);

    try {
      ber.readSequence();
    } catch (e) {
      this.emit('error', e);
      return;
    }

    if (ber.remain < ber.length) {
      return;
    }

    let nextMessage = null;
    if (ber.remain > ber.length) {
      nextMessage = this.buffer.slice(ber.offset + ber.length);
      ber._size = ber.offset + ber.length;
      assert.equal(ber.remain, ber.length);
    }

    this.buffer = null;

    try {
      const message = getMessage(ber);
      message.parse(ber);
      this.emit('message', message);
    } catch (e) {
      this.emit('error', e);
    }

    if (nextMessage) {
      this.parse(nextMessage);
    }
  }
}

module.exports = Parser;
