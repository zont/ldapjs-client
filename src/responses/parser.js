const EventEmitter = require('events').EventEmitter;
const assert = require('assert-plus');
const { BerReader } = require('asn1');
const Protocol = require('../utils/protocol');

const MAP = {
  [Protocol.LDAP_REP_ADD]: require('./add_response'),
  [Protocol.LDAP_REP_BIND]: require('./bind_response'),
  [Protocol.LDAP_REP_DELETE]: require('./del_response'),
  [Protocol.LDAP_REP_MODIFY]: require('./modify_response'),
  [Protocol.LDAP_REP_MODRDN]: require('./moddn_response'),
  [Protocol.LDAP_REP_SEARCH]: require('./search_response'),
  [Protocol.LDAP_REP_SEARCH_ENTRY]: require('./search_entry'),
  [Protocol.LDAP_REP_SEARCH_REF]: require('./search_reference')
};

class Parser extends EventEmitter {
  constructor() {
    super();
    this.buffer = null;
  }

  getMessage(ber) {
    assert.ok(ber);

    const id = ber.readInt() || 0;
    const type = ber.readSequence();
    const Message = MAP[type];

    if (!Message) {
      this.emit('error', new Error(`Op 0x${type ? type.toString(16) : '??'} not supported`));
      return false;
    }

    return new Message({ id });
  }

  write(data) {
    assert.buffer(data, 'data');

    let nextMessage = null;

    this.buffer = (this.buffer ? Buffer.concat([this.buffer, data]) : data);

    const ber = new BerReader(this.buffer);

    let foundSeq = false;
    try {
      foundSeq = ber.readSequence();
    } catch (e) {
      this.emit('error', e);
    }

    if (!foundSeq || ber.remain < ber.length) {
      return false;
    } else if (ber.remain > ber.length) {
      nextMessage = this.buffer.slice(ber.offset + ber.length);
      ber._size = ber.offset + ber.length;
      assert.equal(ber.remain, ber.length);
    }

    this.buffer = null;

    let message;
    try {
      message = this.getMessage(ber);

      if (!message) {
        return nextMessage ? this.write(nextMessage) : true;
      }
      message.parse(ber);
    } catch (e) {
      this.emit('error', e, message);
      return false;
    }

    this.emit('message', message);
    return nextMessage ? this.write(nextMessage) : true;
  }
}

module.exports = Parser;
