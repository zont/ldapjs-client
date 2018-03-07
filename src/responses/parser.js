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

const getMessage = ber => {
  const id = ber.readInt() || 0;
  const type = ber.readSequence();
  const Message = MAP[type];

  if (!Message) {
    throw new Error(`Op 0x${type ? type.toString(16) : '??'} not supported`);
  }

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
      if (nextMessage) {
        this.parse(nextMessage);
      } else {
        this.emit('error', e);
      }
      return;
    }

    if (nextMessage) {
      this.parse(nextMessage);
    }
  }
}

module.exports = Parser;
