const EventEmitter = require('events').EventEmitter;
const assert = require('assert-plus');
const { BerReader } = require('asn1');
const LDAPResult = require('./result');
const Protocol = require('../protocol');

const MAP = {
  [Protocol.LDAP_REQ_ABANDON]: require('./abandon_request'),
  [Protocol.LDAP_REQ_ADD]: require('./add_request'),
  [Protocol.LDAP_REP_ADD]: require('./add_response'),
  [Protocol.LDAP_REQ_BIND]: require('./bind_request'),
  [Protocol.LDAP_REP_BIND]: require('./bind_response'),
  [Protocol.LDAP_REQ_COMPARE]: require('./compare_request'),
  [Protocol.LDAP_REP_COMPARE]: require('./compare_response'),
  [Protocol.LDAP_REQ_DELETE]: require('./del_request'),
  [Protocol.LDAP_REP_DELETE]: require('./del_response'),
  [Protocol.LDAP_REQ_EXTENSION]: require('./ext_request'),
  [Protocol.LDAP_REP_EXTENSION]: require('./ext_response'),
  [Protocol.LDAP_REQ_MODIFY]: require('./modify_request'),
  [Protocol.LDAP_REP_MODIFY]: require('./modify_response'),
  [Protocol.LDAP_REQ_MODRDN]: require('./moddn_request'),
  [Protocol.LDAP_REP_MODRDN]: require('./moddn_response'),
  [Protocol.LDAP_REQ_SEARCH]: require('./search_request'),
  [Protocol.LDAP_REP_SEARCH]: require('./search_response'),
  [Protocol.LDAP_REP_SEARCH_ENTRY]: require('./search_entry'),
  [Protocol.LDAP_REP_SEARCH_REF]: require('./search_reference'),
  [Protocol.LDAP_REQ_UNBIND]: require('./unbind_request')
};

class Parser extends EventEmitter {
  constructor() {
    super();
    this.buffer = null;
  }

  getMessage(ber) {
    assert.ok(ber);

    const messageID = ber.readInt();
    const type = ber.readSequence();
    const Message = MAP[type];

    if (!Message) {
      this.emit('error', new Error(`Op 0x${type ? type.toString(16) : '??'} not supported`), new LDAPResult({ messageID, protocolOp: type || Protocol.LDAP_REP_EXTENSION }));
      return false;
    }

    return new Message({ messageID });
  }

  write(data) {
    if (!data || !Buffer.isBuffer(data))
      throw new TypeError('data (buffer) required');

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
