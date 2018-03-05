const { AbandonedError } = require('./errors');
const MAX_MSGID = Math.pow(2, 31) - 1;

class MessageTracker {
  constructor(opts) {
    Object.assign(this, opts);

    this._msgid = 0;
    this._messages = {};
    this._abandoned = {};

    this.__defineGetter__('pending', () => Object.keys(this._messages));
  }

  track(message, callback) {
    message.messageID = this._nextID();
    this._messages[message.messageID] = callback;
    return message.messageID;
  }

  fetch(msgid) {
    let msg = this._messages[msgid];
    if (msg) {
      this._purgeAbandoned(msgid);
      return msg;
    }
    msg = this._abandoned[msgid];
    if (msg) {
      return msg.cb;
    }
    return null;
  }

  remove(msgid) {
    if (this._messages[msgid]) {
      delete this._messages[msgid];
    } else if (this._abandoned[msgid]) {
      delete this._abandoned[msgid];
    }
  }

  abandonMsg(msgid) {
    if (this._messages[msgid]) {
      this._abandoned[msgid] = {
        age: this._msgid,
        cb: this._messages[msgid]
      };
      delete this._messages[msgid];
    }
  }

  _purgeAbandoned(msgid) {
    const geWindow = (ref, comp) => {
      let max = ref + (MAX_MSGID / 2);
      const min = ref;
      if (max >= MAX_MSGID) {
        max = max - MAX_MSGID - 1;
        return ((comp <= max) || (comp >= min));
      } else {
        return ((comp <= max) && (comp >= min));
      }
    };

    Object.keys(this._abandoned).forEach(id => {
      if (geWindow(this._abandoned[id].age, msgid)) {
        this._abandoned[id].cb(new AbandonedError('client request abandoned'));
        delete this._abandoned[id];
      }
    });
  }

  _nextID() {
    if (++this._msgid >= MAX_MSGID)
      this._msgid = 1;

    return this._msgid;
  }
}

MessageTracker.MAX_MSGID = MAX_MSGID;

module.exports = MessageTracker;
