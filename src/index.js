const EventEmitter = require('events').EventEmitter;
const net = require('net');
const tls = require('tls');

const once = require('once');
const backoff = require('backoff');
const vasync = require('vasync');
const assert = require('assert-plus');

const Attribute = require('./attribute');
const Change = require('./change');
const Protocol = require('./protocol');
const dn = require('./dn');
const { getError, AbandonedError, ConnectionError, TimeoutError, ProtocolError, LDAP_SUCCESS, LDAP_COMPARE_TRUE, LDAP_COMPARE_FALSE } = require('./errors');
const { parseString, isFilter, PresenceFilter } = require('./filters');
const {
  AbandonRequest,
  AddRequest,
  BindRequest,
  CompareRequest,
  DeleteRequest,
  ExtendedRequest,
  ModifyRequest,
  ModifyDNRequest,
  SearchRequest,
  UnbindRequest,
  UnbindResponse,
  LDAPResult,
  SearchEntry,
  SearchReference,
  Parser
} = require('./messages');
const parseUrl = require('./utils/parse-url');

///--- Globals

const CMP_EXPECT = [LDAP_COMPARE_TRUE, LDAP_COMPARE_FALSE];
const MAX_MSGID = Math.pow(2, 31) - 1;

let CLIENT_ID = 0;

///--- Internal Helpers

function nextClientId() {
  if (++CLIENT_ID === MAX_MSGID)
    return 1;

  return CLIENT_ID;
}

function ensureDN(input, strict) {
  if (dn.DN.isDN(input)) {
    return dn;
  } else if (strict) {
    return dn.parse(input);
  } else if (typeof (input) === 'string') {
    return input;
  } else {
    throw new Error('invalid DN');
  }
}

class RequestQueue {
  constructor(opts) {
    if (!opts || typeof (opts) !== 'object') {
      opts = {};
    }
    this.size = (opts.size > 0) ? opts.size : Infinity;
    this.timeout = (opts.timeout > 0) ? opts.timeout : 0;
    this._queue = [];
    this._timer = null;
    this._frozen = false;
  }

  enqueue(msg, expect, emitter, cb) {
    if (this._queue.length >= this.size || this._frozen) {
      return false;
    }
    this._queue.push([msg, expect, emitter, cb]);
    if (this.timeout > 0) {
      if (this._timer !== null) {
        this._timer = setTimeout(() => {
          this.freeze();
          this.purge();
        }, this.timeout);
      }
    }
    return true;
  }

  flush(cb) {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    const items = this._queue;
    this._queue = [];
    items.forEach(req => cb(...req));
  }

  purge() {
    this.flush((msg, expect, emitter, cb) => cb(new TimeoutError('request queue timeout')));
  }

  freeze() {
    this._frozen = true;
  }

  thaw() {
    this._frozen = false;
  }
}

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
    const self = this;
    function geWindow(ref, comp) {
      let max = ref + (MAX_MSGID / 2);
      const min = ref;
      if (max >= MAX_MSGID) {
        max = max - MAX_MSGID - 1;
        return ((comp <= max) || (comp >= min));
      } else {
        return ((comp <= max) && (comp >= min));
      }
    }

    Object.keys(this._abandoned).forEach(function (id) {
      if (geWindow(self._abandoned[id].age, msgid)) {
        self._abandoned[id].cb(new AbandonedError(
          'client request abandoned'));
        delete self._abandoned[id];
      }
    });
  }

  _nextID() {
    if (++this._msgid >= MAX_MSGID)
      this._msgid = 1;

    return this._msgid;
  }
}

class Client extends EventEmitter {
  constructor(options) {
    super(options);

    const _url = options.url ? parseUrl(options.url) : undefined;
    this.host = _url ? _url.hostname : undefined;
    this.port = _url ? _url.port : false;
    this.secure = _url ? _url.secure : false;
    this.url = _url;
    this.tlsOptions = options.tlsOptions;
    this.socketPath = options.socketPath || false;

    this.timeout = parseInt((options.timeout || 0), 10);
    this.connectTimeout = parseInt((options.connectTimeout || 0), 10);
    this.idleTimeout = parseInt((options.idleTimeout || 0), 10);
    if (options.reconnect) {
      const rOpts = (typeof (options.reconnect) === 'object') ? options.reconnect : {};
      this.reconnect = {
        initialDelay: parseInt(rOpts.initialDelay || 100, 10),
        maxDelay: parseInt(rOpts.maxDelay || 10000, 10),
        failAfter: parseInt(rOpts.failAfter, 10) || Infinity
      };
    }
    this.strictDN = (options.strictDN !== undefined) ? options.strictDN : true;

    this.queue = new RequestQueue({
      size: parseInt((options.queueSize || 0), 10),
      timeout: parseInt((options.queueTimeout || 0), 10)
    });
    if (options.queueDisable) {
      this.queue.freeze();
    }

    if (options.bindDN !== undefined &&
      options.bindCredentials !== undefined) {
      this.on('setup', (clt, cb) => clt.bind(options.bindDN, options.bindCredentials, (err) => {
        if (err) {
          this.emit('error', err);
        }
        cb(err);
      }));
    }

    this._socket = null;
    this.connected = false;
    this.connect();
  }

  abandon(messageID, callback) {
    assert.number(messageID, 'messageID');
    assert.func(callback, 'callback');

    const req = new AbandonRequest({ abandonID: messageID });

    return this._send(req, 'abandon', null, callback);
  }

  add(name, entry, callback) {
    assert.ok(name !== undefined, 'name');
    assert.object(entry, 'entry');
    assert.func(callback, 'callback');

    if (Array.isArray(entry)) {
      entry.forEach(function (a) {
        if (!Attribute.isAttribute(a))
          throw new TypeError('entry must be an Array of Attributes');
      });
    } else {
      const save = entry;

      entry = [];
      Object.keys(save).forEach(function (k) {
        const attr = new Attribute({ type: k });
        if (Array.isArray(save[k])) {
          save[k].forEach(function (v) {
            attr.addValue(v.toString());
          });
        } else {
          attr.addValue(save[k].toString());
        }
        entry.push(attr);
      });
    }

    const req = new AddRequest({ entry: ensureDN(name, this.strictDN), attributes: entry });

    return this._send(req, [LDAP_SUCCESS], null, callback);
  }

  bind(name, credentials, callback, _bypass) {
    if (typeof (name) !== 'string' && !(name instanceof dn.DN))
      throw new TypeError('name (string) required');
    assert.optionalString(credentials, 'credentials');
    assert.func(callback, 'callback');

    const req = new BindRequest({
      name: name || '',
      authentication: 'Simple',
      credentials: credentials || '',
    });

    return this._send(req, [LDAP_SUCCESS], null, callback, _bypass);
  }

  compare(name, attr, value, callback) {
    assert.ok(name !== undefined, 'name');
    assert.string(attr, 'attr');
    assert.string(value, 'value');
    assert.func(callback, 'callback');

    const req = new CompareRequest({
      entry: ensureDN(name, this.strictDN),
      attribute: attr,
      value
    });

    return this._send(req, CMP_EXPECT, null, function (err, res) {
      if (err)
        return callback(err);

      return callback(null, (res.status === LDAP_COMPARE_TRUE), res);
    });
  }

  del(name, callback) {
    assert.ok(name !== undefined, 'name');
    assert.func(callback, 'callback');

    const req = new DeleteRequest({ entry: ensureDN(name, this.strictDN) });

    return this._send(req, [LDAP_SUCCESS], null, callback);
  }

  exop(name, value, callback) {
    assert.string(name, 'name');
    if (typeof (value) === 'function') {
      callback = value;
      value = '';
    }
    if (!(Buffer.isBuffer(value) || typeof (value) === 'string'))
      throw new TypeError('value (Buffer || string) required');
    assert.func(callback, 'callback');

    const req = new ExtendedRequest({
      requestName: name,
      requestValue: value
    });

    return this._send(req, [LDAP_SUCCESS], null, function (err, res) {
      if (err)
        return callback(err);

      return callback(null, res.responseValue || '', res);
    });
  }

  modify(name, change, callback) {
    assert.ok(name !== undefined, 'name');
    assert.object(change, 'change');

    const changes = [];

    function changeFromObject(change) {
      if (!change.operation && !change.type)
        throw new Error('change.operation required');
      if (typeof (change.modification) !== 'object')
        throw new Error('change.modification (object) required');

      if (Object.keys(change.modification).length == 2 &&
        typeof (change.modification.type) === 'string' &&
        Array.isArray(change.modification.vals)) {
        changes.push(new Change({
          operation: change.operation || change.type,
          modification: change.modification
        }));
      } else {
        // Normalize the modification object
        Object.keys(change.modification).forEach(function (k) {
          const mod = {};
          mod[k] = change.modification[k];
          changes.push(new Change({
            operation: change.operation || change.type,
            modification: mod
          }));
        });
      }
    }

    if (Change.isChange(change)) {
      changes.push(change);
    } else if (Array.isArray(change)) {
      change.forEach(function (c) {
        if (Change.isChange(c)) {
          changes.push(c);
        } else {
          changeFromObject(c);
        }
      });
    } else {
      changeFromObject(change);
    }

    assert.func(callback, 'callback');

    const req = new ModifyRequest({
      object: ensureDN(name, this.strictDN),
      changes
    });

    return this._send(req, [LDAP_SUCCESS], null, callback);
  }

  modifyDN(name, newName, callback) {
    assert.ok(name !== undefined, 'name');
    assert.string(newName, 'newName');
    assert.func(callback);

    const DN = ensureDN(name);
    const newDN = dn.parse(newName);

    const req = new ModifyDNRequest({
      entry: DN,
      deleteOldRdn: true
    });

    if (newDN.length !== 1) {
      req.newRdn = dn.parse(newDN.rdns.shift().toString());
      req.newSuperior = newDN;
    } else {
      req.newRdn = newDN;
    }

    return this._send(req, [LDAP_SUCCESS], null, callback);
  }

  search(base, options, callback, _bypass) {
    assert.ok(base !== undefined, 'search base');
    if (typeof (options) === 'function') {
      callback = options;
      options = {
        filter: new PresenceFilter({ attribute: 'objectclass' })
      };
    } else if (typeof (options) === 'string') {
      options = { filter: parseString(options) };
    } else if (typeof (options) !== 'object') {
      throw new TypeError('options (object) required');
    }
    if (typeof (options.filter) === 'string') {
      options.filter = parseString(options.filter);
    } else if (!options.filter) {
      options.filter = new PresenceFilter({ attribute: 'objectclass' });
    } else if (!isFilter(options.filter)) {
      throw new TypeError('options.filter (Filter) required');
    }
    assert.func(callback, 'callback');

    if (options.attributes) {
      if (!Array.isArray(options.attributes)) {
        if (typeof (options.attributes) === 'string') {
          options.attributes = [options.attributes];
        } else {
          throw new TypeError('options.attributes must be an Array of Strings');
        }
      }
    }

    const baseDN = ensureDN(base, this.strictDN);

    const req = new SearchRequest({
      baseObject: baseDN,
      scope: options.scope || 'base',
      filter: options.filter,
      derefAliases: options.derefAliases || Protocol.NEVER_DEREF_ALIASES,
      sizeLimit: options.sizeLimit || 0,
      timeLimit: options.timeLimit || 10,
      typesOnly: options.typesOnly || false,
      attributes: options.attributes || []
    });

    return this._send(req, [LDAP_SUCCESS], new EventEmitter(), callback, _bypass);
  }

  unbind(callback) {
    if (!callback)
      callback = function () { };

    if (typeof (callback) !== 'function')
      throw new TypeError('callback must be a function');

    this.unbound = true;

    if (!this._socket)
      return callback();

    const req = new UnbindRequest();
    return this._send(req, 'unbind', null, callback);
  }

  starttls(options, callback, _bypass) {
    assert.optionalObject(options);
    options = options || {};
    callback = once(callback);
    const self = this;

    if (this._starttls) {
      return callback(new Error('STARTTLS already in progress or active'));
    }

    function onSend(err, emitter) {
      if (err) {
        callback(err);
        return;
      }
      self._starttls = {
        started: true
      };

      emitter.on('error', function (err) {
        self._starttls = null;
        callback(err);
      });
      emitter.on('end', function () {
        const sock = self._socket;
        sock.removeAllListeners('data');

        options.socket = sock;
        const secure = tls.connect(options);
        secure.once('secureConnect', function () {
          secure.removeAllListeners('error');
          secure.on('data', function onData(data) {
            self._tracker.parser.write(data);
          });
          secure.on('error', function (err) {
            self.emit('error', err);
            sock.destroy();
          });
          callback(null);
        });
        secure.once('error', function (err) {
          // If the SSL negotiation failed, to back to plain mode.
          self._starttls = null;
          secure.removeAllListeners();
          callback(err);
        });
        self._starttls.success = true;
        self._socket = secure;
      });
    }

    const req = new ExtendedRequest({
      requestName: '1.3.6.1.4.1.1466.20037',
      requestValue: null
    });

    return this._send(req,
      [LDAP_SUCCESS],
      new EventEmitter(),
      onSend,
      _bypass);
  }

  destroy(err) {
    this.destroyed = true;
    this.queue.freeze();
    // Purge any queued requests which are now meaningless
    this.queue.flush(function (msg, expect, emitter, cb) {
      if (typeof (cb) === 'function') {
        cb(new Error('client destroyed'));
      }
    });
    if (this.connected) {
      this.unbind();
    } else if (this._socket) {
      this._socket.destroy();
    }
    this.emit('destroy', err);
  }

  connect() {
    if (this.connecting || this.connected) {
      return;
    }
    const self = this;
    let socket;
    let tracker;

    function connectSocket(cb) {
      cb = once(cb);

      function onResult(err, res) {
        if (err) {
          if (self.connectTimer) {
            clearTimeout(self.connectTimer);
            self.connectTimer = null;
          }
          self.emit('connectError', err);
        }
        cb(err, res);
      }
      function onConnect() {
        if (self.connectTimer) {
          clearTimeout(self.connectTimer);
          self.connectTimer = null;
        }
        socket.removeAllListeners('error')
          .removeAllListeners('connect')
          .removeAllListeners('secureConnect');

        tracker.id = nextClientId() + '__' + tracker.id;

        // Move on to client setup
        setupClient(cb);
      }

      const port = (self.port || self.socketPath);
      if (self.secure) {
        socket = tls.connect(port, self.host, self.tlsOptions);
        socket.once('secureConnect', onConnect);
      } else {
        socket = net.connect(port, self.host);
        socket.once('connect', onConnect);
      }
      socket.once('error', onResult);
      initSocket();

      if (self.connectTimeout) {
        self.connectTimer = setTimeout(function onConnectTimeout() {
          if (!socket || !socket.readable || !socket.writeable) {
            socket.destroy();
            self._socket = null;
            onResult(new ConnectionError('connection timeout'));
          }
        }, self.connectTimeout);
      }
    }

    function initSocket() {
      tracker = new MessageTracker({
        id: self.url ? self.url.href : self.socketPath,
        parser: new Parser()
      });

      if (typeof (socket.setKeepAlive) !== 'function') {
        socket.setKeepAlive = function setKeepAlive(enable, delay) {
          return socket.socket ?
            socket.socket.setKeepAlive(enable, delay) : false;
        };
      }

      socket.on('data', function onData(data) {
        tracker.parser.write(data);
      });

      tracker.parser.on('message', function onMessage(message) {
        message.connection = self._socket;
        const callback = tracker.fetch(message.messageID);

        if (!callback) {
          return false;
        }

        return callback(message);
      });

      tracker.parser.on('error', function onParseError(err) {
        self.emit('error', err);
        self.connected = false;
        socket.end();
      });
    }

    function setupClient(cb) {
      cb = once(cb);

      function bail(err) {
        socket.destroy();
        cb(err || new Error('client error during setup'));
      }
      ((socket.socket) ? socket.socket : socket).once('close', bail);
      socket.once('error', bail);
      socket.once('end', bail);
      socket.once('timeout', bail);

      self._socket = socket;
      self._tracker = tracker;

      const basicClient = {
        bind: function bindBypass(name, credentials,  callback) {
          return self.bind(name, credentials, callback, true);
        },
        search: function searchBypass(base, options, callback) {
          return self.search(base, options, callback, true);
        },
        starttls: function starttlsBypass(options, callback) {
          return self.starttls(options, callback, true);
        },
        unbind: self.unbind.bind(self)
      };
      vasync.forEachPipeline({
        func: function (f, callback) {
          f(basicClient, callback);
        },
        inputs: self.listeners('setup')
      }, function (err) {
        if (err) {
          self.emit('setupError', err);
        }
        cb(err);
      });
    }

    function postSetup() {
      socket.removeAllListeners('error')
        .removeAllListeners('close')
        .removeAllListeners('end')
        .removeAllListeners('timeout');

      ((socket.socket) ? socket.socket : socket).once('close',
        self._onClose.bind(self));
      socket.on('end', function onEnd() {
        self.emit('end');
        socket.end();
      });
      socket.on('error', function onSocketError(err) {
        self.emit('error', err);
        socket.destroy();
      });
      socket.on('timeout', function onTimeout() {
        self.emit('socketTimeout');
        socket.end();
      });
    }

    let retry;
    let failAfter;
    if (this.reconnect) {
      retry = backoff.exponential({
        initialDelay: this.reconnect.initialDelay,
        maxDelay: this.reconnect.maxDelay
      });
      failAfter = this.reconnect.failAfter;
    } else {
      retry = backoff.exponential({
        initialDelay: 1,
        maxDelay: 2
      });
      failAfter = 1;
    }
    retry.failAfter(failAfter);

    retry.on('ready', function () {
      if (self.destroyed) {
        return;
      }
      connectSocket(function (err) {
        if (!err) {
          postSetup();
          self.connecting = false;
          self.connected = true;
          self.emit('connect', socket);
          // Flush any queued requests
          self._flushQueue();
          self._connectRetry = null;
        } else {
          retry.backoff(err);
        }
      });
    });
    retry.on('fail', function (err) {
      if (self.destroyed) {
        return;
      }
      if (err instanceof ConnectionError) {
        self.emit('connectTimeout', err);
      } else {
        self.emit('error', err);
      }
    });

    this._connectRetry = retry;
    this.connecting = true;
    retry.backoff();
  }

  _flushQueue() {
    this.queue.flush(this._send.bind(this));
  }

  _onClose(had_err) {
    const socket = this._socket;
    const tracker = this._tracker;
    socket.removeAllListeners('connect')
      .removeAllListeners('data')
      .removeAllListeners('drain')
      .removeAllListeners('end')
      .removeAllListeners('error')
      .removeAllListeners('timeout');
    this._socket = null;
    this.connected = false;

    ((socket.socket) ? socket.socket : socket).removeAllListeners('close');

    this.emit('close', had_err);
    tracker.pending.forEach(function (msgid) {
      const cb = tracker.fetch(msgid);
      tracker.remove(msgid);

      if (socket.unbindMessageID !== parseInt(msgid, 10)) {
        return cb(new ConnectionError(tracker.id + ' closed'));
      } else {
        // Unbinds will be communicated as a success since we're closed
        const unbind = new UnbindResponse({ messageID: msgid });
        unbind.status = 'unbind';
        return cb(unbind);
      }
    });

    this._tracker = null;
    delete this._starttls;

    if (this.reconnect && !this.unbound) {
      this.connect();
    }
    this.unbound = false;
    return false;
  }

  _updateIdle(override) {
    if (this.idleTimeout === 0) {
      return;
    }
    const self = this;
    function isIdle(disable) {
      return ((disable !== true) &&
        (self._socket && self.connected) &&
        (self._tracker.pending.length === 0));
    }
    if (isIdle(override)) {
      if (!this._idleTimer) {
        this._idleTimer = setTimeout(function () {
          if (isIdle()) {
            self.emit('idle');
          }
        }, this.idleTimeout);
      }
    } else {
      if (this._idleTimer) {
        clearTimeout(this._idleTimer);
        this._idleTimer = null;
      }
    }
  }

  _send(message, expect, emitter, callback, _bypass) {
    assert.ok(message);
    assert.ok(expect);
    assert.optionalObject(emitter);
    assert.ok(callback);

    if (_bypass && this._socket && this._socket.writable) {
      return this._sendSocket(message, expect, emitter, callback);
    }
    if (!this._socket || !this.connected) {
      if (!this.queue.enqueue(message, expect, emitter, callback)) {
        callback(new ConnectionError('connection unavailable'));
      }
      if (this.reconnect) {
        this.connect();
      }
      return false;
    } else {
      this._flushQueue();
      return this._sendSocket(message, expect, emitter, callback);
    }
  }

  _sendSocket(message, expect, emitter, callback) {
    const conn = this._socket;
    const tracker = this._tracker;
    const self = this;
    let timer = false;
    let sentEmitter = false;

    function sendResult(event, obj) {
      if (event === 'error' && self.listeners('resultError')) {
        self.emit('resultError', obj);
      }
      if (emitter) {
        if (event === 'error') {
          if (!sentEmitter)
            return callback(obj);
        }
        return emitter.emit(event, obj);
      }

      if (event === 'error')
        return callback(obj);

      return callback(null, obj);
    }

    function messageCallback(msg) {
      if (timer)
        clearTimeout(timer);

      if (expect === 'abandon')
        return sendResult('end', null);

      if (msg instanceof SearchEntry || msg instanceof SearchReference) {
        const event = msg.constructor.name;
        return sendResult(event[0].toLowerCase() + event.slice(1), msg);
      } else {
        tracker.remove(message.messageID);
        self._updateIdle();

        if (msg instanceof LDAPResult) {
          if (expect.indexOf(msg.status) === -1) {
            return sendResult('error', getError(msg));
          }
          return sendResult('end', msg);
        } else if (msg instanceof Error) {
          return sendResult('error', msg);
        } else {
          return sendResult('error', new ProtocolError(msg.type));
        }
      }
    }

    function onRequestTimeout() {
      self.emit('timeout', message);
      const cb = tracker.fetch(message.messageID);
      if (cb) {
        cb(new TimeoutError('request timeout (client interrupt)'));
      }
    }

    function writeCallback() {
      if (expect === 'abandon') {
        tracker.abandon(message.abandonID);
        tracker.remove(message.id);
        return callback(null);
      } else if (expect === 'unbind') {
        conn.unbindMessageID = message.id;
        self.connected = false;
        conn.removeAllListeners('error');
        conn.on('error', function () { });
        conn.end();
      } else if (emitter) {
        sentEmitter = true;
        return callback(null, emitter);
      }
      return false;
    }

    tracker.track(message, messageCallback);
    this._updateIdle(true);

    if (self.timeout) {
      timer = setTimeout(onRequestTimeout, self.timeout);
    }

    try {
      return conn.write(message.toBer(), writeCallback);
    } catch (e) {
      if (timer)
        clearTimeout(timer);

      return callback(e);
    }
  }
}

module.exports = Client;
