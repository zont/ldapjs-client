const net = require('net');
const tls = require('tls');
const assert = require('assert-plus');
const Attribute = require('./attribute');
const Change = require('./change');
const { parse } = require('./dn');
const { getError, TimeoutError, ProtocolError, LDAP_SUCCESS } = require('./errors');
const { AddRequest, BindRequest, DeleteRequest, ModifyRequest, ModifyDNRequest, SearchRequest,
  UnbindRequest, UnbindResponse, LDAPResult, SearchEntry, SearchReference, Parser } = require('./messages');
const parseUrl = require('./utils/parse-url');

class Client {
  constructor(options) {
    assert.object(options, 'options');
    assert.optionalNumber(options.timeout, 'timeout');

    const url = options.url ? parseUrl(options.url) : null;
    delete url.search;

    Object.assign(this, options, url);

    this._queue = new Map();

    this._parser = new Parser();
    this._parser.on('error', e => console.error(e));
    this._parser.on('message', msg => {
      if (msg instanceof SearchEntry || msg instanceof SearchReference) {
        this._queue.get(msg.id).result.push(msg.object);
      } else {
        const { resolve, reject, result, type } = this._queue.get(msg.id);

        if (msg instanceof LDAPResult) {
          if (msg.status !== LDAP_SUCCESS) {
            reject(getError(msg));
          }

          resolve(type === 'SearchRequest' ? result : msg.object);
        } else if (msg instanceof Error) {
          reject(msg);
        } else {
          reject(new ProtocolError(msg.type));
        }

        this._queue.delete(msg.id);
      }
    });
  }

  async add(entry, attributes) {
    assert.string(entry, 'entry');
    assert.object(attributes, 'attributes');

    return this._send(new AddRequest({ entry, attributes: Attribute.fromObject(attributes) }));
  }

  async bind(name, credentials = '') {
    assert.string(name, 'name');
    assert.optionalString(credentials, 'credentials');

    return this._send(new BindRequest({ name, credentials }));
  }

  async del(entry) {
    assert.string(entry, 'entry');

    return this._send(new DeleteRequest({ entry }));
  }

  async modify(object, change) {
    assert.string(object, 'object');
    assert.object(change, 'change');

    const changes = [];
    (Array.isArray(change) ? change : [change]).forEach(c => changes.push(...Change.fromObject(c)));

    return this._send(new ModifyRequest({ object, changes }));
  }

  async modifyDN(entry, newName) {
    assert.string(entry, 'entry');
    assert.string(newName, 'newName');

    const newRdn = parse(newName);

    if (newRdn.rdns.length !== 1) {
      return this._send(new ModifyDNRequest({ entry, newRdn: parse(newRdn.rdns.shift().toString()), newSuperior: newRdn }));
    } else {
      return this._send(new ModifyDNRequest({ entry, newRdn }));
    }
  }

  async search(baseObject, options) {
    assert.string(baseObject, 'baseObject');
    assert.object(options, 'options');
    assert.optionalString(options.scope, 'options.scope');
    assert.optionalString(options.filter, 'options.filter');
    assert.optionalNumber(options.sizeLimit, 'options.sizeLimit');
    assert.optionalNumber(options.timeLimit, 'options.timeLimit');
    assert.optionalArrayOfString(options.attributes, 'options.attributes');

    return this._send(new SearchRequest(Object.assign({ baseObject }, options)));
  }

  async unbind() {
    return this._send(new UnbindRequest());
  }

  async destroy() {
    if (this._socket) {
      this._socket.removeAllListeners('error');
      this._socket.removeAllListeners('end');
      this._socket.removeAllListeners('close');
      this._socket.destroy();
      this._socket = null;
    }

    if (this._parser) {
      this._parser.removeAllListeners('error');
      this._parser.removeAllListeners('message');
      this._parser = null;
    }

    if (this._queue) {
      this._queue.clear();
      this._queue = null;
    }
  }

  async _connect() {
    return new Promise((resolve, reject) => {
      const errorHandler = err => {
        if (this._socket) {
          this._socket.destroy();
          this._socket = null;
        }
        reject(err || new Error('client error during setup'));
      };

      if (this.secure) {
        this._socket = tls.connect(this.port, this.host, this.tlsOptions);
        this._socket.once('secureConnect', resolve);
      } else {
        this._socket = net.connect(this.port, this.host);
        this._socket.once('connect', resolve);
      }

      this._socket.on('close', errorHandler);
      this._socket.on('end', errorHandler);
      this._socket.on('error', errorHandler);
      this._socket.on('timeout', errorHandler);
      this._socket.on('data', data => this._parser.write(data));
    });
  }

  async _send(message) {
    if (!this._socket) {
      await this._connect();
    }

    return new Promise((resolve, reject) => {
      try {
        this._queue.set(message.id, { resolve, reject, type: message.type, result: [] });
        this._socket.write(message.toBer());

        if (message.type === 'UnbindRequest') {
          this._queue.delete(message.id);
          resolve(new UnbindResponse());
        } else if (this.timeout) {
          setTimeout(() => {
            this._queue.delete(message.id);
            reject(new TimeoutError('request timeout (client interrupt)'));
          }, this.timeout);
        }
      } catch (e) {
        this._queue.delete(message.id);
        reject(e);
      }
    });
  }
}

module.exports = Client;
