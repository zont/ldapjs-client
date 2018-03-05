const net = require('net');
const tls = require('tls');
const assert = require('assert-plus');
const Attribute = require('./attribute');
const Change = require('./change');
const { NEVER_DEREF_ALIASES } = require('./protocol');
const dn = require('./dn');
const { getError, TimeoutError, ProtocolError, LDAP_SUCCESS } = require('./errors');
const { parseString, isFilter, PresenceFilter } = require('./filters');
const { AddRequest, BindRequest, DeleteRequest, ModifyRequest, ModifyDNRequest, SearchRequest,
  UnbindRequest, LDAPResult, SearchEntry, SearchReference, Parser } = require('./messages');
const parseUrl = require('./utils/parse-url');


const ensureDN = (input, strict) => {
  if (dn.DN.isDN(input)) {
    return dn;
  } else if (strict) {
    return dn.parse(input);
  } else if (typeof input === 'string') {
    return input;
  } else {
    throw new Error('invalid DN');
  }
};

const changeFromObject = change => {
  assert.ok(change.operation || change.type, 'change.operation required');
  assert.object(change.modification, 'change.modification');

  if (Object.keys(change.modification).length == 2 && typeof change.modification.type === 'string' && Array.isArray(change.modification.vals)) {
    return [new Change({
      operation: change.operation || change.type,
      modification: change.modification
    })];
  } else {
    return Object.keys(change.modification).map(k => new Change({
      operation: change.operation || change.type,
      modification: {
        [k]: change.modification[k]
      }
    }));
  }
};


class Client {
  constructor(options) {
    assert.object(options, 'options');
    assert.optionalNumber(options.timeout, 'timeout');

    const url = options.url ? parseUrl(options.url) : null;
    delete url.search;

    Object.assign(this, { strictDN: true }, options, url);

    let searchEntries = [];
    this._parser = new Parser();
    this._parser.on('error', e => this._reject(e));
    this._parser.on('message', msg => {
      if (msg instanceof SearchEntry || msg instanceof SearchReference) {
        searchEntries.push(msg.object);
      } else {
        if (msg instanceof LDAPResult) {
          if (msg.status !== LDAP_SUCCESS) {
            this._reject(getError(msg));
          }

          if (searchEntries.length > 0) {
            this._resolve(searchEntries.slice());
            searchEntries.length = 0;
          } else {
            this._resolve(msg);
          }
        } else if (msg instanceof Error) {
          this._reject(msg);
        } else {
          this._reject(new ProtocolError(msg.type));
        }
      }
    });
  }

  async add(name, attributes) {
    assert.ok(name !== undefined, 'name');
    assert.object(attributes, 'attributes');

    if (Array.isArray(attributes)) {
      if (attributes.some(a => !Attribute.isAttribute(a))) {
        throw new TypeError('entry must be an Array of Attributes');
      }
    } else {
      attributes = Object.keys(attributes).map(k => {
        const attr = new Attribute({ type: k });

        if (Array.isArray(attributes[k])) {
          attributes[k].forEach(v => attr.addValue(v.toString()));
        } else {
          attr.addValue(attributes[k].toString());
        }

        return attr;
      });
    }

    return this._send(new AddRequest({ entry: ensureDN(name, this.strictDN), attributes }));
  }

  async bind(name, credentials = '') {
    assert.ok(typeof name === 'string' || name instanceof dn.DN, 'name (string) required');
    assert.optionalString(credentials, 'credentials');

    return this._send(new BindRequest({ authentication: 'Simple', name, credentials }));
  }

  async del(name) {
    assert.ok(name !== undefined, 'name');
    return this._send(new DeleteRequest({ entry: ensureDN(name, this.strictDN) }));
  }

  async modify(name, change) {
    assert.ok(name !== undefined, 'name');
    assert.object(change, 'change');

    change = Array.isArray(change) ? change : [change];

    const changes = [];
    change.forEach(c => {
      if (Change.isChange(c)) {
        changes.push(c);
      } else {
        changes.push(...changeFromObject(c));
      }
    });

    return this._send(new ModifyRequest({ object: ensureDN(name, this.strictDN), changes }));
  }

  async modifyDN(name, newName) {
    assert.ok(name !== undefined, 'name');
    assert.string(newName, 'newName');

    const newDN = dn.parse(newName);
    const req = new ModifyDNRequest({ entry: ensureDN(name), deleteOldRdn: true });

    if (newDN.length !== 1) {
      req.newRdn = dn.parse(newDN.rdns.shift().toString());
      req.newSuperior = newDN;
    } else {
      req.newRdn = newDN;
    }

    return this._send(req);
  }

  async search(base, options) {
    if (typeof options === 'string') {
      options = { filter: options };
    }

    assert.ok(base, 'search base');
    assert.object(options, 'options');

    if (typeof (options.filter) === 'string') {
      options.filter = parseString(options.filter);
    } else if (!options.filter) {
      options.filter = new PresenceFilter({ attribute: 'objectclass' });
    } else if (!isFilter(options.filter)) {
      throw new TypeError('options.filter (Filter) required');
    }

    if (options.attributes) {
      if (typeof (options.attributes) === 'string') {
        options.attributes = [options.attributes];
      }

      assert.arrayOfString(options.attributes, 'options.attributes');
    }

    return this._send(new SearchRequest({
      baseObject: ensureDN(base, this.strictDN),
      scope: options.scope || 'base',
      filter: options.filter,
      derefAliases: options.derefAliases || NEVER_DEREF_ALIASES,
      sizeLimit: options.sizeLimit || 0,
      timeLimit: options.timeLimit || 10,
      typesOnly: options.typesOnly || false,
      attributes: options.attributes || []
    }));
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
  }

  async _connect() {
    return new Promise((resolve, reject) => {
      const errorHandler = err => {
        this._socket.destroy();
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
        this._resolve = resolve;
        this._reject = reject;

        this._socket.write(message.toBer());

        if (this.timeout) {
          setTimeout(() => reject(new TimeoutError('request timeout (client interrupt)')), this.timeout);
        }
      } catch (e) {
        reject(e);
      }
    });
  }
}

module.exports = Client;
