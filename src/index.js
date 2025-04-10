const net = require('net');
const tls = require('tls');
const assert = require('assert-plus');
const Attribute = require('./attribute');
const Change = require('./change');
const { parse } = require('./dn');
const { getError, ConnectionError, TimeoutError, ProtocolError, LDAP_SUCCESS } = require('./errors');
const { Add, Bind, Del, Modify, ModifyDN, Search, Unbind } = require('./requests');
const { Response, SearchEntry, SearchReference, Parser } = require('./responses');
const parseUrl = require('./utils/parse-url');
const OID = require('./controls/OID');

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
        const qItem = this._queue.get(msg.id);
        if (qItem) {
          const { resolve, reject, result, request, controls } = qItem;

          if (msg instanceof Response) {
            if (msg.status !== LDAP_SUCCESS) {
              reject(getError(msg));
            }
            
            controls.length = 0;
            msg.controls.forEach((control) => {
              controls.push(control);
            });

            resolve(request instanceof Search ? result : msg.object);
          } else if (msg instanceof Error) {
            reject(msg);
          } else {
            reject(new ProtocolError(msg.type));
          }

          this._queue.delete(msg.id);
        }
      }
    });
  }

  async add(entry, attributes, controls = []) {
    assert.string(entry, 'entry');
    assert.object(attributes, 'attributes');
    assert.arrayOfObject(controls, 'controls');

    return this._send(new Add({ entry, attributes: Attribute.fromObject(attributes), controls}));
  }

  async bind(name, credentials, controls = []) {
    assert.string(name, 'name');
    assert.optionalString(credentials, 'credentials');
    assert.arrayOfObject(controls, 'controls');

    return this._send(new Bind({ name, credentials, controls }));
  }

  async del(entry, controls = []) {
    assert.string(entry, 'entry');
    assert.arrayOfObject(controls, 'controls');

    return this._send(new Del({ entry, controls }));
  }

  async modify(entry, change, controls = []) {
    assert.string(entry, 'entry');
    assert.object(change, 'change');
    assert.arrayOfObject(controls, 'controls');

    const changes = [];
    (Array.isArray(change) ? change : [change]).forEach(c => changes.push(...Change.fromObject(c)));

    return this._send(new Modify({ entry, changes, controls }));
  }

  async modifyDN(entry, newName, controls = []) {
    assert.string(entry, 'entry');
    assert.string(newName, 'newName');
    assert.arrayOfObject(controls, 'controls');

    const newRdn = parse(newName);

    if (newRdn.rdns.length !== 1) {
      return this._send(new ModifyDN({ entry, newRdn: parse(newRdn.rdns.shift().toString()), newSuperior: newRdn, controls }));
    } else {
      return this._send(new ModifyDN({ entry, newRdn, controls }));
    }
  }

  async search(baseObject, options, controls = []) {
    assert.string(baseObject, 'baseObject');
    assert.object(options, 'options');
    assert.optionalString(options.scope, 'options.scope');
    assert.optionalString(options.filter, 'options.filter');
    assert.optionalNumber(options.sizeLimit, 'options.sizeLimit');
    assert.optionalNumber(options.pageSize, 'options.pageSize');
    assert.optionalNumber(options.timeLimit, 'options.timeLimit');
    assert.optionalArrayOfString(options.attributes, 'options.attributes');
    assert.arrayOfObject(controls, 'controls');
    
    if ( typeof options.pageSize === 'number' ) {
      let pageSize = options.pageSize;
      delete options.pageSize;
      if ( pageSize < 50 ) { pageSize = 500; }
      if ( pageSize > 1000 ) { pageSize = 1000; }
      options.sizeLimit = pageSize + 1;
      
      const controls0 = controls.filter((control) => {
        return control.OID !== OID.PagedResults;
      });
      
      const pagedResults = {
        OID: OID.PagedResults,
        criticality: true,
        value: {
          size: pageSize,
          cookie: ''
        }
      };
      
      let cookie = '';
      const results = [];
      
      while(true) {
        pagedResults.value.cookie = cookie;
        controls.length = 0;
        controls0.forEach((conrol) => {
          controls.push(control);
        });
        controls.push(pagedResults);
        
        results.push(await this._send(new Search(Object.assign({ baseObject, controls }, options))));
        
        const responsePagedResults = controls.find((control) => {
          return control.OID === OID.PagedResults;
        })
        
        if (responsePagedResults !== undefined) {
          cookie = responsePagedResults.value.cookie;
        } else {
          cookie = '';
        }
        
        if (cookie === '') {
          break;
        }
      }
      
      return results.flat();
    } else {
      return this._send(new Search(Object.assign({ baseObject, controls }, options)));
    }
  }

  async unbind(controls = []) {
    return this._send(new Unbind({ controls }));
  }

  async destroy() {
    if (this._socket) {
      this._socket.removeAllListeners('error');
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
      const destroy = () => {
        if (this._socket) {
          this._socket.destroy();
          this._socket = null;
        }

        if (this._queue) {
          for (const { reject } of this._queue.values()) {
            reject(new ConnectionError('Connection closed'));
          }

          this._queue.clear();
        }
      };

      if (this.secure) {
        this._socket = tls.connect(this.port, this.host, this.tlsOptions);
        this._socket.once('secureConnect', resolve);
      } else {
        this._socket = net.connect(this.port, this.host);
        this._socket.once('connect', resolve);
      }

      this._socket.on('close', destroy);
      this._socket.on('error', e => {
        destroy();
        reject(e || new Error('client error during setup'));
      });
      this._socket.on('data', data => this._parser.parse(data));
    });
  }

  async _send(message) {
    if (!this._socket) {
      await this._connect();
    }

    return new Promise((resolve, reject) => {
      try {
        this._queue.set(message.id, { resolve, reject, request: message, result: [], controls: message.controls });
        this._socket.write(message.toBer());

        if (message instanceof Unbind) {
          this._socket.removeAllListeners('close');
          this._socket.on('close', () => resolve(new Response({})));
        }

        if (this.timeout) {
          setTimeout(() => {
            if (this._queue) {
              this._queue.delete(message.id);
            }
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
