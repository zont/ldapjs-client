const assert = require('assert-plus');
const LDAPResult = require('./result');
const SearchEntry = require('./search_entry');
const SearchReference = require('./search_reference');
const parseDN = require('../dn').parse;
const parseURL = require('../utils/parse-url');
const { LDAP_REP_SEARCH } = require('../protocol');

module.exports = class SearchResponse extends LDAPResult {
  constructor(options) {
    super(Object.assign({}, options, { protocolOp: LDAP_REP_SEARCH }));

    this.attributes = options.attributes ? options.attributes.slice() : [];
    this.notAttributes = [];
    this.sentEntries = 0;
  }

  send(entry, nofiltering = false) {
    assert.object(entry, 'entry');
    assert.bool(nofiltering, 'nofiltering');

    const savedAttrs = {};
    const save = entry;

    if (entry instanceof SearchEntry || entry instanceof SearchReference) {
      if (!entry.messageID)
        entry.messageID = this.messageID;
      assert.ok(entry.messageID === this.messageID, 'SearchEntry messageID mismatch');
    } else {
      assert.ok(entry.attributes, 'entry.attributes required');

      const all = (this.attributes.indexOf('*') !== -1);
      Object.keys(entry.attributes).forEach(a => {
        const _a = a.toLowerCase();
        if (!nofiltering && _a.length && _a[0] === '_') {
          savedAttrs[a] = entry.attributes[a];
          delete entry.attributes[a];
        } else if (!nofiltering && this.notAttributes.indexOf(_a) !== -1) {
          savedAttrs[a] = entry.attributes[a];
          delete entry.attributes[a];
        } else if (all) {
          return;
        } else if (this.attributes.length && this.attributes.indexOf(_a) === -1) {
          savedAttrs[a] = entry.attributes[a];
          delete entry.attributes[a];
        }
      });

      entry = new SearchEntry({
        objectName: typeof (save.dn) === 'string' ? parseDN(save.dn) : save.dn,
        messageID: this.messageID
      });
      entry.fromObject(save);
    }

    try {
      this.connection.write(entry.toBer());
      this.sentEntries++;

      // Restore attributes
      Object.keys(savedAttrs || {}).forEach(k => {
        save.attributes[k] = savedAttrs[k];
      });

    } catch (e) {
      console.warn(e, '%s failure to write message %j', this.connection.ldap.id, this.json);
    }
  }

  createSearchEntry(object) {
    assert.object(object);

    const entry = new SearchEntry({
      messageID: this.messageID,
      objectName: object.objectName || object.dn
    });
    entry.fromObject((object.attributes || object));
    return entry;
  }

  createSearchReference(uris) {
    assert.ok(uris, 'uris ([string]) required');

    if (!Array.isArray(uris))
      uris = [uris];

    for (let i = 0; i < uris.length; ++i) {
      if (typeof (uris[i]) == 'string')
        uris[i] = parseURL(uris[i]);
    }

    return new SearchReference({ messageID: this.messageID, uris });
  }
};
