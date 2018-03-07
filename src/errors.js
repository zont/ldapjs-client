const assert = require('assert-plus');
const { Response } = require('./responses');
const CODES = require('./utils/error-codes');

const ERRORS = {};
const capitalize = str => str.charAt(0) + str.slice(1).toLowerCase();

class LDAPError extends Error {
  constructor(message, dn, caller) {
    super(message);

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, caller || LDAPError);

    this.lde_message = message;
    this.lde_dn = dn;
  }

  get name() {
    return 'LDAPError';
  }

  get code() {
    return CODES.LDAP_OTHER;
  }

  get message() {
    return this.lde_message || this.name;
  }

  get dn() {
    return this.lde_dn ? this.lde_dn.toString() : '';
  }
}

class ConnectionError extends LDAPError {
  constructor(message) {
    super(message, null, ConnectionError);
  }

  get name() {
    return 'ConnectionError';
  }
}

class TimeoutError extends LDAPError {
  constructor(message) {
    super(message, null, TimeoutError);
  }

  get name() {
    return 'TimeoutError';
  }
}

Object.keys(CODES)
  .filter(key => key !== 'LDAP_SUCCESS')
  .forEach(key => {
    const pieces = key.split('_').slice(1).map(capitalize);
    if (pieces[pieces.length - 1] !== 'Error') {
      pieces.push('Error');
    }

    ERRORS[CODES[key]] = class extends LDAPError {
      get message() {
        return pieces.join(' ');
      }

      get name() {
        return pieces.join('');
      }

      get code() {
        return CODES[key];
      }
    };
  });

module.exports = {
  ConnectionError,
  TimeoutError,
  ProtocolError: ERRORS[CODES.LDAP_PROTOCOL_ERROR],

  LDAP_SUCCESS: CODES.LDAP_SUCCESS,

  getError(res) {
    assert.ok(res instanceof Response, 'res (Response) required');

    return new (ERRORS[res.status])(null, res.matchedDN || null, module.exports.getError);
  }
};
