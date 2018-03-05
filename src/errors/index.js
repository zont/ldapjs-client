const assert = require('assert-plus');
const { LDAPResult } = require('../messages');
const CODES = require('./codes');

const ERRORS = [];
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

class AbandonedError extends LDAPError {
  constructor(message) {
    super(message, null, AbandonedError);
  }

  get name() {
    return 'AbandonedError';
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


module.exports = {
  LDAPError,
  ConnectionError,
  AbandonedError,
  TimeoutError,

  getMessage(code) {
    assert.number(code, 'code (number) required');

    const errObj = ERRORS[code];
    return errObj && errObj.message ? errObj.message : '';
  },

  getError(res) {
    assert.ok(res instanceof LDAPResult, 'res (LDAPResult) required');

    const errObj = ERRORS[res.status];
    const E = module.exports[errObj.err];
    return new E(res.errorMessage || errObj.message, res.matchedDN || null, module.exports.getError);
  }
};

// Some whacky games here to make sure all the codes are exported
Object.keys(CODES).forEach(code => {
  module.exports[code] = CODES[code];

  if (code === 'LDAP_SUCCESS')
    return;

  const pieces = code.split('_').slice(1).map(capitalize);
  if (pieces[pieces.length - 1] !== 'Error') {
    pieces.push('Error');
  }

  const err = pieces.join(''); // At this point LDAP_OPERATIONS_ERROR is now OperationsError
  const message = pieces.join(' '); // and 'Operations Error'

  ERRORS[CODES[code]] = { err, message };

  module.exports[err] = class extends LDAPError {
    constructor(message, dn, caller) {
      super(message, dn, caller || module.exports[err]);
    }

    get name() {
      return err;
    }

    get code() {
      return CODES[code];
    }
  };
});
