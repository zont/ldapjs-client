module.exports = class LDAPMessage {
  constructor(options) {
    Object.assign(this, options);
  }

  get dn() {
    return this._dn || '';
  }

  get type() {
    return 'LDAPMessage';
  }

  parse(ber) {
    this._parse(ber, ber.length);

    return true;
  }
};
