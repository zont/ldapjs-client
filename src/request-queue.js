const { TimeoutError } = require('./errors');

module.exports = class RequestQueue {
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
};
