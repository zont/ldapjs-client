# LDAP js client

[!['Build status'][travis_image_url]][travis_page_url]

[travis_image_url]: https://api.travis-ci.org/zont/ldapjs-client.svg
[travis_page_url]: https://travis-ci.org/zont/ldapjs-client

> node >= 8.0

No `ldapjs` (https://www.npmjs.com/package/ldapjs) as dependency.

**Why**: because `ldapjs` is not maintained for more than two years.


## Installation

    npm install ldapjs-client

Usage
-----

To create a new client:

```js
var LdapClient = require('ldapjs-client');
var client = new LdapClient({ url: 'ldap://127.0.0.1:389' });
```

Attribute | Type | Description
--- | --- | ---
url | String | A valid LDAP URL (proto/host/port only)
timeout | Number | Milliseconds client should let operations live for before timing out (Default: Infinity)
tlsOptions | Object | Additional options passed to TLS connection layer when connecting via ldaps:// (See: The TLS docs for node.js)

### add
```js
try {
  const entry = {
    cn: 'foo',
    sn: 'bar',
    email: ['foo@bar.com', 'foo1@bar.com'],
    objectclass: 'fooPerson'
  };

  await client.add('cn=foo, o=example', entry);
} catch (e) {
  console.log('Add failed');
}
```

### bind
```js
try {
  await client.bind('username', 'password');
} catch (e) {
  console.log('Bind failed');
}
```

### del
```js
try {
  await client.del('cn=foo, o=example');
} catch (e) {
  console.log(e);
}
```

### modify
```js
try {
  const change = {
    operation: 'add', // add, delete, replace
    modification: {
      pets: ['cat', 'dog']
    }
  };

  await client.modify('cn=foo, o=example', change);
} catch (e) {
  console.log(e);
}
```

### modifyDN
```js
try {
  await client.modifyDN('cn=foo, o=example', 'cn=bar');
} catch (e) {
  console.log(e);
}
```

### search
```js
try {
  const options = {
    filter: '(&(l=Seattle)(email=*@foo.com))',
    scope: 'sub',
    attributes: ['dn', 'sn', 'cn']
  };

  const entries = await client.search('o=example', options);
} catch (e) {
  console.log(e);
}
```

Attribute | Type | Description
--- | --- | ---
scope | String | One of base, one, or sub. Defaults to base
filter | String | A string version of an LDAP filter. Defaults to (objectclass=*)
attributes | Array of String | attributes to select and return. Defaults to the empty set, which means all attributes
sizeLimit | Number | the maximum number of entries to return. Defaults to 0 (unlimited)
timeLimit | Number | the maximum amount of time the server should take in responding, in seconds. Defaults to 10. Lots of servers will ignore this
typesOnly | Boolean | on whether you want the server to only return the names of the attributes, and not their values. Borderline useless. Defaults to false

### unbind
```js
try {
  await client.unbind();
} catch (e) {
  console.log(e);
}
```

### destroy
```js
try {
  await client.destroy();
} catch (e) {
  console.log(e);
}
```
Close connection if exists and destroy current client

---

Pull requests and suggestions are welcome!

## License

MIT.
