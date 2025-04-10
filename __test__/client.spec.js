const Client = require('../src');

const url = 'ldap://ldap.forumsys.com';
const user = 'cn=read-only-admin,dc=example,dc=com';
const password = 'password';

describe('Client', () => {
  it('defined', () => {
    expect(Client).toBeDefined();

    const client = new Client({ url });

    expect(client).toBeDefined();
    expect(client.add).toBeDefined();
    expect(client.bind).toBeDefined();
    expect(client.del).toBeDefined();
    expect(client.destroy).toBeDefined();
    expect(client.modify).toBeDefined();
    expect(client.modifyDN).toBeDefined();
    expect(client.search).toBeDefined();
    expect(client.unbind).toBeDefined();
  });

  it('destroy', async () => {
    expect.assertions(1);

    const client = new Client({ url });

    await client.destroy();

    expect(true).toBeTruthy();
  });

  it('bind', async () => {
    expect.assertions(1);

    const client = new Client({ url });

    await client.bind(user, password);

    expect(true).toBeTruthy();

    await client.destroy();
  });

  it('parallel bind', async () => {
    expect.assertions(1);

    const client = new Client({ url });

    const p1 = client.bind(user, password);
    const p2 = client.bind('uid=einstein,dc=example,dc=com', password);

    await Promise.all([p1, p2]);

    expect(true).toBeTruthy();

    await client.destroy();
  });

  it('bind fail', async () => {
    expect.assertions(1);

    const client = new Client({ url });

    try {
      await client.bind(user, '');

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }

    await client.destroy();
  });

  it('connect fail', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldap://127.0.0.1' });

    try {
      await client.bind(user, password);

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }

    await client.destroy();
  });

  it('SSl fail', async () => {
    expect.assertions(1);

    const client = new Client({ url: url.replace('ldap:', 'ldaps:') });

    try {
      await client.bind(user, password);

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }

    await client.destroy();
  });

  it('search', async () => {
    expect.assertions(4);

    const client = new Client({ url });

    await client.bind(user, password);
    const response = await client.search('ou=scientists,dc=example,dc=com', { scope: 'sub' });

    expect(response.length).toBeGreaterThan(0);
    expect(response[0].dn).toBeDefined();
    expect(response[0].ou).toBe('scientists');
    expect(response[0].objectClass.length).toBeGreaterThan(0);

    await client.destroy();
  });

  it('search w/ base scope', async () => {
    const client = new Client({ url });

    await client.bind(user, password);

    try {
      const response = await client.search('ou=scientists,dc=example,dc=com', { scope: 'base' });
      expect(response.length).toBeGreaterThanOrEqual(0);
    } catch (e) {
      expect(false).toBeTruthy();
    }

    await client.destroy();
  });

  it('search not found', async () => {
    expect.assertions(2);

    const client = new Client({ url });

    await client.bind(user, password);
    const response = await client.search('ou=scientists,dc=example,dc=com', { filter: '(ou=sysadmins)', scope: 'sub' });

    expect(Array.isArray(response)).toBeTruthy();
    expect(response.length).toBe(0);

    await client.destroy();
  });

  it('paged search', async () => {
    const client = new Client({ url });
    await client.bind(user, password);
    const sizeLimit = 1;
    let cookie = '';
    let hasNext = true;
    let i = 0;
    let response = [];
    while (hasNext && i < 5) {
      const result = await client.search('ou=scientists,dc=example,dc=com', { scope: 'sub', sizeLimit, filters: '(objectclass=*)', attributes: ['cn'], cookie });
      if (result.length === sizeLimit + 1) {
        const tmp = result.pop();
        hasNext = tmp.hasNext;
        cookie = tmp.cookie;
        response = response.concat(result);
      }
      i += 1;
    }

    expect(Array.isArray(response)).toBeTruthy();
    expect(response.length).toBe(2);
    expect(i).toBe(2);

    await client.destroy();
  });

  xit('unbind', async () => {
    expect.assertions(4);

    const client = new Client({ url });

    await client.bind(user, password);

    expect(true).toBeTruthy();

    await client.unbind();

    expect(true).toBeTruthy();

    try {
      await client.search('ou=scientists,dc=example,dc=com', { scope: 'sub' });

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }

    await client.bind(user, password);
    await client.search('ou=scientists,dc=example,dc=com', { scope: 'sub' });
    await client.unbind();

    expect(true).toBeTruthy();

    await client.destroy();
  });
});
