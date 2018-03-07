const Client = require('../src');

describe('Client', () => {
  it('defined', () => {
    expect(Client).toBeDefined();

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

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

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    try {
      await client.destroy();

      expect(true).toBeTruthy();
    } catch (e) {
      expect(e).toBe(null);
    }
  });

  it('bind', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    try {
      await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

      expect(true).toBeTruthy();
    } catch (e) {
      expect(e).toBe(null);
    }

    await client.destroy();
  });

  it('parallel bind', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    const p1 = client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');
    const p2 = client.bind('uid=guest1,ou=users,ou=guests,dc=zflexsoftware,dc=com', 'guest1password');

    await Promise.all([p1, p2]);

    expect(true).toBeTruthy();
  });

  it('bind fail', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    try {
      await client.bind('cn=undefined_111_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'no_pass_222');

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
      await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }

    await client.destroy();
  });

  it('SSl fail', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldaps://www.zflexldap.com' });

    try {
      await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }

    await client.destroy();
  });

  it('search', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    try {
      await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');
      const response = await client.search('ou=guests,dc=zflexsoftware,dc=com', { scope: 'sub' });

      expect(response.length).toBeGreaterThan(0);
    } catch (e) {
      expect(e).toBe(null);
    }

    await client.destroy();
  });

  it('unbind', async () => {
    expect.assertions(2);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    try {
      await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

      expect(true).toBeTruthy();

      await client.unbind();

      expect(true).toBeTruthy();
    } catch (e) {
      expect(e).toBe(null);
    }

    await client.destroy();
  });
});
