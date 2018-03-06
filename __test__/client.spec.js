const Client = require('../src');

describe('Client', () => {
  it('defined', () => {
    expect(Client).toBeDefined();
  });

  it('create', async () => {
    expect.assertions(12);

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

    try {
      await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

      expect(true).toBeTruthy();

      const response = await client.search('ou=guests,dc=zflexsoftware,dc=com', { scope: 'sub' });

      expect(response.length).toBeGreaterThan(0);

      await client.destroy();

      expect(true).toBeTruthy();
    } catch (e) {
      expect(e).toBe(null);
    }
  });

  it('create fail', async () => {
    expect.assertions(2);

    const client = new Client({ url: 'ldap://127.0.0.1' });

    expect(client).toBeDefined();

    try {
      await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }
  });

  it('SSl fail', async () => {
    expect.assertions(2);

    const client = new Client({ url: 'ldaps://www.zflexldap.com' });

    expect(client).toBeDefined();

    try {
      await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }
  });

  it('parallel bind', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    const p1 = client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');
    const p2 = client.bind('uid=guest1,ou=users,ou=guests,dc=zflexsoftware,dc=com', 'guest1password');

    await Promise.all([p1, p2]);

    expect(true).toBeTruthy();
  });
});
