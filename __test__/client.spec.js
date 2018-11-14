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

    await client.destroy();

    expect(true).toBeTruthy();
  });

  it('bind', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

    expect(true).toBeTruthy();

    await client.destroy();
  });

  it('parallel bind', async () => {
    expect.assertions(1);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    const p1 = client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');
    const p2 = client.bind('uid=guest1,ou=users,ou=guests,dc=zflexsoftware,dc=com', 'guest1password');

    await Promise.all([p1, p2]);

    expect(true).toBeTruthy();

    await client.destroy();
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
    expect.assertions(4);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');
    const response = await client.search('ou=guests,dc=zflexsoftware,dc=com', { scope: 'sub' });

    expect(response.length).toBeGreaterThan(0);
    expect(response[0].dn).toBeDefined();
    expect(response[0].ou).toBe('guests');
    expect(response[0].objectclass.length).toBeGreaterThan(0);

    await client.destroy();
  });

  it ('search w/ base scope', async () => {
    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

    try {
      const response = await client.search('ou=guests,dc=zflexsoftware,dc=com', { scope: 'base' });
      expect(response.length).toBeGreaterThanOrEqual(0);
    } catch (e) {
      expect(false).toBeTruthy();
    }

    await client.destroy();
  });

  it('search not found', async () => {
    expect.assertions(2);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');
    const response = await client.search('ou=guests,dc=zflexsoftware,dc=com', { filter: '(ou=sysadmins)', scope: 'sub' });

    expect(Array.isArray(response)).toBeTruthy();
    expect(response.length).toBe(0);

    await client.destroy();
  });

  it('unbind', async () => {
    expect.assertions(4);

    const client = new Client({ url: 'ldap://www.zflexldap.com' });

    await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');

    expect(true).toBeTruthy();

    await client.unbind();

    expect(true).toBeTruthy();

    try {
      await client.search('ou=guests,dc=zflexsoftware,dc=com', { scope: 'sub' });

      expect(false).toBeTruthy();
    } catch (e) {
      expect(true).toBeTruthy();
    }

    await client.bind('cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com', 'zflexpass');
    await client.search('ou=guests,dc=zflexsoftware,dc=com', { scope: 'sub' });
    await client.unbind();

    expect(true).toBeTruthy();

    await client.destroy();
  });
});
