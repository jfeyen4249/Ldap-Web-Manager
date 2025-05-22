// tools/ad.js

const ldapjs     = require('ldapjs');
const { Client, Attribute, Change } = require('ldapts');
require('dotenv').config();

const url      = process.env.AD_URL;
const bindDN   = process.env.AD_USERNAME;
const password = process.env.AD_PASSWORD;
const baseDN   = process.env.AD_BASEDN;

/** Escape filter input per RFC4515 */
function escapeLDAPFilter(input = '') {
  return input
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

/** Escape a single RDN value per RFC2253 */
function escapeDNValue(value = '') {
  return value
    .replace(/([,+"\\<>;])/g, '\\$1')
    .replace(/^ | $/g, '\\ ');
}

/** Bind and return a fresh ldapts Client */
async function getClient() {
  const client = new Client({
    url,
    tlsOptions: { rejectUnauthorized: false }
  });
  await client.bind(bindDN, password);
  return client;
}

//
// ─── CORE HELPERS ──────────────────────────────────────────────────────────────
//

async function findUserDN(username) {
  const client = await getClient();
  try {
    const safe = escapeLDAPFilter(username);
    const { searchEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: `(&(objectClass=user)(sAMAccountName=${safe}))`,
      attributes: [
        'distinguishedName',
        'cn',
        'sAMAccountName',
        'userPrincipalName',
        'userAccountControl'
      ]
    });
    if (!searchEntries.length) {
      throw new Error(`User not found: ${username}`);
    }
    return searchEntries[0];
  } finally {
    await client.unbind();
  }
}

async function getAllUsersAndOUs() {
    const client = await getClient();
    try {
      // fetch users
      const { searchEntries: userEntries } = await client.search(baseDN, {
        scope: 'sub',
        filter: '(objectCategory=person)',
        attributes: [
          'cn',
          'sAMAccountName',
          'userPrincipalName',
          'userAccountControl',
          'distinguishedName'
        ]
      });
  
      // map into your UI format
      const users = userEntries
        .filter(u => u.sAMAccountName)
        .map(u => {
          const parts = (u.distinguishedName || '')
            .split(',')
            .filter(p => p.startsWith('OU='))
            .map(p => p.replace('OU=', ''))
            .reverse();
          return {
            name: u.cn || '',
            username: u.sAMAccountName,
            email: u.userPrincipalName || '',
            ou: parts.join('/'),
            disabled: (parseInt(u.userAccountControl || '0', 10) & 2) !== 0
          };
        });
  
      // *** Sort alphabetically by display name ***
      users.sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { sensitivity: 'base' })
      );
  
      // fetch OUs for dropdown
      const { searchEntries: ouEntries } = await client.search(baseDN, {
        scope: 'sub',
        filter: '(objectCategory=organizationalUnit)',
        attributes: ['distinguishedName']
      });
  
      const ouList = ouEntries
        .map(o => {
          const parts = (o.distinguishedName || '')
            .split(',')
            .filter(p => p.startsWith('OU='))
            .map(p => p.replace('OU=', ''))
            .reverse();
          return parts.join('/');
        })
        .filter(p => p);
  
      return { users, ouList };
    } finally {
      await client.unbind();
    }
  }

async function getAllGroups() {
  const client = await getClient();
  try {
    const { searchEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: '(objectCategory=group)',
      attributes: ['cn']
    });
    return searchEntries.map(g => g.cn).sort();
  } finally {
    await client.unbind();
  }
}

async function getGroupMembers(groupName) {
  const client = await getClient();
  try {
    const safeGroup = escapeLDAPFilter(groupName);
    const { searchEntries: grp } = await client.search(baseDN, {
      scope: 'sub',
      filter: `(&(objectClass=group)(cn=${safeGroup}))`,
      attributes: ['distinguishedName']
    });
    if (!grp.length) throw new Error(`Group not found: ${groupName}`);
    const groupDN = grp[0].distinguishedName;

    const safeDN = escapeLDAPFilter(groupDN);
    const { searchEntries: memberEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: `(&(objectClass=user)(memberOf=${safeDN}))`,
      attributes: [
        'cn',
        'sAMAccountName',
        'userPrincipalName',
        'distinguishedName',
        'userAccountControl'
      ]
    });

    const members = memberEntries.map(u => {
      const parts = (u.distinguishedName || '')
        .split(',')
        .filter(p => p.startsWith('OU='))
        .map(p => p.replace('OU=', ''));
      return {
        name: u.cn,
        username: u.sAMAccountName,
        email: u.userPrincipalName,
        ou: parts.reverse().join('/'),
        disabled: Boolean(parseInt(u.userAccountControl||'0',10) & 2)
      };
    });

    return { groupDN, members };
  } finally {
    await client.unbind();
  }
}

async function addUserToGroup(username, groupName) {
  const client = await getClient();
  try {
    const safeGroup = escapeLDAPFilter(groupName);
    const { searchEntries: grp } = await client.search(baseDN, {
      scope: 'sub',
      filter: `(&(objectClass=group)(cn=${safeGroup}))`,
      attributes: ['distinguishedName']
    });
    if (!grp.length) throw new Error(`Group not found: ${groupName}`);
    const groupDN = grp[0].distinguishedName;

    const user = await findUserDN(username);
    await client.modify(groupDN, [
      new Change({
        operation: 'add',
        modification: new Attribute({
          type: 'member',
          values: [user.distinguishedName]
        })
      })
    ]);
    return { success: true };
  } catch (err) {
    return { success: false, message: err.message };
  } finally {
    await client.unbind();
  }
}

async function removeUserFromGroup(username, groupDN) {
  const client = await getClient();
  try {
    const user = await findUserDN(username);
    await client.modify(groupDN, [
      new Change({
        operation: 'delete',
        modification: new Attribute({
          type: 'member',
          values: [user.distinguishedName]
        })
      })
    ]);
    return { success: true };
  } catch (err) {
    return { success: false, message: err.message };
  } finally {
    await client.unbind();
  }
}

async function getUserDetails(username) {
  const client = await getClient();
  try {
    const user = await findUserDN(username);
    const safeDN = escapeLDAPFilter(user.distinguishedName);

    const { searchEntries: grpEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: `(member:1.2.840.113556.1.4.1941:=${safeDN})`,
      attributes: ['cn']
    });
    const groups = grpEntries.map(g => g.cn);

    const { searchEntries: allGrp } = await client.search(baseDN, {
      scope: 'sub',
      filter: '(objectCategory=group)',
      attributes: ['cn']
    });
    const allGroups = allGrp.map(g => g.cn);

    const { searchEntries: ouEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: '(objectCategory=organizationalUnit)',
      attributes: ['distinguishedName']
    });
    const ous = ouEntries.map(o => o.distinguishedName);

    return {
      success: true,
      user: {
        name: user.cn,
        username: user.sAMAccountName,
        email: user.userPrincipalName,
        ou: (user.distinguishedName||'')
               .split(',')
               .filter(r=>r.startsWith('OU='))
               .map(r=>r.replace('OU=',''))
               .reverse()
               .join('/'),
        disabled: Boolean(parseInt(user.userAccountControl||'0',10)&2)
      },
      groups,
      allGroups,
      ous
    };
  } finally {
    await client.unbind();
  }
}

async function searchUsers(query) {
  const client = await getClient();
  try {
    const safe = escapeLDAPFilter(query);
    const { searchEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: `(&(objectClass=user)(|(cn=*${safe}*)(sAMAccountName=*${safe}*)))`,
      attributes: ['cn','sAMAccountName','userPrincipalName'],
      sizeLimit: 20
    });
    return searchEntries.map(u => ({
      name: u.cn,
      username: u.sAMAccountName,
      email: u.userPrincipalName
    }));
  } finally {
    await client.unbind();
  }
}

async function moveUserToOU(username, newOuDN) {
  const client = await getClient();
  try {
    const user = await findUserDN(username);
    const cn   = escapeDNValue(user.cn);
    await client.modifyDN(user.distinguishedName, `CN=${cn},${newOuDN}`);
    return { success: true };
  } finally {
    await client.unbind();
  }
}

async function enableUser(username) {
  const client = await getClient();
  try {
    const user = await findUserDN(username);
    await client.modify(user.distinguishedName, [
      new Change({ operation:'replace', modification:new Attribute({ type:'userAccountControl', values:['512'] }) })
    ]);
    return { success: true };
  } finally {
    await client.unbind();
  }
}

async function disableUser(username) {
  const client = await getClient();
  try {
    const user = await findUserDN(username);
    let flags = parseInt(user.userAccountControl||'0',10);
    flags |= 2;
    await client.modify(user.distinguishedName, [
      new Change({ operation:'replace', modification:new Attribute({ type:'userAccountControl', values:[flags.toString()] }) })
    ]);
    return { success: true };
  } finally {
    await client.unbind();
  }
}

async function resetPassword(username, newPassword) {
  const client = await getClient();
  try {
    const user = await findUserDN(username);
    await client.modify(user.distinguishedName, [
      new Change({ operation:'replace', modification:new Attribute({ type:'unicodePwd', values:[Buffer.from(`"${newPassword}"`,'utf16le')] }) })
    ]);
    return { success: true };
  } finally {
    await client.unbind();
  }
}

async function updateADUser({ oldUsername, newName, newUsername, newEmail }) {
  const client = await getClient();
  try {
    const user = await findUserDN(oldUsername);
    const changes = [];

    if (newName) {
      changes.push(new Change({ operation:'replace', modification:new Attribute({ type:'displayName', values:[newName] }) }));
    }
    if (newUsername) {
      const suffix = (user.userPrincipalName||'').split('@')[1]||'';
      changes.push(new Change({ operation:'replace', modification:new Attribute({ type:'sAMAccountName', values:[newUsername] }) }));
      if (suffix) {
        changes.push(new Change({ operation:'replace', modification:new Attribute({ type:'userPrincipalName', values:[`${newUsername}@${suffix}`] }) }));
      }
    }
    if (newEmail) {
      changes.push(new Change({ operation:'replace', modification:new Attribute({ type:'mail', values:[newEmail] }) }));
    }
    if (!changes.length) return { success:false, message:'No changes provided' };

    await client.modify(user.distinguishedName, changes);
    return { success: true };
  } finally {
    await client.unbind();
  }
}

/**
 * Fetch all groups & OUs for the Create/Edit modals.
 * Now returns:
 *   { groups: string[], ous: { dn: string, path: string }[] }
 */
async function getGroupsAndOUs() {
  const client = await getClient();
  try {
    // groups
    const { searchEntries: grpEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: '(objectCategory=group)',
      attributes: ['cn']
    });
    const groups = grpEntries.map(g => g.cn).filter(Boolean).sort();

    // ous
    const { searchEntries: ouEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: '(objectCategory=organizationalUnit)',
      attributes: ['distinguishedName']
    });

    const seen = new Set();
    const ous = ouEntries
      .map(o => {
        const dn    = o.distinguishedName;
        if (seen.has(dn)) return null;
        seen.add(dn);
        const parts = dn
          .split(',')
          .filter(r => r.startsWith('OU='))
          .map(r => r.replace('OU=', ''))
          .reverse();
        return { dn, path: parts.join(' / ') };
      })
      .filter(x => x);

    return { groups, ous };

  } finally {
    await client.unbind();
  }
}

/**
 * Create a new user + set password + enable + add to groups.
 */
async function createADUser({ name, username, email, password, groups = [], ou }) {
  const client = await getClient();
  try {
    // verify OU exists
    const { searchEntries: check } = await client.search(ou, {
      scope: 'base',
      filter: '(objectClass=organizationalUnit)',
      attributes: ['distinguishedName']
    });
    if (!check.length) throw new Error(`Parent OU not found: ${ou}`);

    const userDN = `CN=${escapeDNValue(name)},${ou}`;

    // 1) create disabled
    await client.add(userDN, {
      cn: name,
      sn: name.split(' ').slice(-1)[0]||name,
      objectClass: ['top','person','organizationalPerson','user'],
      sAMAccountName: username,
      userPrincipalName: email,
      displayName: name,
      givenName: name.split(' ')[0]||name,
      mail: email,
      userAccountControl: '514'
    });

    // 2) set password
    await client.modify(userDN, [
      new Change({
        operation: 'replace',
        modification: new Attribute({
          type: 'unicodePwd',
          values: [Buffer.from(`"${password}"`, 'utf16le')]
        })
      })
    ]);

    // 3) enable
    await client.modify(userDN, [
      new Change({
        operation: 'replace',
        modification: new Attribute({
          type: 'userAccountControl',
          values: ['512']
        })
      })
    ]);

    // 4) add to groups
    for (const grpCN of groups) {
      const safe = escapeLDAPFilter(grpCN);
      const { searchEntries: gg } = await client.search(baseDN, {
        scope: 'sub',
        filter: `(&(objectClass=group)(cn=${safe}))`,
        attributes: ['distinguishedName']
      });
      if (!gg.length) throw new Error(`Group not found: ${grpCN}`);
      await client.modify(gg[0].distinguishedName, [
        new Change({
          operation: 'add',
          modification: new Attribute({
            type: 'member',
            values: [userDN]
          })
        })
      ]);
    }

    return { success: true };
  } finally {
    await client.unbind();
  }
}

module.exports = {
  findUserDN,
  getAllUsersAndOUs,
  getAllGroups,
  getGroupMembers,
  addUserToGroup,
  removeUserFromGroup,
  getUserDetails,
  searchUsers,
  moveUserToOU,
  enableUser,
  disableUser,
  resetPassword,
  updateADUser,
  getGroupsAndOUs,
  createADUser
};
