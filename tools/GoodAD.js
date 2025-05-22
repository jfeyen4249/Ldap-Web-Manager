// tools/ad.js
const ldapjs = require('ldapjs');
const { Client, Attribute, Change } = require('ldapts');
require('dotenv').config();

async function findUserDN(username) {
    const url = process.env.AD_URL;
    const bindDN = process.env.AD_USERNAME;
    const password = process.env.AD_PASSWORD;
    const baseDN = process.env.AD_BASEDN; // ✅ Use full base
  
    const client = new Client({
      url,
      tlsOptions: { rejectUnauthorized: false }
    });
  
    try {
      await client.bind(bindDN, password);
  
      console.log(`🔎 Searching for exact user: ${username} from base: ${baseDN}`);
  
      const { searchEntries } = await client.search(baseDN, {
        scope: 'sub',
        filter: `(&(objectClass=user)(sAMAccountName=${username}))`,   // ✅ Force exact match
        attributes: ['distinguishedName', 'cn', 'sAMAccountName', 'userPrincipalName', 'userAccountControl']
      });
  
      if (!searchEntries || searchEntries.length === 0) {
        throw new Error('User not found');
      }
  
      console.log(`✅ Found exact user: ${searchEntries[0].distinguishedName}`);
      return searchEntries[0];
  
    } catch (error) {
      console.error('❌ LDAP search error:', error);
      throw error;
    } finally {
      await client.unbind();
    }
  }

  async function getAllUsersAndOUs() {
    const client = new Client({
      url: process.env.AD_URL,
      tlsOptions: { rejectUnauthorized: false }
    });
  
    try {
      await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);
  
      // --- build users array ---
      const { searchEntries: userEntries } = await client.search(
        process.env.AD_BASEDN,
        {
          scope: 'sub',
          filter: '(objectCategory=person)',
          attributes: ['cn','sAMAccountName','userPrincipalName','userAccountControl','distinguishedName']
        }
      );
  
      const users = userEntries
        .filter(u => u.sAMAccountName)
        .map(u => {
          // *** reverse here to match the dropdown ***
          const ouPath = (u.distinguishedName || '')
            .split(',')
            .filter(p => p.startsWith('OU='))
            .map(p => p.replace('OU=', ''))
            .reverse()      // ← ADD THIS line
            .join('/');
  
          return {
            name: u.cn || '',
            username: u.sAMAccountName,
            email: u.userPrincipalName || '',
            ou: ouPath,
            disabled: (parseInt(u.userAccountControl||'0',10) & 2) !== 0
          };
        });
  
      // --- build OU list for dropdown, already reversed ---
      const { searchEntries: ouEntries } = await client.search(
        process.env.AD_BASEDN,
        {
          scope: 'sub',
          filter: '(objectCategory=organizationalUnit)',
          attributes: ['distinguishedName']
        }
      );
  
      const ouList = ouEntries
        .map(o => o.distinguishedName
          .split(',')
          .filter(r => r.startsWith('OU='))
          .map(r => r.replace('OU=', ''))
          .reverse()      // keep this to match the above
          .join('/')
        )
        .filter(p => p);
  
      await client.unbind();
      return { users, ouList };
  
    } catch (err) {
      await client.unbind();
      throw err;
    }
  }
  

async function getAllGroups() {
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  try {
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    const { searchEntries: groupEntries } = await client.search(process.env.AD_BASEDN, {
      scope: 'sub',
      filter: '(objectCategory=group)',
      attributes: ['cn']
    });

    const groups = (groupEntries || []).map(g => g.cn).sort();

    await client.unbind();
    return groups;
  } catch (error) {
    console.error('LDAP Error:', error);
    await client.unbind();
    throw error;
  }
}

async function getGroupMembers(groupName) {
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  try {
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    console.log(`🔎 Finding group: ${groupName}`);

    const { searchEntries: groupEntries } = await client.search(process.env.AD_BASEDN, {
      scope: 'sub',
      filter: `(&(objectClass=group)(cn=${groupName}))`,
      attributes: ['distinguishedName']
    });

    if (!groupEntries.length) {
      throw new Error('Group not found');
    }

    const groupDN = groupEntries[0].distinguishedName;
    console.log(`✅ Found group DN: ${groupDN}`);

    const { searchEntries: memberEntries } = await client.search(process.env.AD_BASEDN, {
      scope: 'sub',
      filter: `(&(objectClass=user)(memberOf=${groupDN}))`,
      attributes: ['cn', 'sAMAccountName', 'userPrincipalName', 'distinguishedName', 'userAccountControl']
    });

    const cleanUsers = memberEntries.map(u => ({
      name: u.cn || '',
      username: u.sAMAccountName || '',
      email: u.userPrincipalName || '',
      ou: (u.distinguishedName || '').split(',').find(p => p.startsWith('OU='))?.replace('OU=', '') || 'Unknown',
      disabled: (parseInt(u.userAccountControl || 0) & 2) !== 0
    }));

    await client.unbind();
    return { groupDN, members: cleanUsers };

  } catch (error) {
    console.error('LDAP Error:', error);
    await client.unbind();
    throw error;
  }
}

async function addUserToGroup(username, groupName) {
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  try {
    // 1️⃣ Bind
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    // 2️⃣ Lookup Group DN
    const { searchEntries: groupEntries } = await client.search(process.env.AD_BASEDN, {
      scope: 'sub',
      filter: `(&(objectClass=group)(cn=${groupName}))`,
      attributes: ['distinguishedName']
    });
    if (!groupEntries.length) throw new Error('Group not found');
    const groupDN = groupEntries[0].distinguishedName;

    // 3️⃣ Lookup User DN
    const user = await findUserDN(username);
    if (!user?.distinguishedName) throw new Error('User not found');

    // 4️⃣ Build & send the “add member” change
    const change = new Change({
      operation: 'add',
      modification: new Attribute({
        type: 'member',
        values: [user.distinguishedName]
      })
    });
    await client.modify(groupDN, [change]);

    console.log(`✅ Added ${username} to group ${groupName}`);
    return { success: true };

  } catch (error) {
    console.error('Error adding user to group:', error);
    return { success: false, message: error.message };

  } finally {
    await client.unbind();
  }
}

async function removeUserFromGroup(username, groupDN) {
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  try {
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    const user = await findUserDN(username);
    if (!user?.distinguishedName) {
      throw new Error('User DN not found');
    }

    // wrap the modification in ldapts.Attribute
    const change = new Change({
      operation: 'delete',
      modification: new Attribute({
        type: 'member',
        values: [user.distinguishedName]
      })
    });

    // you can pass a single Change or an array of them
    await client.modify(groupDN, [change]);
    console.log(`✅ Removed ${username} from group ${groupDN}`);
    return { success: true };

  } catch (error) {
    console.error('Error removing user from group:', error);
    return { success: false, message: error.message };

  } finally {
    await client.unbind();
  }
}

async function getUserDetails(username) {
const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
});

try {
    if (!username) throw new Error('Missing username');

    // 🔎 Get user info
    const userResult = await findUserDN(username);

    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    console.log(`🔎 Searching for groups for user: ${username}`);

    // 🔎 Find groups the user belongs to
    const { searchEntries: groupEntries } = await client.search(process.env.AD_BASEDN, {
    scope: 'sub',
    filter: `(member:1.2.840.113556.1.4.1941:=${userResult.distinguishedName})`,
    attributes: ['cn']
    });
    const userGroups = groupEntries.map(g => g.cn);

    console.log(`🔎 Searching all groups under base: ${process.env.AD_BASEDN}`);

    // 🔎 Get all groups
    const { searchEntries: allGroupEntries } = await client.search(process.env.AD_BASEDN, {
    scope: 'sub',
    filter: '(objectClass=group)',
    attributes: ['cn']
    });
    const allGroups = allGroupEntries.map(g => g.cn);

    console.log(`🔎 Searching all OUs under base: ${process.env.AD_BASEDN}`);

    // 🔎 Get all OUs
    const { searchEntries: ouEntries } = await client.search(process.env.AD_BASEDN, {
    scope: 'sub',
    filter: '(objectClass=organizationalUnit)',
    attributes: ['ou', 'distinguishedName']
    });
    const ous = ouEntries.map(ou => ou.distinguishedName);

    await client.unbind();

    return {
    success: true,
    user: {
        name: userResult.cn,
        username: userResult.sAMAccountName,
        email: userResult.userPrincipalName,
        ou: (userResult.distinguishedName || '').split(',').filter(p => p.startsWith('OU=')).map(p => p.replace('OU=', '')).join('/'),
        disabled: (parseInt(userResult.userAccountControl || 0) & 2) !== 0
    },
    groups: userGroups,
    allGroups,
    ous
    };

} catch (error) {
    console.error('❌ LDAP Error in getUserDetails:', error);
    await client.unbind();
    throw error;
}
}

async function searchUsers(search) {
    const client = new Client({
      url: process.env.AD_URL,
      tlsOptions: { rejectUnauthorized: false }
    });
  
    try {
      await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);
  
      const { searchEntries } = await client.search(process.env.AD_DEFAULT_OU, {
        baseDN: process.env.AD_DEFAULT_OU,
        scope: 'sub',
        filter: `(&(objectClass=user)(|(cn=*${search}*)(sAMAccountName=*${search}*)))`,
        attributes: ['cn', 'sAMAccountName', 'userPrincipalName'],
        sizeLimit: 20
      });
  
      await client.unbind();
  
      return (searchEntries || []).map(u => ({
        name: u.cn || '',
        username: u.sAMAccountName || '',
        email: u.userPrincipalName || ''
      }));
    } catch (error) {
      console.error('LDAP Error:', error);
      await client.unbind();
      throw error;
    }
  }

async function moveUserToOU(username, newOu) {
const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
});

try {
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    const { searchEntries } = await client.search(process.env.AD_BASEDN, {
    scope: 'sub',
    filter: `(sAMAccountName=${username})`,
    attributes: ['distinguishedName', 'cn']
    });

    if (!searchEntries || searchEntries.length === 0) {
    throw new Error('User not found');
    }

    const user = searchEntries[0];
    const currentDn = user.distinguishedName;
    const cn = user.cn;
    const newDn = `CN=${cn},${newOu}`;

    await client.modifyDN(currentDn, newDn);

    await client.unbind();
    return true;
} catch (error) {
    console.error('LDAP Error:', error);
    await client.unbind();
    throw error;
}
}

async function enableUser(username) {
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  try {
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    const { searchEntries } = await client.search(process.env.AD_BASEDN, {
      scope: 'sub',
      filter: `(sAMAccountName=${username})`,
      attributes: ['distinguishedName']
    });

    if (!searchEntries.length) throw new Error('User not found');
    const userDN = searchEntries[0].distinguishedName;

    const change = new Change({
      operation: 'replace',
      modification: new Attribute({
        type: 'userAccountControl',
        values: ['512']
      })
    });

    await client.modify(userDN, [change]);
    console.log(`✅ User ${username} enabled.`);
    await client.unbind();
    return { success: true };
  } catch (error) {
    console.error('LDAP Error (enableUser):', error);
    await client.unbind();
    throw error;
  }
}

async function disableUser(username) {
    const client = new Client({
      url: process.env.AD_URL,
      tlsOptions: { rejectUnauthorized: false }
    });
  
    try {
      await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);
  
      const { searchEntries } = await client.search(process.env.AD_BASEDN, {
        scope: 'sub',
        filter: `(sAMAccountName=${username})`,
        attributes: ['distinguishedName', 'userAccountControl']
      });
  
      if (!searchEntries.length) {
        throw new Error('User not found');
      }
  
      const userDN = searchEntries[0].distinguishedName;
      let flags = parseInt(searchEntries[0].userAccountControl || 0);
      flags = flags | 2; // Set disabled bit
  
      const attribute = new Attribute({
        type: 'userAccountControl',
        values: [flags.toString()]
      });
  
      const change = new Change({
        operation: 'replace',
        modification: attribute
      });
  
      await client.modify(userDN, change);
      await client.unbind();
  
      console.log(`✅ User ${username} disabled successfully.`);
    } catch (error) {
      console.error('LDAP Error (disableUser):', error);
      await client.unbind();
      throw error;
    }
}

  /**
 * Reset an AD user's password.
 *
 * @param {string} username    – sAMAccountName of the user to reset
 * @param {string} newPassword – Plain-text new password
 * @returns {Promise<{success: true}>}
 * @throws on any LDAP error
 */
async function resetPassword(username, newPassword) {
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false },
  });

  try {
    // 1️⃣ bind as your service account
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    // 2️⃣ find the user's DN
    const user = await findUserDN(username);
    if (!user?.distinguishedName) {
      throw new Error('User not found');
    }

    // 3️⃣ build the unicodePwd replace change
    const change = new Change({
      operation: 'replace',
      modification: new Attribute({
        type: 'unicodePwd',
        values: [Buffer.from(`"${newPassword}"`, 'utf16le')],
      }),
    });

    // 4️⃣ send the modify
    await client.modify(user.distinguishedName, [change]);

    console.log(`✅ Password reset for ${username}`);
    return { success: true };

  } finally {
    // 5️⃣ always unbind
    await client.unbind();
  }
}

async function updateADUser({ oldUsername, newName, newUsername, newEmail }) {
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  try {
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    // ✅ This will correctly log the actual username value
    console.log(`🔎 Searching for exact user: ${oldUsername}`);

    const user = await findUserDN(oldUsername);
    const userDN = user.distinguishedName;

    const changes = [];

    if (newName) {
      changes.push(new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'displayName', values: [newName] }),
      }));
    }

    if (newUsername) {
      changes.push(new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'sAMAccountName', values: [newUsername] }),
      }));
      changes.push(new Change({
        operation: 'replace',
        modification: new Attribute({
          type: 'userPrincipalName',
          values: [`${newUsername}@${process.env.AD_DOMAIN}`],
        }),
      }));
    }

    if (newEmail) {
      changes.push(new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'mail', values: [newEmail] }),
      }));
    }

    if (changes.length === 0) {
      return { success: false, message: 'No changes provided' };
    }

    await client.modify(userDN, changes);
    console.log(`✅ Updated user: ${oldUsername}`);
    return { success: true, message: `User ${oldUsername} updated.` };

  } catch (err) {
    console.error("❌ Failed to update user:", err);
    return { success: false, error: err.message };
  } finally {
    await client.unbind();
  }
}

/**
 * Fetch all group CNs and OU DNs from AD.
 *
 * @returns {Promise<{groups: string[], ous: string[]}>}
 * @throws on any LDAP error
 */
async function getGroupsAndOUs() {
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  try {
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);
    const baseDN = process.env.AD_BASEDN;

    console.log(`🔎 Searching groups under base: ${baseDN}`);
    const { searchEntries: groupEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: '(objectClass=group)',
      attributes: ['cn'],
    });
    const groups = groupEntries.map(e => e.cn).filter(Boolean);

    console.log(`🔎 Searching OUs under base: ${baseDN}`);
    const { searchEntries: ouEntries } = await client.search(baseDN, {
      scope: 'sub',
      filter: '(objectClass=organizationalUnit)',
      attributes: ['distinguishedName'],
    });
    const ous = ouEntries.map(e => e.distinguishedName).filter(Boolean);

    return { groups, ous };
  } finally {
    await client.unbind();
  }
}

/**
 * Create a new AD user, set password, enable it, and add to groups.
 *
 * @param {object} params
 * @param {string} params.name     – Display name and CN
 * @param {string} params.username – sAMAccountName
 * @param {string} params.email    – userPrincipalName & mail
 * @param {string} params.password – initial password
 * @param {string[]} params.groups – array of group CNs
 * @param {string} params.ou       – full OU DN (e.g. "OU=IT,OU=Black Hawk Users,DC=…")
 */
async function createADUser({ name, username, email, password, groups = [], ou }) {
  const userDN = `CN=${name},${ou}`;
  const client = new Client({
    url: process.env.AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  try {
    // Bind as service account
    await client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD);

    // Verify OU exists
    const { searchEntries: ouCheck } = await client.search(ou, {
      scope: 'base',
      filter: '(objectClass=organizationalUnit)',
      attributes: ['distinguishedName']
    });
    if (!ouCheck.length) {
      throw new Error(`Parent OU not found: ${ou}`);
    }

    // 1️⃣ Create the user (disabled)
    const entry = {
      cn: name,
      sn: name.split(' ').slice(-1)[0] || name,
      objectClass: ['top', 'person', 'organizationalPerson', 'user'],
      sAMAccountName: username,
      userPrincipalName: email,
      displayName: name,
      givenName: name.split(' ')[0] || name,
      mail: email,
      userAccountControl: '514'
    };
    await client.add(userDN, entry);
    console.log(`✅ User created: ${userDN}`);

    // 2️⃣ Set password
    await client.modify(userDN, [
      new Change({
        operation: 'replace',
        modification: new Attribute({
          type: 'unicodePwd',
          values: [Buffer.from(`"${password}"`, 'utf16le')]
        })
      })
    ]);
    console.log('✅ Password set');

    // 3️⃣ Enable account
    await client.modify(userDN, [
      new Change({
        operation: 'replace',
        modification: new Attribute({
          type: 'userAccountControl',
          values: ['512']
        })
      })
    ]);
    console.log('✅ Account enabled');

    // 4️⃣ Add user to each group by first searching for that group’s DN
    for (const groupCN of groups) {
      // Lookup the group's DN
      const { searchEntries: grp } = await client.search(process.env.AD_BASEDN, {
        scope: 'sub',
        filter: `(&(objectClass=group)(cn=${groupCN}))`,
        attributes: ['distinguishedName']
      });
      if (!grp.length) {
        throw new Error(`Group not found: ${groupCN}`);
      }
      const groupDN = grp[0].distinguishedName;

      // Add member
      await client.modify(groupDN, [
        new Change({
          operation: 'add',
          modification: new Attribute({
            type: 'member',
            values: [userDN]
          })
        })
      ]);
      console.log(`✅ Added to group: ${groupCN}`);
    }

    return { success: true };
  } catch (err) {
    // Better messaging on NoSuchObject for parent OU
    if (err.lde_message === 'No Such Object') {
      throw new Error(`Parent or group DN not found in directory: ${err.lde_dn}`);
    }
    throw err;
  } finally {
    await client.unbind();
  }
}

module.exports = {
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
