const express = require('express');
require('dotenv').config();
const { Client, Change, Attribute, SearchScope } = require('ldapts'); // ✅ only this
const { getAllUsersAndOUs, getAllGroups, getGroupMembers, addUserToGroup, removeUserFromGroup, getUserDetails, searchUsers, moveUserToOU, enableUser, disableUser, resetPassword, updateADUser, getGroupsAndOUs, createADUser } = require('./tools/ad');
const session = require('express-session');
const ActiveDirectory = require('activedirectory2');
const path = require('path');
const hbs = require('hbs');
const ldap = require('ldapjs');
const bodyParser = require('body-parser');
const app = express();
const PORT = 3100;
const domain = process.env.AD_DOMAIN;

// LDAP Configuration
const adConfig = {
    url: process.env.AD_URL,
    baseDN: process.env.AD_BASE_DN,
    username: process.env.AD_USERNAME,
    password: process.env.AD_PASSWORD,
    tlsOptions: {
      rejectUnauthorized: false
    }
  };
  

const ad = new ActiveDirectory(adConfig);


// Express + HBS setup
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));
hbs.registerHelper('eq', (a, b) => a === b);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({ secret: 'ldapSecret', resave: false, saveUninitialized: false }));


hbs.registerHelper('ouPath', function(dn) {
  // dn = "OU=Child,OU=Parent,DC=foo,DC=bar"
  return dn
    .split(',')
    .filter(part => part.startsWith('OU='))
    .map(part => part.slice(3))        // strip "OU="
    .reverse()                         // show top-level first
    .join(' / ');
});


// Middleware
function ensureAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/');
}





// ----------------- ROUTES -----------------

// Login Page
app.get('/', (req, res) => res.render('login'));

// Handle Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const userPrincipalName = `${username}@${domain}`;
  if (!username || !password) return res.render('login', { error: 'Username and password required.' });

  ad.authenticate(userPrincipalName, password, (err, auth) => {
    if (err || !auth) {
      console.error('Authentication error:', err);
      return res.render('login', { error: 'Invalid username or password.', username });
    }
    req.session.user = { username, userPrincipalName };
    res.redirect('/dashboard/users');
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard: USERS
app.get('/dashboard/users', ensureAuthenticated, async (req, res) => {
  try {
    const { users, ouList } = await getAllUsersAndOUs();
    res.render('dashboard', { page: 'users', users, ouList });
  } catch (error) {
    console.error('Error loading dashboard/users:', error);
    res.status(500).send('Error loading users');
  }
});

// Dashboard: GROUPS
app.get('/dashboard/groups', ensureAuthenticated, async (req, res) => {
    try {
      const groups = await getAllGroups();
      res.render('dashboard', { page: 'groups', groups, users: [] });
    } catch (error) {
      console.error('Error loading groups:', error);
      res.status(500).send('Error loading groups');
    }
  });

// API: Get Members of Group
app.get('/api/group/members', ensureAuthenticated, async (req, res) => {
    const groupName = req.query.group;
    if (!groupName) return res.status(400).send('Group name required');
  
    try {
      const { groupDN, members } = await getGroupMembers(groupName);
      res.json({ groupDN, members });
    } catch (error) {
      console.error('Error loading group members:', error);
      res.status(500).send('Error loading group members');
    }
  });

// API: Add User to Group
  
app.post('/api/group/add', ensureAuthenticated, async (req, res) => {
    const { username, group } = req.body;
    if (!username || !group) return res.status(400).json({ success: false, message: 'Missing fields' });
  
    try {
      await addUserToGroup(username, group);
      res.json({ success: true });
    } catch (error) {
      console.error('Error adding user to group:', error);
      res.status(500).json({ success: false, message: error.message });
    }
  });

app.post('/api/group/remove', ensureAuthenticated, async (req, res) => {
    const { username, groupDN } = req.body;
    if (!username || !groupDN) return res.status(400).json({ success: false, message: 'Missing username or group DN' });
  
    try {
      await removeUserFromGroup(username, groupDN);
      res.json({ success: true });
    } catch (error) {
      console.error('Error removing user from group:', error);
      res.status(500).json({ success: false, message: error.message });
    }
  });

app.get('/api/user/details', ensureAuthenticated, async (req, res) => {
const username = req.query.username;
if (!username) return res.status(400).json({ success: false, message: 'Missing username' });

try {
    const userDetails = await getUserDetails(username);
    res.json(userDetails);
} catch (error) {
    console.error('Error in /api/user/details:', error);
    res.status(500).json({ success: false, message: error.message });
}
});

app.get('/api/users/search', ensureAuthenticated, async (req, res) => {
    const search = req.query.q;
    if (!search) return res.json([]);
  
    try {
      const users = await searchUsers(search);
      res.json(users);
    } catch (error) {
      console.error('Error searching users:', error);
      res.json([]);
    }
  });

app.post('/api/user/move-ou', ensureAuthenticated, async (req, res) => {
    const { username, newOu } = req.body;
    if (!username || !newOu) {
      return res.status(400).json({ success: false, message: 'Missing fields' });
    }
  
    try {
      await moveUserToOU(username, newOu);
      res.json({ success: true });
    } catch (error) {
      console.error('Error moving user to new OU:', error);
      res.status(500).json({ success: false, message: error.message });
    }
  });

app.post('/api/user/enable', ensureAuthenticated, async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ success: false, message: 'Username is required' });
  }

  try {
    const result = await enableUser(username);
    res.json(result);
  } catch (error) {
    console.error('Enable user error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

  app.post('/api/user/disable', ensureAuthenticated, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ success: false, message: 'Username required' });
  
    try {
      await disableUser(username);
      res.json({ success: true });
    } catch (error) {
      console.error('Error disabling user:', error);
      res.status(500).json({ success: false, message: error.message });
    }
  });

  app.post('/api/user/reset-password', ensureAuthenticated, async (req, res) => {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) {
      return res.status(400).json({ success: false, message: 'Missing username or password' });
    }
  
    try {
      const result = await resetPassword(username, newPassword);
      res.json(result);
    } catch (err) {
      console.error('Error resetting password:', err);
      res.status(500).json({ success: false, message: err.message });
    }
  });








  




// app.post('/api/user/move-ou', ensureAuthenticated, async (req, res) => {
//     const { username, newOu } = req.body;
//     if (!username || !newOu) {
//       return res.status(400).json({ success: false, message: 'Missing username or new OU' });
//     }
  
//     try {
//       // 1. Find the user's DN using a proper LDAP search
//       const userResult = await new Promise((resolve, reject) => {
//         ad.find({
//           baseDN: process.env.AD_BASEDN,
//           filter: `(&(objectClass=user)(sAMAccountName=${username}))`,
//           attributes: ['dn', 'cn']
//         }, (err, result) => {
//           if (err || !result.users || result.users.length === 0) return reject(new Error('User not found'));
//           resolve(result.users[0]);
//         });
//       });
  
//       const currentDn = userResult.dn;
//       const cn = userResult.cn;
//       const newDn = `CN=${cn},${newOu}`;
  
//       // 2. Create a new LDAPS client
//       const client = ldap.createClient({
//         url: process.env.AD_URL,
//         tlsOptions: { rejectUnauthorized: false }
//       });
  
//       await new Promise((resolve, reject) => client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD, err => err ? reject(err) : resolve()));
  
//       // 3. Move the user
//       await new Promise((resolve, reject) => client.modifyDN(currentDn, newDn, err => err ? reject(err) : resolve()));
  
//       client.unbind();
  
//       console.log(`Moved ${username} to ${newOu}`);
//       res.json({ success: true });
//     } catch (error) {
//       console.error('Error moving user OU:', error);
//       res.status(500).json({ success: false, message: error.message });
//     }
//   });

app.post('/api/user/update-info', async (req, res) => {
  const { oldUsername, newName, newUsername, newEmail } = req.body;

  if (!oldUsername) {
    return res.status(400).json({ success: false, error: 'Missing oldUsername' });
  }

  const result = await updateADUser({ oldUsername, newName, newUsername, newEmail });
  res.json(result);
});

  // app.post('/api/user/create', async (req, res) => {
  //   const { name, username, email, password, groups = [], ou } = req.body;
  
  //   if (!name || !username || !email || !password || !ou) {
  //     return res.status(400).json({ success: false, message: 'Missing required fields' });
  //   }
  
  //   const userDN = `CN=${name},${ou}`;
  
  //   try {
  //     const client = createLdapClient();
  //     await new Promise((resolve, reject) => client.bind(process.env.AD_USERNAME, process.env.AD_PASSWORD, err => err ? reject(err) : resolve()));
  
  //     console.log(`👤 Creating user: ${username} at ${userDN}`);
  
  //     const entry = {
  //       cn: name,
  //       sn: name.split(' ').slice(-1)[0] || name,
  //       objectClass: ['top', 'person', 'organizationalPerson', 'user'],
  //       sAMAccountName: username,
  //       userPrincipalName: email,
  //       displayName: name,
  //       givenName: name.split(' ')[0] || name,
  //       mail: email,
  //       userAccountControl: '514'  // Disabled initially
  //     };
  
  //     // ➡️ 1. Add user
  //     await new Promise((resolve, reject) => client.add(userDN, entry, err => err ? reject(err) : resolve()));
  //     console.log(`✅ User created`);
  
  //     // ➡️ 2. Set password
  //     const passwordAttr = new Attribute({
  //       type: 'unicodePwd',
  //       values: [Buffer.from(`"${password}"`, 'utf16le')]
  //     });
  
  //     const passwordChange = new Change({
  //       operation: 'replace',
  //       modification: passwordAttr
  //     });
  
  //     await new Promise((resolve, reject) => client.modify(userDN, passwordChange, err => err ? reject(err) : resolve()));
  //     console.log(`✅ Password set`);
  
  //     // ➡️ 3. Enable account
  //     const enableAttr = new Attribute({
  //       type: 'userAccountControl',
  //       values: ['512']
  //     });
  
  //     const enableChange = new Change({
  //       operation: 'replace',
  //       modification: enableAttr
  //     });
  
  //     await new Promise((resolve, reject) => client.modify(userDN, enableChange, err => err ? reject(err) : resolve()));
  //     console.log(`✅ Account enabled`);
  
  //     // ➡️ 4. Add user to groups (optional)
  //     for (const group of groups) {
  //       const groupDN = `CN=${group},${process.env.AD_GROUPS_OU || process.env.AD_BASEDN}`;  // Adjust if needed
  
  //       const addMemberAttr = new Attribute({
  //         type: 'member',
  //         values: [userDN]
  //       });
  
  //       const addMemberChange = new Change({
  //         operation: 'add',
  //         modification: addMemberAttr
  //       });
  
  //       await new Promise((resolve, reject) => client.modify(groupDN, addMemberChange, err => err ? reject(err) : resolve()));
  //       console.log(`✅ Added to group: ${group}`);
  //     }
  
  //     client.unbind();
  //     res.json({ success: true });
  
  //   } catch (error) {
  //     console.error('❌ Error creating user:', error);
  //     res.status(500).json({ success: false, message: error.message });
  //   }
  // });
  
  app.get('/api/user/groups-ous', ensureAuthenticated, async (req, res) => {
    try {
      const { groups, ous } = await getGroupsAndOUs();
      res.json({ success: true, groups, ous });
    } catch (error) {
      console.error('Error loading groups/OUs:', error);
      res.status(500).json({ success: false, message: 'Failed to load groups and OUs.' });
    }
  });
  
  app.post('/api/user/create', async (req, res) => {
    const { name, username, email, password, groups = [], ou } = req.body;
    if (!name || !username || !email || !password || !ou) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }
  
    try {
      await createADUser({ name, username, email, password, groups, ou });
      res.json({ success: true });
    } catch (error) {
      console.error('❌ Error creating user:', error);
      res.status(500).json({ success: false, message: error.message });
    }
  });


  
  
  
  
  

// Start server
app.listen(PORT, () => console.log(`Server running at https://localhost:${PORT}`));
