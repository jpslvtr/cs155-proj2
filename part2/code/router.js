import express from 'express';
import sqlite from 'sqlite';

import { asyncMiddleware } from './utils/asyncMiddleware';
import sleep from './utils/sleep';
import { generateRandomness, HMAC, KDF, checkPassword } from './utils/crypto';

const router = express.Router();
const dbPromise = sqlite.open('./db/database.sqlite');

function render(req, res, next, page, title, errorMsg = false, result = null, nonce = null) {
  res.render(
    'layout/template', {
    page,
    title,
    loggedIn: req.session.loggedIn,
    account: req.session.account,
    errorMsg,
    result,
    nonce,
  }
  );
}

// https://stackoverflow.com/questions/1527803/generating-random-whole-numbers-in-javascript-in-a-specific-range
function getRandomInt(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1) + min);
}

/* Secret Key and HMAC helper functions for Exploits Charlie and Delta, used across several endpoints */
const secretKey = generateRandomness();
const generateTag = cookie => HMAC(secretKey, JSON.stringify(cookie.loggedIn) + JSON.stringify(cookie.account));
const verifyTag = cookie => cookie.HMAC === HMAC(secretKey, JSON.stringify(cookie.loggedIn) + JSON.stringify(cookie.account));


router.get('/', (req, res, next) => {
  render(req, res, next, 'index', 'Bitbar Home');
});


router.post('/set_profile', asyncMiddleware(async (req, res, next) => {
  if (!verifyTag(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  req.session.account.profile = req.body.new_profile;
  console.log(req.body.new_profile);
  const db = await dbPromise;
  const query = `UPDATE Users SET profile = ? WHERE username = "${req.session.account.username}";`;
  const result = await db.run(query, req.body.new_profile);

  req.session.HMAC = generateTag(req.session);
  render(req, res, next, 'index', 'Bitbar Home');

}));


router.get('/login', (req, res, next) => {
  render(req, res, next, 'login/form', 'Login');
});


router.get('/get_login', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
  const result = await db.get(query);

  if(result) { // if this username actually exists
    if(checkPassword(req.query.password, result)) { // if password is valid
      var randomTime1 = getRandomInt(100,200);
      await sleep(randomTime1);
      req.session.loggedIn = true;
      req.session.account = result;
      req.session.HMAC = generateTag(req.session);
      render(req, res, next, 'login/success', 'Bitbar Home');
      return;
    }
    else { // if password is invalid
      // slightly larger range because requests with invalid passwords are faster
      var randomTime2 = getRandomInt(100,300);
      await sleep(randomTime2);
      render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
      return;
    }
  }

  render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
  return;
}));


router.get('/register', (req, res, next) => {
  render(req, res, next, 'register/form', 'Register');
});


router.post('/post_register', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.username}";`;
  let result = await db.get(query);
  if (result) { // query returns results
    if (result.username === req.body.username) { // if username exists
      render(req, res, next, 'register/form', 'Register', 'This username already exists!');
      return;
    }
  }
  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);
  console.log(hashedPassword);
  console.log(salt);
  query = `INSERT INTO Users(username, hashedPassword, salt, profile, bitbars) VALUES(?, ?, ?, ?, ?)`;
  await db.run(query, [req.body.username, hashedPassword, salt, '', 100]);
  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: '',
    bitbars: 100,
  };
  req.session.HMAC = generateTag(req.session);
  render(req, res, next, 'register/success', 'Bitbar Home');
}));


router.get('/close', asyncMiddleware(async (req, res, next) => {
  if (!verifyTag(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  if (req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  const db = await dbPromise;

  /* Exploit Echo Defense */
  const query = `DELETE FROM Users WHERE username = ?;`;
  await db.get(query, req.session.account.username);

  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
}));


router.get('/logout', (req, res, next) => {
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
});


router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if (!verifyTag(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  if (req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  // CSP with nonce
  const nonce_csp = generateRandomness();
  const csp_profile = `script-src 'nonce-${nonce_csp}' 'strict-dynamic' 'unsafe-eval';`;
  res.header("Content-Security-Policy", csp_profile);

  if (req.query.username != null) { // if visitor makes a search query

    /* Exploit Alpha Defense - contains HTML tag characters, which we determine to be invalid */
    if (req.query.username.toUpperCase().includes('<') ||
      req.query.username.toUpperCase().includes('>') ||
      req.query.username.toUpperCase().includes('%3C') ||
      req.query.username.toUpperCase().includes('%3E')) {
      render(req, res, next, 'profile/view', 'View Profile', `Profile name contains invalid characters!`, false);
      return;
    }

    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
    let result;
    try {
      result = await db.get(query);
    } catch (err) {
      result = false;
    }
    if (result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result, nonce_csp);
    }
    else { // user does not exist
      render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account, nonce_csp);
  }
}));


router.get('/transfer', (req, res, next) => {
  if (!verifyTag(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  if (req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  if (req.session) req.session.csrf_token = generateRandomness(); /* Exploit Bravo Defense */
  render(req, res, next, 'transfer/form', 'Transfer Bitbars', false, { receiver: null, amount: null, csrf_token: req.session.csrf_token });
});


router.post('/post_transfer', asyncMiddleware(async (req, res, next) => {
  if (!verifyTag(req.session)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  

  // CSP
  const csp_transfer = `script-src 'self';`;
  res.header("Content-Security-Policy", csp_transfer);
  
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if (req.body.csrf_token !== req.session.csrf_token) { /* Exploit Bravo Defense */
    req.session.loggedIn = false;
    req.session.account = {};
    req.session.csrf_token = false;
    render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!'); // log out if detected csrf_token
    return;
  }

  if (req.body.destination_username === req.session.account.username) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!', { receiver: null, amount: null, csrf_token: req.session.csrf_token });
    return;
  }


  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.destination_username}";`;
  const receiver = await db.get(query);
  if (receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if (Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!', { receiver: null, amount: null, csrf_token: req.session.csrf_token });
      return;
    }

    req.session.account.bitbars -= amount;
    query = `UPDATE Users SET bitbars = "${req.session.account.bitbars}" WHERE username == "${req.session.account.username}";`;
    await db.exec(query);
    const receiverNewBal = receiver.bitbars + amount;
    query = `UPDATE Users SET bitbars = "${receiverNewBal}" WHERE username == "${receiver.username}";`;
    await db.exec(query);
    req.session.HMAC = generateTag(req.session);
    render(req, res, next, 'transfer/success', 'Transfer Complete', false, { receiver, amount, csrf_token: req.session.csrf_token });
  } else { // user does not exist
    let q = req.body.destination_username;
    if (q == null) q = '';

    let oldQ;
    while (q !== oldQ) {
      oldQ = q;
      q = q.replace(/script|SCRIPT|img|IMG/g, '');
    }
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', `User ${q} does not exist!`, { receiver: null, amount: null, csrf_token: req.session.csrf_token });
  }
}));


router.get('/steal_cookie', (req, res, next) => {
  let stolenCookie = req.query.cookie;
  console.log('\n\n' + stolenCookie + '\n\n');
  render(req, res, next, 'theft/view_stolen_cookie', 'Cookie Stolen!', false, stolenCookie);
});

router.get('/steal_password', (req, res, next) => {
  let password = req.query.password;
  let timeElapsed = req.query.timeElapsed;
  console.log(`\n\nPassword: ${req.query.password}, time elapsed: ${req.query.timeElapsed}\n\n`);
  res.end();
});


module.exports = router;