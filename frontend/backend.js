const express = require('express');
const path = require('path');
const session = require('express-session');                  
const { hashPassword, checkPassword } = require('./createHash');

const { Pool } = require('pg');

const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'crisp',
  user: 'postgres',
  password: 'crisppassword'
});

const app = express();

app.use(express.urlencoded({ extended: true }));


app.use(session({
  secret: 'change-this-to-a-long-random-string',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24
  }
}));


function requireLogin(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/');
  }
}

app.use('/Styles', express.static(path.join(__dirname, 'Styles')));
app.use('/icons', express.static(path.join(__dirname, 'icons')));
app.use('/src', express.static(path.join(__dirname, 'src')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    'SELECT * FROM user_account WHERE username = $1',
    [username]
  );
  const user = result.rows[0];

  if (user && await checkPassword(password, user.password_hash)) {
   
    req.session.user = {
      id: user.user_id,
      username: user.username,
      role: user.role,
      organizationId: user.organization_id
    };
    res.redirect('/dashboard');
  } else {
    res.status(401).send('Wrong username or password.');
  }
});


app.get('/dashboard', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});


app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});