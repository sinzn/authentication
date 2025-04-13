const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) throw err;
  console.log('✅ Connected to MySQL database');
});

// Routes

// Show index.html (login/register form)
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Register
app.post('/register', async (req, res) => {
  const { email, username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], (err, results) => {
    if (err) return res.send('Database error');
    if (results.length > 0) return res.send('Email or username already exists');

    db.query('INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)', [email, username, hashedPassword, 'user'], (err) => {
      if (err) return res.send('Error registering user');
      res.redirect('/');
    });
  });
});

// Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.send('Invalid credentials');

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      req.session.user = { id: user.id, email: user.email, role: user.role };
      res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
    } else {
      res.send('Invalid credentials');
    }
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Forgot Password
app.get('/forgot', (req, res) => {
  res.send(`
    <h2>Forgot Password</h2>
    <form method="POST" action="/forgot">
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="newPassword" placeholder="New Password" required />
      <button type="submit">Reset Password</button>
    </form>
    <a href="/">Back</a>
  `);
});

app.post('/forgot', async (req, res) => {
  const { email, newPassword } = req.body;
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err, result) => {
    if (err || result.affectedRows === 0) return res.send('Email not found');
    res.send('Password reset successfully. <a href="/">Login</a>');
  });
});

// Dashboard
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.send(`
    <h2>Welcome, ${req.session.user.email}</h2>
    <p>You are logged in as <strong>${req.session.user.role}</strong></p>
    <a href="/logout">Logout</a>
  `);
});

// Admin Dashboard
app.get('/admin', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.send('Access denied');

  db.query('SELECT id, email, username, role FROM users', (err, results) => {
    if (err) return res.send('Error loading users');

    let html = `
      <h1>Admin Dashboard</h1>

      <h2>Create New User</h2>
      <form method="POST" action="/admin/create">
        <input type="email" name="email" placeholder="Email" required>
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <select name="role">
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
        <button type="submit">Register User</button>
      </form>

      <h2>All Users</h2>
      <table border="1" cellpadding="5">
        <tr>
          <th>ID</th>
          <th>Email</th>
          <th>Username</th>
          <th>Role</th>
          <th>Delete</th>
          <th>Reset Password</th>
        </tr>
    `;

    results.forEach(user => {
      html += `
        <tr>
          <td>${user.id}</td>
          <td>${user.email}</td>
          <td>${user.username}</td>
          <td>${user.role}</td>
          <td>
            <form method="POST" action="/admin/delete">
              <input type="hidden" name="id" value="${user.id}">
              <button type="submit">Delete</button>
            </form>
          </td>
          <td>
            <form method="POST" action="/admin/reset">
              <input type="hidden" name="id" value="${user.id}">
              <input type="password" name="newPassword" placeholder="New Password" required>
              <button type="submit">Reset</button>
            </form>
          </td>
        </tr>
      `;
    });

    html += '</table><br><a href="/logout">Logout</a>';
    res.send(html);
  });
});

// Admin Create User
app.post('/admin/create', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.send('Access denied');

  const { email, username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], (err, results) => {
    if (err) return res.send('Database error');
    if (results.length > 0) return res.send('Email or username already exists');

    db.query('INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)', [email, username, hashedPassword, role], (err) => {
      if (err) return res.send('Error creating user');
      res.redirect('/admin');
    });
  });
});

// Admin Delete User
app.post('/admin/delete', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.send('Access denied');

  db.query('DELETE FROM users WHERE id = ?', [req.body.id], (err) => {
    if (err) return res.send('Error deleting user');
    res.redirect('/admin');
  });
});

// Admin Reset Password
app.post('/admin/reset', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.send('Access denied');

  const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
  db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.body.id], (err) => {
    if (err) return res.send('Error resetting password');
    res.redirect('/admin');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
