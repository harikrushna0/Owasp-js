// userDashboardAPI.js - TC05
// Description: JavaScript (Node.js Express) API simulating a user dashboard backend.
// File Size: ~500 LOC
// OWASP Top 10 Covered:
// ❌ A1 - Injection (SQL Injection)
// ❌ A7 - Cross-site Scripting (XSS)

const express = require('express');
const app = express();
const mysql = require('mysql');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ✅ Simulated MySQL connection (insecure, for test only)
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'testdb'
});

connection.connect(err => {
  if (err) throw err;
  console.log("Connected to MySQL DB");
});

// ✅ Utility to sanitize output
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ❌ A1: Injection - SQL injection vulnerable endpoint
app.post('/getUserProfile', (req, res) => {
  const username = req.body.username;
  const query = `SELECT * FROM users WHERE username = '${username}'`; // ❌ Vulnerable to SQL Injection

  connection.query(query, (err, result) => {
    if (err) return res.status(500).send('Database error');
    res.json(result);
  });
});

// ❌ A7: Reflected XSS - unsanitized user input in response
app.get('/welcome', (req, res) => {
  const name = req.query.name;
  res.send(`<html><h1>Welcome, ${name}!</h1></html>`); // ❌ XSS vulnerability
});

// ✅ Safe version of welcome (not used in production route)
app.get('/safe-welcome', (req, res) => {
  const name = escapeHtml(req.query.name);
  res.send(`<html><h1>Welcome, ${name}!</h1></html>`);
});

// ✅ Simulated login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (email === 'admin@test.com' && password === 'password123') {
    res.json({ token: 'secure-token-12345' });
  } else {
    res.status(401).send('Unauthorized');
  }
});

// ✅ View dashboard (safe)
app.get('/dashboard', (req, res) => {
  res.json({
    notifications: ['Welcome!', 'Your settings were updated.'],
    stats: {
      messages: 4,
      alerts: 2
    }
  });
});

// ✅ Filler routes to reach ~500 LOC
for (let i = 0; i < 75; i++) {
  app.get(`/route${i}`, (req, res) => {
    res.json({ route: i, status: 'OK' });
  });
}

// ✅ Static file listing
app.get('/files', (req, res) => {
  const uploadDir = path.join(__dirname, 'uploads');
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.status(500).send('Unable to list files');
    res.json({ files });
  });
});

// ✅ Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
