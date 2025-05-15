// adminPortalAPI.js - TC06 Enhanced
// Language: JavaScript (Node.js + Express)
// Target Size: ~1500 LOC
// OWASP Top 10 Covered:
// ✅ A3 - Sensitive Data Exposure (Fixed)
// ✅ A9 - Insufficient Logging & Monitoring (Fixed)

const express = require('express');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const app = express();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const validator = require('validator');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');

// Configuration
require('dotenv').config();
const SALT_ROUNDS = 12;
const TOKEN_EXPIRY = '1h';
const LOGIN_ATTEMPTS_LIMIT = 5;

// Database simulation
class Database {
  constructor() {
    this.users = [];
    this.sessions = [];
    this.auditLogs = [];
    this.settings = Array(100).fill(0).map((_,i) => ({
      id: i,
      name: `setting_${i}`,
      value: `default_value_${i}`
    }));
  }

  logEvent(type, details, userId = null) {
    const entry = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      type,
      details,
      userId
    };
    this.auditLogs.push(entry);
    fs.appendFileSync('audit.log', JSON.stringify(entry) + '\n');
  }
}

const db = new Database();

// Middleware setup
app.use(helmet());
app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('combined'));

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});

const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: LOGIN_ATTEMPTS_LIMIT,
  message: 'Too many login attempts, please try again later'
});

// Utility functions
function generateAccessToken(user) {
  return jwt.sign(
    { 
      userId: user.id,
      username: user.username,
      role: user.role 
    },
    process.env.JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

function validatePassword(password) {
  return password.length >= 8 &&
         /[A-Z]/.test(password) &&
         /[0-9]/.test(password) &&
         /[^A-Za-z0-9]/.test(password);
}

// Authentication Middleware
async function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    db.logEvent('auth_failure', 'Missing token');
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    
    // Verify user still exists
    const userExists = db.users.some(u => u.id === decoded.userId);
    if (!userExists) {
      db.logEvent('auth_failure', 'Token for non-existent user');
      return res.status(403).json({ error: 'Invalid user' });
    }
    
    db.logEvent('auth_success', `User ${decoded.username} authenticated`, decoded.userId);
    next();
  } catch (err) {
    db.logEvent('auth_failure', `Invalid token: ${err.message}`);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      db.logEvent('auth_failure', `User ${req.user.username} attempted ${role}-only access`);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Routes
app.post('/admin/register', async (req, res) => {
  try {
    const { username, password, email, inviteCode } = req.body;
    
    if (!username || !password || !email || !inviteCode) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (inviteCode !== process.env.ADMIN_INVITE_CODE) {
      db.logEvent('registration_failure', 'Invalid invite code used');
      return res.status(403).json({ error: 'Invalid invite code' });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (!validatePassword(password)) {
      return res.status(400).json({ 
        error: 'Password must be at least 8 characters with uppercase, number, and special character' 
      });
    }
    
    const exists = db.users.some(u => u.username === username || u.email === email);
    if (exists) {
      db.logEvent('registration_failure', `Duplicate registration attempt for ${username}`);
      return res.status(409).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const newUser = {
      id: uuidv4(),
      username,
      password: hashedPassword,
      email,
      role: 'admin',
      createdAt: new Date().toISOString(),
      lastLogin: null
    };
    
    db.users.push(newUser);
    db.logEvent('registration_success', `User ${username} registered`, newUser.id);
    
    const token = generateAccessToken(newUser);
    res.status(201).json({ 
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (err) {
    db.logEvent('error', `Registration error: ${err.message}`);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/admin/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = db.users.find(u => u.username === username);
    if (!user) {
      db.logEvent('auth_failure', `Login attempt for non-existent user: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      db.logEvent('auth_failure', `Invalid password for user: ${username}`, user.id);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date().toISOString();
    
    const token = generateAccessToken(user);
    db.logEvent('auth_success', `User ${username} logged in`, user.id);
    
    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    db.logEvent('error', `Login error: ${err.message}`);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/admin/dashboard', verifyToken, requireRole('admin'), (req, res) => {
  try {
    const stats = {
      totalUsers: db.users.length,
      activeSessions: db.sessions.length,
      lastLogin: req.user.lastLogin,
      systemHealth: 'operational'
    };
    
    db.logEvent('dashboard_access', `User ${req.user.username} accessed dashboard`, req.user.userId);
    res.json({ user: req.user, stats });
  } catch (err) {
    db.logEvent('error', `Dashboard error: ${err.message}`, req.user?.userId);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

// User management routes
app.get('/admin/users', verifyToken, requireRole('admin'), (req, res) => {
  try {
    const userList = db.users.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin
    }));
    
    db.logEvent('user_list', `User ${req.user.username} accessed user list`, req.user.userId);
    res.json({ users: userList });
  } catch (err) {
    db.logEvent('error', `User list error: ${err.message}`, req.user.userId);
    res.status(500).json({ error: 'Failed to retrieve users' });
  }
});

app.put('/admin/users/:id', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    
    if (!['admin', 'editor', 'viewer'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified' });
    }
    
    const user = db.users.find(u => u.id === id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.id === req.user.userId) {
      return res.status(400).json({ error: 'Cannot modify your own role' });
    }
    
    const oldRole = user.role;
    user.role = role;
    
    db.logEvent(
      'user_modified', 
      `User ${req.user.username} changed ${user.username} role from ${oldRole} to ${role}`,
      req.user.userId
    );
    
    res.json({ 
      message: 'User role updated',
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (err) {
    db.logEvent('error', `User update error: ${err.message}`, req.user.userId);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Settings management
app.get('/admin/settings', verifyToken, (req, res) => {
  try {
    const settings = db.settings.map(s => ({
      id: s.id,
      name: s.name,
      value: s.value
    }));
    
    res.json({ settings });
  } catch (err) {
    db.logEvent('error', `Settings error: ${err.message}`, req.user?.userId);
    res.status(500).json({ error: 'Failed to retrieve settings' });
  }
});

app.put('/admin/settings/:id', verifyToken, requireRole('admin'), (req, res) => {
  try {
    const { id } = req.params;
    const { value } = req.body;
    
    const setting = db.settings.find(s => s.id === Number(id));
    if (!setting) {
      return res.status(404).json({ error: 'Setting not found' });
    }
    
    const oldValue = setting.value;
    setting.value = value;
    
    db.logEvent(
      'setting_changed',
      `User ${req.user.username} changed ${setting.name} from ${oldValue} to ${value}`,
      req.user.userId
    );
    
    res.json({ 
      message: 'Setting updated',
      setting: {
        id: setting.id,
        name: setting.name,
        value: setting.value
      }
    });
  } catch (err) {
    db.logEvent('error', `Setting update error: ${err.message}`, req.user.userId);
    res.status(500).json({ error: 'Failed to update setting' });
  }
});

// Audit log routes
app.get('/admin/audit', verifyToken, requireRole('admin'), (req, res) => {
  try {
    const { limit = 100, type } = req.query;
    
    let logs = db.auditLogs;
    if (type) {
      logs = logs.filter(log => log.type === type);
    }
    
    logs = logs.slice(0, Math.min(Number(limit), 1000));
    
    res.json({ logs });
  } catch (err) {
    db.logEvent('error', `Audit log error: ${err.message}`, req.user.userId);
    res.status(500).json({ error: 'Failed to retrieve audit logs' });
  }
});

// System health endpoints
app.get('/admin/health', verifyToken, (req, res) => {
  try {
    const health = {
      status: 'OK',
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      dbSize: {
        users: db.users.length,
        logs: db.auditLogs.length
      }
    };
    
    res.json(health);
  } catch (err) {
    res.status(500).json({ status: 'ERROR', error: err.message });
  }
});

// Additional filler routes for testing
require('./fillerRoutes')(app, db, verifyToken);

// Error handling
app.use((err, req, res, next) => {
  db.logEvent('error', `Unhandled error: ${err.message}`, req.user?.userId);
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Admin Portal API running on port ${PORT}`);
  db.logEvent('system', `Server started on port ${PORT}`);
});

// Create initial admin if none exists
async function initializeAdmin() {
  if (db.users.length === 0 && process.env.ADMIN_INIT_PASSWORD) {
    const hashedPassword = await bcrypt.hash(process.env.ADMIN_INIT_PASSWORD, SALT_ROUNDS);
    db.users.push({
      id: uuidv4(),
      username: 'admin',
      password: hashedPassword,
      email: 'admin@example.com',
      role: 'admin',
      createdAt: new Date().toISOString()
    });
    db.logEvent('system', 'Initial admin user created');
  }
}

initializeAdmin();
