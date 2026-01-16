/*
 * Simple backend server for the AHELP wellness application.
 *
 * This server is implemented without external dependencies using Node.js built‑in
 * modules only. It provides a REST‑like API for user registration, login,
 * activity logging and reward redemption. Data is persisted to a JSON file
 * (db.json) located in the same directory as the server. If the file does
 * not exist at startup it will be created automatically.
 *
 * Endpoints:
 *   POST /api/signup      – create a new user account
 *   POST /api/login       – authenticate an existing user
 *   GET  /api/user        – retrieve user data (query param: email)
 *   POST /api/activities  – log an activity (exercise, nutrition, etc.)
 *   POST /api/redeem      – redeem points for time off rewards
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PASSWORD_MIN_LENGTH = 8;
const EMPLOYEE_NUMBER_RE = /^[0-9A-Za-z-]{3,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PBKDF2_ITERATIONS = 100000;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const RATE_LIMITS = new Map();

// Path to JSON database file
const DB_FILE = path.join(__dirname, 'db.json');

// Load or initialize the database
let db = { users: [] };
function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    try {
      const data = fs.readFileSync(DB_FILE, 'utf8');
      db = JSON.parse(data);
    } catch (err) {
      console.error('Failed to parse DB file, starting with empty database.', err);
      db = { users: [] };
    }
  }
}

// Persist the database to disk
function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

// Initialize DB on server start
loadDB();

// Path and store for authorised users (imported from SAP)
const AUTH_FILE = path.join(__dirname, 'authorized_users.json');
let authorizedUsers = {};

function loadAuthorizedUsers() {
  // Load authorised users list from a JSON file. The file should map lowercased email
  // addresses to employee numbers. Example:
  // {
  //   "john@example.com": "12345",
  //   "jane@example.com": "54321"
  // }
  if (fs.existsSync(AUTH_FILE)) {
    try {
      const data = fs.readFileSync(AUTH_FILE, 'utf8');
      authorizedUsers = JSON.parse(data);
    } catch (err) {
      console.error('Failed to parse authorised users file', err);
      authorizedUsers = {};
    }
  }
}

// Load authorised users at startup
loadAuthorizedUsers();

// Helper functions for password hashing and verification
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 64, 'sha512').toString('hex');
  return { salt, hash, iterations: PBKDF2_ITERATIONS };
}

function verifyPassword(password, user) {
  if (!user.salt) {
    return { ok: password === user.password, needsUpgrade: true };
  }
  const iterations = user.iterations || PBKDF2_ITERATIONS;
  const hash = crypto.pbkdf2Sync(password, user.salt, iterations, 64, 'sha512').toString('hex');
  return { ok: hash === user.password, needsUpgrade: false };
}

function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
}

function getClientKey(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = Array.isArray(forwarded) ? forwarded[0] : forwarded || req.socket.remoteAddress || 'unknown';
  return ip;
}

function isRateLimited(req, key, maxRequests) {
  const clientKey = getClientKey(req);
  const now = Date.now();
  const bucketKey = `${clientKey}:${key}`;
  const bucket = RATE_LIMITS.get(bucketKey) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }
  bucket.count += 1;
  RATE_LIMITS.set(bucketKey, bucket);
  return bucket.count > maxRequests;
}

// Helper to send JSON responses
function sendJSON(res, status, payload) {
  applySecurityHeaders(res);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(payload));
}

// Simple in-memory session store. Each session maps a token to an object containing
// the user's email, whether they are an admin, and an expiry timestamp. Sessions
// expire after 12 hours. When a user logs in, a new session token is created
// and stored here. For a production deployment you would persist sessions in a
// durable store (like Redis) and enforce HTTPS (Secure cookies).
const sessions = new Map();

function newSession(user) {
  // Generate a random token and store session data. The token is returned to the
  // client via a cookie. The session stores the lowercase email and admin flag.
  const token = crypto.randomBytes(32).toString('hex');
  const adminAgency = user.isAdmin ? (user.adminAgency || user.agency || 'all') : null;
  sessions.set(token, {
    email: user.email.toLowerCase(),
    isAdmin: !!user.isAdmin,
    adminAgency,
    expiresAt: Date.now() + (12 * 60 * 60 * 1000) // 12 hours
  });
  return token;
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const parts = raw.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf('=');
    const key = idx >= 0 ? trimmed.slice(0, idx) : trimmed;
    if (key === name) {
      return decodeURIComponent(trimmed.slice(idx + 1));
    }
  }
  return null;
}

function getSession(req) {
  const token = getCookie(req, 'ahelp_session');
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function requireAuth(req, res) {
  const session = getSession(req);
  if (!session) {
    // Redirect unauthenticated users to the login page
    res.writeHead(302, { Location: '/login.html' });
    res.end();
    return null;
  }
  return session;
}

function requireAdmin(req, res) {
  const session = getSession(req);
  if (!session || !session.isAdmin) {
    // Deny access to non‑admins. Do not reveal details to avoid information leakage.
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Access denied');
    return null;
  }
  return session;
}

// Helper to parse JSON body
function parseJSONBody(req, callback) {
  let body = '';
  req.on('data', chunk => {
    body += chunk;
    // prevent too large
    if (body.length > 1e6) req.connection.destroy();
  });
  req.on('end', () => {
    try {
      const data = JSON.parse(body || '{}');
      callback(null, data);
    } catch (err) {
      callback(err);
    }
  });
}

function isValidEmail(email) {
  return EMAIL_RE.test(email);
}

function isValidEmployeeNumber(employeeNumber) {
  return EMPLOYEE_NUMBER_RE.test(String(employeeNumber || ''));
}

function sanitizeUser(user) {
  const { password, salt, passwordReset, ...safeUser } = user;
  return safeUser;
}

function filterUsersForAgency(users, agency) {
  if (!agency || agency === 'all') return users;
  return users.filter(user => (user.agency || '').toLowerCase() === String(agency).toLowerCase());
}

function toCsv(rows, headers) {
  const escape = value => {
    const str = value == null ? '' : String(value);
    if (str.includes('"') || str.includes(',') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };
  const lines = [headers.join(',')];
  rows.forEach(row => {
    lines.push(headers.map(header => escape(row[header])).join(','));
  });
  return lines.join('\n');
}

// Compute achievements and level ups based on points
function computeAchievements(user) {
  // Simple achievement rules: award titles based on points
  const achievements = [];
  if (user.points >= 100) achievements.push('Health Enthusiast');
  if (user.points >= 300) achievements.push('Wellness Warrior');
  if (user.points >= 600) achievements.push('Lifestyle Legend');
  return achievements;
}

function computeLevel(points) {
  // Simple level system: each 100 points equals a level
  return Math.floor(points / 100) + 1;
}

// Create the HTTP server
const server = http.createServer((req, res) => {
  const { method } = req;
  const urlObj = new URL(req.url, `http://${req.headers.host}`);
  const pathname = urlObj.pathname;

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    applySecurityHeaders(res);
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  // Endpoint: POST /api/signup
  if (method === 'POST' && pathname === '/api/signup') {
    if (isRateLimited(req, 'signup', 20)) {
      return sendJSON(res, 429, { error: 'Too many requests. Please try again later.' });
    }
    return parseJSONBody(req, (err, data) => {
      if (err) return sendJSON(res, 400, { error: 'Invalid JSON' });
      const { firstName, lastName, email, password, employeeNumber, age, gender, height, weight, smoke, conditions } = data;
      if (!email || !password || !firstName || !employeeNumber) {
        return sendJSON(res, 400, { error: 'Missing required fields' });
      }
      if (!isValidEmail(email)) {
        return sendJSON(res, 400, { error: 'Invalid email address' });
      }
      if (!isValidEmployeeNumber(employeeNumber)) {
        return sendJSON(res, 400, { error: 'Invalid employee number' });
      }
      if (String(password).length < PASSWORD_MIN_LENGTH) {
        return sendJSON(res, 400, { error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` });
      }
      // Authorisation check: email must exist in authorizedUsers and employee number must match
      const authEmp = authorizedUsers[email.toLowerCase()];
      if (!authEmp || authEmp !== String(employeeNumber)) {
        return sendJSON(res, 403, { error: 'You are not authorised to sign up. Please contact your administrator.' });
      }
      // Check if user exists
      const existing = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
      if (existing) {
        return sendJSON(res, 409, { error: 'User already exists' });
      }
      // Hash password
      const { salt, hash, iterations } = hashPassword(password);
      // Create user record
      const newUser = {
        id: Date.now(),
        name: `${firstName} ${lastName || ''}`.trim(),
        email,
        password: hash,
        salt,
        iterations,
        employeeNumber: String(employeeNumber),
        age: age || null,
        gender: gender || null,
        height: height || null,
        weight: weight || null,
        smoke: smoke || 'no',
        conditions: conditions || '',
        agency: data && data.agency ? String(data.agency) : null,
        points: 0,
        weeklyPoints: 0,
        cardioStreak: 0,
        nutritionStreak: 0,
        tobaccoStreak: 0,
        todayCardio: 0,
        activities: [],
        redemptions: [],
        achievements: [],
        mood: 'good',
        darkMode: false,
        level: 1,
        leaveTime: 0,
        // Users are non‑admin by default. Set to true in the DB to grant admin rights.
        isAdmin: data && data.isAdmin === true
      };
      db.users.push(newUser);
      saveDB();
      // Return user data without password and salt
      const { password: __, salt: ___, ...safeUser } = newUser;
      return sendJSON(res, 201, { user: safeUser });
    });
  }

  // Endpoint: POST /api/login
  if (method === 'POST' && pathname === '/api/login') {
    if (isRateLimited(req, 'login', 30)) {
      return sendJSON(res, 429, { error: 'Too many login attempts. Please try again later.' });
    }
    return parseJSONBody(req, (err, data) => {
      if (err) return sendJSON(res, 400, { error: 'Invalid JSON' });
      const { email, password, employeeNumber } = data;
      if (!email || !password || !employeeNumber) {
        return sendJSON(res, 400, { error: 'Missing credentials' });
      }
      if (!isValidEmail(email)) {
        return sendJSON(res, 400, { error: 'Invalid email address' });
      }
      const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
      // Verify user exists, password matches and employee number matches
      const verification = user ? verifyPassword(password, user) : { ok: false };
      if (!user || !verification.ok || user.employeeNumber !== String(employeeNumber)) {
        return sendJSON(res, 401, { error: 'Invalid email or password' });
      }
      if (verification.needsUpgrade) {
        const { salt, hash, iterations } = hashPassword(password);
        user.salt = salt;
        user.password = hash;
        user.iterations = iterations;
        saveDB();
      }
      // Create a new session and set a secure cookie
      const token = newSession(user);
      const isSecure = req.connection.encrypted || req.headers['x-forwarded-proto'] === 'https';
      // Set cookie with HttpOnly so it cannot be accessed via client JavaScript. SameSite=Lax to mitigate CSRF.
      res.setHeader('Set-Cookie', `ahelp_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${12*60*60}${isSecure ? '; Secure' : ''}`);
      // On success return user info (excluding password and salt)
      const safeUser = sanitizeUser(user);
      if (safeUser.isAdmin) {
        safeUser.adminAgency = user.adminAgency || user.agency || 'all';
      }
      return sendJSON(res, 200, { user: safeUser });
    });
  }

  // Endpoint: GET /api/me – return current logged-in user from session cookie
  if (method === 'GET' && pathname === '/api/me') {
    const session = requireAuth(req, res);
    if (!session) return;

    const user = db.users.find(u => u.email.toLowerCase() === session.email.toLowerCase());
    if (!user) return sendJSON(res, 401, { error: 'Unauthorized' });

    const safeUser = sanitizeUser(user);
    if (safeUser.isAdmin) {
      safeUser.adminAgency = user.adminAgency || user.agency || 'all';
    }
    return sendJSON(res, 200, { user: safeUser });
  }

  // Endpoint: GET /api/user?email=...  – get user by email
  if (method === 'GET' && pathname === '/api/user') {
    const email = urlObj.searchParams.get('email');
    if (!email) return sendJSON(res, 400, { error: 'Email query parameter required' });
    const session = requireAuth(req, res);
    if (!session) return;
    if (!session.isAdmin && session.email.toLowerCase() !== email.toLowerCase()) {
      return sendJSON(res, 403, { error: 'Access denied' });
    }
    const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) return sendJSON(res, 404, { error: 'User not found' });
    const safeUser = sanitizeUser(user);
    return sendJSON(res, 200, { user: safeUser });
  }

  // Endpoint: POST /api/activities  – log activity
  if (method === 'POST' && pathname === '/api/activities') {
    const session = requireAuth(req, res);
    if (!session) return;
    return parseJSONBody(req, (err, data) => {
      if (err) return sendJSON(res, 400, { error: 'Invalid JSON' });
      const { email, activityType, minutes, description } = data;
      if (!activityType) {
        return sendJSON(res, 400, { error: 'Missing required fields' });
      }
      const requestEmail = (email || session.email).toLowerCase();
      if (session.email.toLowerCase() !== requestEmail && !session.isAdmin) {
        return sendJSON(res, 403, { error: 'Access denied' });
      }
      const user = db.users.find(u => u.email.toLowerCase() === requestEmail);
      if (!user) {
        return sendJSON(res, 404, { error: 'User not found' });
      }
      const minutesValue = minutes ? Math.max(0, Math.min(600, Number(minutes))) : null;
      // Determine points based on activity type and minutes
      let earned = 0;
      switch (activityType) {
        case 'cardio':
          earned = minutesValue ? Math.floor(minutesValue / 30) * 10 : 10; // 10 points per 30 min
          user.cardioStreak += 1;
          user.todayCardio += minutesValue || 0;
          break;
        case 'nutrition':
          earned = 5;
          user.nutritionStreak += 1;
          break;
        case 'tobaccoFree':
          earned = 5;
          user.tobaccoStreak += 1;
          break;
        case 'screening':
          earned = 15;
          break;
        case 'education':
          earned = 5;
          break;
        case 'event':
          earned = 20;
          break;
        default:
          earned = 0;
      }
      user.points += earned;
      user.weeklyPoints += earned;
      // Record the activity
      user.activities.push({
        timestamp: new Date().toISOString(),
        type: activityType,
        minutes: minutesValue || null,
        description: description || '',
        points: earned
      });
      // Update achievements and level
      user.achievements = computeAchievements(user);
      user.level = computeLevel(user.points);
      saveDB();
      const safeUser = sanitizeUser(user);
      return sendJSON(res, 200, { user: safeUser, earned });
    });
  }

  // Endpoint: POST /api/redeem  – redeem points for leave
  if (method === 'POST' && pathname === '/api/redeem') {
    const session = requireAuth(req, res);
    if (!session) return;
    return parseJSONBody(req, (err, data) => {
      if (err) return sendJSON(res, 400, { error: 'Invalid JSON' });
      const { email, hours } = data;
      if (!hours) return sendJSON(res, 400, { error: 'Missing email or hours' });
      const requestEmail = (email || session.email).toLowerCase();
      if (session.email.toLowerCase() !== requestEmail && !session.isAdmin) {
        return sendJSON(res, 403, { error: 'Access denied' });
      }
      const user = db.users.find(u => u.email.toLowerCase() === requestEmail);
      if (!user) return sendJSON(res, 404, { error: 'User not found' });
      const hoursValue = Math.max(0, Math.min(40, Number(hours)));
      if (!hoursValue) return sendJSON(res, 400, { error: 'Invalid hours' });
      // Points cost per hour: 100 points per hour as example
      const cost = hoursValue * 100;
      if (user.points < cost) return sendJSON(res, 400, { error: 'Insufficient points' });
      user.points -= cost;
      user.leaveTime += hoursValue;
      user.redemptions = user.redemptions || [];
      user.redemptions.push({
        timestamp: new Date().toISOString(),
        hours: hoursValue,
        cost
      });
      user.achievements = computeAchievements(user);
      user.level = computeLevel(user.points);
      saveDB();
      const safeUser = sanitizeUser(user);
      return sendJSON(res, 200, { user: safeUser, redeemed: hoursValue, cost });
    });
  }

  // Endpoint: POST /api/logout – destroy session cookie
  if (method === 'POST' && pathname === '/api/logout') {
    // Find the current session token and remove it
    const token = getCookie(req, 'ahelp_session');
    if (token) {
      sessions.delete(token);
    }
    // Clear the cookie
    const isSecure = req.connection.encrypted || req.headers['x-forwarded-proto'] === 'https';
    res.setHeader('Set-Cookie', `ahelp_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${isSecure ? '; Secure' : ''}`);
    return sendJSON(res, 200, { ok: true });
  }

  // Endpoint: POST /api/password/request – initiate password reset
  if (method === 'POST' && pathname === '/api/password/request') {
    if (isRateLimited(req, 'password-request', 10)) {
      return sendJSON(res, 429, { error: 'Too many requests. Please try again later.' });
    }
    return parseJSONBody(req, (err, data) => {
      // Always respond with ok to avoid disclosing whether a user exists
      if (err) return sendJSON(res, 200, { ok: true });
      const { email, employeeNumber } = data || {};
      const user = db.users.find(u => u.email.toLowerCase() === (email || '').toLowerCase() && u.employeeNumber === String(employeeNumber));
      if (user) {
        // Generate a six‑digit code and store a hash with expiry
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const codeHash = crypto.createHash('sha256').update(code).digest('hex');
        user.passwordReset = {
          codeHash,
          expiresAt: Date.now() + (15 * 60 * 1000) // 15 minutes
        };
        saveDB();
        // In development you may log the code to the console to facilitate testing
        console.log(`Password reset code for ${user.email}: ${code}`);
      }
      return sendJSON(res, 200, { ok: true });
    });
  }

  // Endpoint: POST /api/password/reset – reset password using code
  if (method === 'POST' && pathname === '/api/password/reset') {
    if (isRateLimited(req, 'password-reset', 15)) {
      return sendJSON(res, 429, { error: 'Too many requests. Please try again later.' });
    }
    return parseJSONBody(req, (err, data) => {
      if (err) return sendJSON(res, 400, { error: 'Invalid request' });
      const { email, employeeNumber, code, newPassword } = data || {};
      if (!email || !employeeNumber || !code || !newPassword) {
        return sendJSON(res, 400, { error: 'Missing fields' });
      }
      const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.employeeNumber === String(employeeNumber));
      if (!user || !user.passwordReset) {
        return sendJSON(res, 400, { error: 'Invalid or expired reset code' });
      }
      const { expiresAt, codeHash } = user.passwordReset;
      if (Date.now() > expiresAt) {
        delete user.passwordReset;
        saveDB();
        return sendJSON(res, 400, { error: 'Invalid or expired reset code' });
      }
      const providedHash = crypto.createHash('sha256').update(code).digest('hex');
      if (providedHash !== codeHash) {
        return sendJSON(res, 400, { error: 'Invalid or expired reset code' });
      }
      // Reset password
      if (String(newPassword).length < PASSWORD_MIN_LENGTH) {
        return sendJSON(res, 400, { error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` });
      }
      const { salt: newSalt, hash: newHash, iterations } = hashPassword(newPassword);
      user.salt = newSalt;
      user.password = newHash;
      user.iterations = iterations;
      delete user.passwordReset;
      saveDB();
      return sendJSON(res, 200, { ok: true });
    });
  }

  // Admin endpoints: metrics and reports
  if (method === 'GET' && pathname === '/api/admin/metrics') {
    const session = requireAdmin(req, res);
    if (!session) return;
    const filteredUsers = filterUsersForAgency(db.users, session.adminAgency);
    const totalUsers = filteredUsers.length;
    const avgPoints = totalUsers ? Math.round(filteredUsers.reduce((sum, u) => sum + (u.points || 0), 0) / totalUsers) : 0;
    const avgWeekly = totalUsers ? Math.round(filteredUsers.reduce((sum, u) => sum + (u.weeklyPoints || 0), 0) / totalUsers) : 0;
    const assessmentsCompleted = filteredUsers.filter(u => u.assessmentDate).length;
    return sendJSON(res, 200, {
      totalUsers,
      avgPoints,
      avgWeekly,
      assessmentsCompleted
    });
  }

  if (method === 'GET' && pathname === '/api/admin/users') {
    const session = requireAdmin(req, res);
    if (!session) return;
    const filteredUsers = filterUsersForAgency(db.users, session.adminAgency).map(user => sanitizeUser(user));
    return sendJSON(res, 200, { users: filteredUsers });
  }

  if (method === 'GET' && pathname === '/api/admin/redemptions') {
    const session = requireAdmin(req, res);
    if (!session) return;
    const filteredUsers = filterUsersForAgency(db.users, session.adminAgency);
    const redemptions = filteredUsers.flatMap(user => {
      return (user.redemptions || []).map(redemption => ({
        user: user.email,
        name: user.name,
        agency: user.agency || '',
        hours: redemption.hours,
        cost: redemption.cost,
        timestamp: redemption.timestamp
      }));
    });
    return sendJSON(res, 200, { redemptions });
  }

  if (method === 'GET' && pathname === '/api/admin/reports/users') {
    const session = requireAdmin(req, res);
    if (!session) return;
    const filteredUsers = filterUsersForAgency(db.users, session.adminAgency).map(user => ({
      name: user.name,
      email: user.email,
      agency: user.agency || '',
      points: user.points || 0,
      weeklyPoints: user.weeklyPoints || 0,
      assessmentDate: user.assessmentDate || ''
    }));
    const csv = toCsv(filteredUsers, ['name', 'email', 'agency', 'points', 'weeklyPoints', 'assessmentDate']);
    applySecurityHeaders(res);
    res.writeHead(200, {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="ahelp_user_report_${new Date().toISOString().slice(0, 10)}.csv"`
    });
    return res.end(csv);
  }

  if (method === 'GET' && pathname === '/api/admin/reports/redemptions') {
    const session = requireAdmin(req, res);
    if (!session) return;
    const filteredUsers = filterUsersForAgency(db.users, session.adminAgency);
    const redemptions = filteredUsers.flatMap(user => (user.redemptions || []).map(redemption => ({
      user: user.email,
      name: user.name,
      agency: user.agency || '',
      hours: redemption.hours,
      cost: redemption.cost,
      timestamp: redemption.timestamp
    })));
    const csv = toCsv(redemptions, ['user', 'name', 'agency', 'hours', 'cost', 'timestamp']);
    applySecurityHeaders(res);
    res.writeHead(200, {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="ahelp_redemptions_${new Date().toISOString().slice(0, 10)}.csv"`
    });
    return res.end(csv);
  }

  // Serve static frontend files and protect authenticated routes
  if (method === 'GET') {
    // Determine the requested path relative to the public directory. Default to login page.
    let reqPath = pathname === '/' ? '/login.html' : pathname;
    // Normalize path to prevent directory traversal
    try {
      reqPath = decodeURIComponent(reqPath);
    } catch (e) {
      reqPath = '/login.html';
    }
    const PUBLIC_DIR = path.join(__dirname, '..');
    const filePath = path.join(PUBLIC_DIR, reqPath);
    // Only serve files within PUBLIC_DIR
    if (filePath.startsWith(PUBLIC_DIR) && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      // Define protected user pages and admin pages
      const PROTECTED_PAGES = new Set([
        '/dashboard.html', '/profile.html', '/progress.html', '/redeem.html', '/settings.html', '/community.html', '/challenges.html', '/health-assessment.html'
      ]);
      const ADMIN_PAGES = new Set([
        '/admin-dashboard.html'
      ]);
      // Check if route is protected; require session
      if (PROTECTED_PAGES.has(reqPath)) {
        const session = requireAuth(req, res);
        if (!session) return;
      }
      // Check if route is admin only
      if (ADMIN_PAGES.has(reqPath)) {
        const session = requireAdmin(req, res);
        if (!session) return;
      }
      // Serve the file
      const ext = path.extname(filePath).toLowerCase();
      const mimeMap = {
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'text/javascript',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.svg': 'image/svg+xml'
      };
      applySecurityHeaders(res);
      res.writeHead(200, { 'Content-Type': mimeMap[ext] || 'application/octet-stream' });
      fs.createReadStream(filePath).pipe(res);
      return;
    }
  }

  // Fallback: Not found
  sendJSON(res, 404, { error: 'Not found' });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`AHELP backend server listening on port ${PORT}`);
});
