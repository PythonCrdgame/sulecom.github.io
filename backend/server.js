const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;
const frontendDir = path.join(__dirname, '..', 'frontend');
const dataDir = process.env.DATA_DIR || __dirname;
const dbPath = process.env.DATABASE_PATH || path.join(dataDir, 'sulecom.db');
const sessionDir = process.env.SESSION_DIR || dataDir;
const production = process.env.NODE_ENV === 'production';

if (production && !process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET must be set in production.');
}
if (process.env.TRUST_PROXY === 'true' || process.env.RENDER) {
  app.set('trust proxy', 1);
}
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
fs.mkdirSync(sessionDir, { recursive: true });
const db = new sqlite3.Database(dbPath);

const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) {
    if (err) return reject(err);
    resolve({ lastID: this.lastID, changes: this.changes });
  });
});
const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
});
const all = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
});
const sanitizeUser = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  accountType: user.account_type,
  createdAt: user.created_at,
});

const seedProducts = async () => {
  const existing = await get('SELECT COUNT(*) AS count FROM products');
  if (Number(existing.count) > 0) return;
  const samples = [
    ['Wireless Headphones', 79.99, 'Electronics', 'Immersive sound and all-day comfort for work and travel.', 'https://images.unsplash.com/photo-1546435770-a3e426bf472b?auto=format&fit=crop&w=900&q=80'],
    ['Smart Watch', 129, 'Electronics', 'Fitness tracking, notifications, and sleek design in one.', 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=900&q=80'],
    ['Running Sneakers', 94.5, 'Fashion', 'Lightweight support for your commute and everyday workouts.', 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=900&q=80'],
    ['Desk Lamp', 39.99, 'Home', 'Warm lighting with a clean design for any workspace.', 'https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?auto=format&fit=crop&w=900&q=80'],
  ];
  for (const product of samples) {
    await run('INSERT INTO products (name, price, category, description, image, seller_id) VALUES (?, ?, ?, ?, ?, NULL)', product);
  }
};

const initDb = async () => {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    account_type TEXT NOT NULL DEFAULT 'buyer-seller',
    created_at TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    image TEXT,
    seller_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    items TEXT NOT NULL,
    total REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);

  // Remove the old publicly documented demo login from both fresh and existing databases.
  await run('DELETE FROM users WHERE email = ?', ['seller@sulecom.local']);
  await seedProducts();
};

app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  name: 'sulecom.sid',
  secret: process.env.SESSION_SECRET || 'development-only-change-before-deploy',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: sessionDir, concurrent没: true }),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: production,
    maxAge: 1000 * 60 * 60 * 8,
  },
}));
app.use(express.static(frontendDir));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { message: 'Too many authentication attempts. Please try again later.' },
});
const requireUser = (req, res, next) => {
  if (!req.session?.user) return res.status(401).json({ message: 'Please sign in to continue.' });
  return next();
};
const validEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
const establishSession = (req, user) => new Promise((resolve, reject) => {
  req.session.regenerate((error) => {
    if (error) return reject(error);
    req.session.user = user;
    req.session.save((saveError) => saveError ? reject(saveError) : resolve());
  });
});

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));
app.get('/api/session', async (req, res) => {
  if (!req.session?.user) return res.status(401).json({ authenticated: false, message: 'Not authenticated.' });
  try {
    const user = await get('SELECT id, name, email, account_type, created_at FROM users WHERE id = ?', [req.session.user.id]);
    if (!user) {
      return req.session.destroy(() => res.status(401).json({ authenticated: false, message: 'Not authenticated.' }));
    }
    req.session.user = sanitizeUser(user);
    return res.json({ authenticated: true, user: req.session.user });
  } catch (error) {
    console.error('Session lookup failed:', error);
    return res.status(500).json({ message: 'Could not load session.' });
  }
});
app.post('/api/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) return res.status(500).json({ message: 'Unable to log out right now.' });
    res.clearCookie('sulecom.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: production,
      path: '/',
    });
    return res.json({ message: 'Logged out successfully.' });
  });
});

app.post('/api/signup', authLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    if (typeof body.name !== 'string' || typeof body.email !== 'string' || typeof body.password !== 'string') {
      return res.status(400).json({ message: 'Name, email, and password are required.' });
    }
    const name = body.name.trim();
    const email = body.email.trim().toLowerCase();
    const password = body.password;
    if (!name || name.length > 100) return res.status(400).json({ message: 'Name must be between 1 and 100 characters.' });
    if (!validEmail(email)) return res.status(400).json({ message: 'Enter a valid email address.' });
    if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ message: 'Password must be at least 12 characters and no more than 72 bytes.' });
    }
    if (body.accountType !== undefined && !['buyer', 'buyer-seller'].includes(body.accountType)) {
      return res.status(400).json({ message: 'Choose a valid account type.' });
    }
    const accountType = body.accountType || 'buyer-seller';
    const passwordHash = await bcrypt.hash(password, 12);
    const createdAt = new Date().toISOString();
    let result;
    try {
      result = await run('INSERT INTO users (name, email, password, account_type, created_at) VALUES (?, ?, ?, ?, ?)',
        [name, email, passwordHash, accountType, createdAt]);
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ message: 'An account with this email already exists.' });
      throw error;
    }
    const user = { id: result.lastID, name, email, account_type: accountType, created_at: createdAt };
    const safeUser = sanitizeUser(user);
    await establishSession(req, safeUser);
    return res.status(201).json({ message: 'Account created successfully.', user: safeUser });
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ message: 'Could not create account.' });
  }
});

app.post('/api/signin', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const normalizedEmail = email.trim().toLowerCase();
    if (!validEmail(normalizedEmail) || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    const user = await get('SELECT id, name, email, password, account_type, created_at FROM users WHERE email = ?', [normalizedEmail]);
    const isMatch = user ? await bcrypt.compare(password, user.password) : false;
    if (!isMatch) return res.status(401).json({ message: 'Invalid email or password.' });
    const safeUser = sanitizeUser(user);
    await establishSession(req, safeUser);
    return res.json({ message: 'Sign in successful.', user: safeUser });
  } catch (error) {
    console.error('Signin error:', error);
    return res.status(500).json({ message: 'Could not sign in.' });
  }
});

// Deliberately do not expose a public user-directory endpoint.
app.get('/api/products', async (_req, res) => {
  try {
    const rows = await all(`SELECT id, name, price, category, description, image, seller_id AS sellerId
      FROM products ORDER BY id DESC`);
    return res.json(rows);
  } catch (error) {
    console.error('Products error:', error);
    return res.status(500).json({ message: 'Could not load products.' });
  }
});
app.post('/api/products', requireUser, async (req, res) => {
  try {
    const { name, price, category, description, image } = req.body || {};
    if (typeof name !== 'string' || !name.trim() || name.trim().length > 120 ||
        typeof category !== 'string' || !category.trim() || category.trim().length > 80 ||
        typeof description !== 'string' || !description.trim() || description.trim().length > 2000 ||
        !Number.isFinite(Number(price)) || Number(price) <= 0) {
      return res.status(400).json({ message: 'Enter valid product details and a positive price.' });
    }
    const user = await get('SELECT account_type FROM users WHERE id = ?', [req.session.user.id]);
    if (!user || user.account_type !== 'buyer-seller') return res.status(403).json({ message: 'Only buyer-seller accounts can list products.' });
    let imageUrl = null;
    if (image) {
      try {
        const parsed = new URL(image);
        if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Invalid protocol');
        imageUrl = parsed.href;
      } catch (_error) {
        return res.status(400).json({ message: 'Image must be a valid HTTP or HTTPS URL.' });
      }
    }
    const result = await run(`INSERT INTO products (name, price, category, description, image, seller_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`, [name.trim(), Number(price), category.trim(), description.trim(), imageUrl,
      req.session.user.id, new Date().toISOString()]);
    return res.status(201).json({ message: 'Product created successfully.', product: { id: result.lastID } });
  } catch (error) {
    console.error('Create product error:', error);
    return res.status(500).json({ message: 'Could not create product.' });
  }
});
app.post('/api/orders', requireUser, async (req, res) => {
  try {
    const { items, total } = req.body || {};
    if (!Array.isArray(items) || items.length === 0 || items.length > 50 ||
        !Number.isFinite(Number(total)) || Number(total) < 0 || JSON.stringify(items).length > 10000) {
      return res.status(400).json({ message: 'A valid cart and total are required.' });
    }
    const result = await run('INSERT INTO orders (user_id, items, total, created_at) VALUES (?, ?, ?, ?)',
      [req.session.user.id, JSON.stringify(items), Number(total), new Date().toISOString()]);
    return res.status(201).json({ message: 'Order placed successfully.', orderId: result.lastID });
  } catch (error) {
    console.error('Create order error:', error);
    return res.status(500).json({ message: 'Could not place order.' });
  }
});

app.get('/signup', (_req, res) => res.sendFile(path.join(frontendDir, 'signup.html')));
app.get('/signin', (_req, res) => res.sendFile(path.join(frontendDir, 'signin.html')));
app.get('/home', (_req, res) => res.sendFile(path.join(frontendDir, 'home.html')));
app.get('/seller', (_req, res) => res.sendFile(path.join(frontendDir, 'seller.html')));
app.get('/cart', (_req, res) => res.sendFile(path.join(frontendDir, 'cart.html')));
app.get('/checkout', (_req, res) => res.sendFile(path.join(frontendDir, 'checkout.html')));
app.get('/', (_req, res) => res.sendFile(path.join(frontendDir, 'index.html')));

initDb().then(() => {
  app.listen(port, () => console.log(`SulE-Com backend is running on port ${port}`));
}).catch((error) => {
  console.error('Database setup failed:', error);
  process.exit(1);
});

const shutdown = () => db.close(() => process.exit(0));
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
