const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const frontendDir = path.join(__dirname, '..', 'frontend');

const dataDir = process.env.VERCEL ? '/tmp' : __dirname;
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = process.env.DATABASE_PATH || path.join(dataDir, 'sulecom.db');
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
  accountType: user.account_type || user.accountType,
  createdAt: user.created_at || user.createdAt,
});

const ensureProductColumns = async () => {
  const columns = await all('PRAGMA table_info(products)');
  const existing = new Set(columns.map((column) => column.name));
  if (!existing.has('stock')) await run('ALTER TABLE products ADD COLUMN stock INTEGER NOT NULL DEFAULT 1');
  if (!existing.has('max_quantity')) await run('ALTER TABLE products ADD COLUMN max_quantity INTEGER NOT NULL DEFAULT 1');
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
    seller_id INTEGER DEFAULT 1,
    stock INTEGER NOT NULL DEFAULT 1,
    max_quantity INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    items TEXT NOT NULL,
    total REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await ensureProductColumns();

  const count = await get('SELECT COUNT(*) AS count FROM products');
  if (Number(count.count) === 0) {
    await run(`INSERT INTO products (name, price, category, description, image, seller_id, stock, max_quantity) VALUES
      (?, ?, ?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?, ?, ?)`,
      ['Wireless Headphones',79.99,'Electronics','Immersive sound and all-day comfort.','https://images.unsplash.com/photo-1546435770-a3e426bf472b?auto=format&fit=crop&w=900&q=80',1,5,2,
       'Smart Watch',129,'Electronics','Fitness tracking and notifications.','https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=900&q=80',1,10,2,
       'Running Sneakers',94.5,'Fashion','Lightweight everyday sneakers.','https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=900&q=80',1,8,3,
       'Desk Lamp',39.99,'Home','Warm lighting for any workspace.','https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?auto=format&fit=crop&w=900&q=80',1,12,4]);
  }
};

app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  name: 'sulecom.sid',
  secret: process.env.SESSION_SECRET || 'local-development-secret-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: Boolean(process.env.VERCEL), maxAge: 1000 * 60 * 60 * 8 },
}));

app.get('/api/health', async (_req, res) => {
  const users = await all('SELECT id FROM users');
  res.json({ status: 'ok', users: users.length });
});

app.get('/api/session', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ authenticated: false, message: 'Not authenticated.' });
  res.json({ authenticated: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) return res.status(500).json({ message: 'Unable to log out right now.' });
    res.clearCookie('sulecom.sid', { path: '/', httpOnly: true, sameSite: 'lax', secure: Boolean(process.env.VERCEL) });
    res.json({ message: 'Logged out successfully.' });
  });
});

app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, accountType } = req.body || {};
    if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Name, email, and password are required.' });
    }
    const normalizedName = name.trim();
    const normalizedEmail = email.trim().toLowerCase();
    const cleanedPassword = password;
    const normalizedAccountType = accountType === 'buyer' ? 'buyer' : 'buyer-seller';

    if (!normalizedName || normalizedName.length > 100) return res.status(400).json({ message: 'Enter a valid full name.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) return res.status(400).json({ message: 'Enter a valid email address.' });
    if (cleanedPassword.length < 12) return res.status(400).json({ message: 'Password must be at least 12 characters.' });

    const existing = await get('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existing) return res.status(409).json({ message: 'An account with this email already exists.' });

    const hash = await bcrypt.hash(cleanedPassword, 12);
    const createdAt = new Date().toISOString();
    const result = await run('INSERT INTO users (name, email, password, account_type, created_at) VALUES (?, ?, ?, ?, ?)',
      [normalizedName, normalizedEmail, hash, normalizedAccountType, createdAt]);
    const user = sanitizeUser({ id: result.lastID, name: normalizedName, email: normalizedEmail, account_type: normalizedAccountType, created_at: createdAt });

    req.session.regenerate((error) => {
      if (error) return res.status(500).json({ message: 'Could not create your session.' });
      req.session.user = user;
      req.session.save((saveError) => {
        if (saveError) return res.status(500).json({ message: 'Could not create your session.' });
        res.status(201).json({ message: 'Account created successfully.', user });
      });
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Could not create account.' });
  }
});

app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') return res.status(400).json({ message: 'Email and password are required.' });
    const normalizedEmail = email.trim().toLowerCase();
    const user = await get('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: 'Invalid email or password.' });

    const safeUser = sanitizeUser(user);
    req.session.regenerate((error) => {
      if (error) return res.status(500).json({ message: 'Could not create your session.' });
      req.session.user = safeUser;
      req.session.save((saveError) => {
        if (saveError) return res.status(500).json({ message: 'Could not create your session.' });
        res.json({ message: 'Sign in successful.', user: safeUser });
      });
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ message: 'Could not sign in.' });
  }
});

app.get('/api/products', async (_req, res) => {
  try {
    const rows = await all('SELECT id, name, price, category, description, image, seller_id AS sellerId, stock, max_quantity AS maxQuantity FROM products ORDER BY id DESC');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Could not load products.' });
  }
});

app.post('/api/products', async (req, res) => {
  if (!req.session?.user) return res.status(401).json({ message: 'Please sign in to publish products.' });
  try {
    const { name, price, category, description, image, stock, maxQuantity } = req.body || {};
    const parsedPrice = Number(price), parsedStock = Number(stock), parsedMax = Number(maxQuantity);
    if (!name || !category || !description || !Number.isFinite(parsedPrice) || parsedPrice <= 0) return res.status(400).json({ message: 'Enter valid product details and a positive price.' });
    if (!Number.isInteger(parsedStock) || parsedStock < 1 || !Number.isInteger(parsedMax) || parsedMax < 1) return res.status(400).json({ message: 'Stock and max quantity must be whole numbers greater than zero.' });

    const userRecord = await get('SELECT account_type FROM users WHERE id = ?', [req.session.user.id]);
    if (!userRecord || userRecord.account_type !== 'buyer-seller') return res.status(403).json({ message: 'Only buyer-seller accounts can list products.' });

    const result = await run('INSERT INTO products (name, price, category, description, image, seller_id, stock, max_quantity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [String(name).trim(), parsedPrice, String(category).trim(), String(description).trim(), String(image || 'https://images.unsplash.com/photo-1524758631624-e2822e304c36'), req.session.user.id, parsedStock, parsedMax, new Date().toISOString()]);
    res.status(201).json({ message: 'Product created successfully.', product: { id: result.lastID } });
  } catch (error) {
    res.status(500).json({ message: 'Could not create product.' });
  }
});

app.post('/api/orders', async (req, res) => {
  if (!req.session?.user) return res.status(401).json({ message: 'Please sign in to place an order.' });
  try {
    const { items, total } = req.body || {};
    if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ message: 'A valid cart is required.' });

    for (const item of items) {
      const quantity = Number(item.quantity || 1);
      const product = await get('SELECT stock, max_quantity AS maxQuantity FROM products WHERE id = ?', [Number(item.productId)]);
      if (!product) return res.status(400).json({ message: 'One or more products are no longer available.' });
      if (quantity < 1 || quantity > product.stock || quantity > product.maxQuantity) return res.status(400).json({ message: 'One or more quantities exceed the seller’s limit.' });
    }

    const result = await run('INSERT INTO orders (user_id, items, total, created_at) VALUES (?, ?, ?, ?)',
      [req.session.user.id, JSON.stringify(items), Number(total || 0), new Date().toISOString()]);
    res.status(201).json({ message: 'Order placed successfully.', orderId: result.lastID });
  } catch (error) {
    res.status(500).json({ message: 'Could not place order.' });
  }
});

app.use(express.static(frontendDir));
app.get('/signup', (_req, res) => res.sendFile(path.join(frontendDir, 'signup.html')));
app.get('/signin', (_req, res) => res.sendFile(path.join(frontendDir, 'signin.html')));
app.get('/home', (_req, res) => res.sendFile(path.join(frontendDir, 'home.html')));
app.get('/seller', (_req, res) => res.sendFile(path.join(frontendDir, 'seller.html')));
app.get('/checkout', (_req, res) => res.sendFile(path.join(frontendDir, 'checkout.html')));

let initialized;
const ensureDb = () => {
  if (!initialized) initialized = initDb();
  return initialized;
};

module.exports = async (req, res) => {
  await ensureDb();
  return app(req, res);
};

if (require.main === module) {
  ensureDb().then(() => {
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`SulE-Com backend running on http://localhost:${port}`));
  }).catch((error) => { console.error(error); process.exit(1); });
}
