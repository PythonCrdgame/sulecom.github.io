const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
const port = 3000;
const frontendDir = path.join(__dirname, '..', 'frontend');
const dbPath = path.join(__dirname, 'sulecom.db');
const db = new sqlite3.Database(dbPath);

const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) {
    if (err) return reject(err);
    resolve({ lastID: this.lastID, changes: this.changes });
  });
});

const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => {
    if (err) return reject(err);
    resolve(row);
  });
});

const all = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => {
    if (err) return reject(err);
    resolve(rows);
  });
});

const seedProducts = async () => {
  const existing = await all('SELECT COUNT(*) AS count FROM products');
  const count = Number(existing[0]?.count || 0);

  if (count > 0) return;

  await run(
    `INSERT INTO products (name, price, category, description, image, seller_id) VALUES
      (?, ?, ?, ?, ?, ?),
      (?, ?, ?, ?, ?, ?),
      (?, ?, ?, ?, ?, ?),
      (?, ?, ?, ?, ?, ?)`,
    [
      'Wireless Headphones', 79.99, 'Electronics', 'Immersive sound and all-day comfort for work and travel.', 'https://images.unsplash.com/photo-1546435770-a3e426bf472b?auto=format&fit=crop&w=900&q=80', 1,
      'Smart Watch', 129.0, 'Electronics', 'Fitness tracking, notifications, and sleek design in one.', 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=900&q=80', 1,
      'Running Sneakers', 94.5, 'Fashion', 'Lightweight support for your commute and everyday workouts.', 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=900&q=80', 1,
      'Desk Lamp', 39.99, 'Home', 'Warm lighting with a clean design for any workspace.', 'https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?auto=format&fit=crop&w=900&q=80', 1
    ]
  );
};

const initDb = async () => {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      account_type TEXT NOT NULL DEFAULT 'buyer-seller',
      created_at TEXT NOT NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      image TEXT,
      seller_id INTEGER DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      items TEXT NOT NULL,
      total REAL NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const defaultSeller = await get(`SELECT id FROM users WHERE email = ?`, ['seller@sulecom.local']);
  if (!defaultSeller) {
    const hash = await bcrypt.hash('seller123', 10);
    await run(
      `INSERT INTO users (name, email, password, account_type, created_at) VALUES (?, ?, ?, ?, ?)`,
      ['SulE-Com Seller', 'seller@sulecom.local', hash, 'buyer-seller', new Date().toISOString()]
    );
  }

  await seedProducts();
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(frontendDir));

app.get('/api/health', async (_req, res) => {
  const users = await all('SELECT id FROM users');
  res.json({ status: 'ok', users: users.length });
});

app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, accountType } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email, and password are required.' });
    }

    const normalizedName = String(name).trim();
    const normalizedEmail = String(email).trim().toLowerCase();
    const cleanedPassword = String(password).trim();
    const normalizedAccountType = accountType === 'buyer' ? 'buyer' : 'buyer-seller';

    if (!normalizedName || !normalizedEmail || !cleanedPassword) {
      return res.status(400).json({ message: 'Please complete all required fields.' });
    }

    const existing = await get('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existing) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(cleanedPassword, 10);
    const result = await run(
      `INSERT INTO users (name, email, password, account_type, created_at) VALUES (?, ?, ?, ?, ?)`,
      [normalizedName, normalizedEmail, passwordHash, normalizedAccountType, new Date().toISOString()]
    );

    const user = {
      id: result.lastID,
      name: normalizedName,
      email: normalizedEmail,
      accountType: normalizedAccountType,
      createdAt: new Date().toISOString(),
    };

    return res.status(201).json({ message: 'Account created successfully.', user });
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ message: 'Could not create account.' });
  }
});

app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = await get('SELECT * FROM users WHERE email = ?', [normalizedEmail]);

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(String(password), user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      accountType: user.account_type,
      createdAt: user.created_at,
    };

    return res.json({ message: 'Sign in successful.', user: safeUser });
  } catch (error) {
    console.error('Signin error:', error);
    return res.status(500).json({ message: 'Could not sign in.' });
  }
});

app.get('/api/users', async (_req, res) => {
  try {
    const rows = await all('SELECT id, name, email, account_type AS accountType, created_at AS createdAt FROM users ORDER BY id DESC');
    return res.json(rows);
  } catch (error) {
    console.error('Users error:', error);
    return res.status(500).json({ message: 'Could not load users.' });
  }
});

app.get('/api/products', async (_req, res) => {
  try {
    const rows = await all(`
      SELECT id, name, price, category, description, image, seller_id AS sellerId
      FROM products
      ORDER BY id DESC
    `);
    return res.json(rows);
  } catch (error) {
    console.error('Products error:', error);
    return res.status(500).json({ message: 'Could not load products.' });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const { name, price, category, description, image } = req.body || {};

    if (!name || !price || !category || !description) {
      return res.status(400).json({ message: 'Product name, price, category, and description are required.' });
    }

    const result = await run(
      `INSERT INTO products (name, price, category, description, image, seller_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        String(name).trim(),
        Number(price),
        String(category).trim(),
        String(description).trim(),
        String(image || 'https://images.unsplash.com/photo-1524758631624-e2822e304c36?auto=format&fit=crop&w=900&q=80'),
        1,
        new Date().toISOString(),
      ]
    );

    return res.status(201).json({ message: 'Product created successfully.', product: { id: result.lastID } });
  } catch (error) {
    console.error('Create product error:', error);
    return res.status(500).json({ message: 'Could not create product.' });
  }
});

app.post('/api/orders', async (req, res) => {
  try {
    const { userId, items, total } = req.body || {};

    if (!userId || !Array.isArray(items) || !items.length) {
      return res.status(400).json({ message: 'A valid user and cart items are required.' });
    }

    const result = await run(
      `INSERT INTO orders (user_id, items, total, created_at) VALUES (?, ?, ?, ?)`,
      [Number(userId), JSON.stringify(items), Number(total || 0), new Date().toISOString()]
    );

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
app.get('/home.html', (_req, res) => res.sendFile(path.join(frontendDir, 'home.html')));
app.get('/seller.html', (_req, res) => res.sendFile(path.join(frontendDir, 'seller.html')));
app.get('/cart.html', (_req, res) => res.sendFile(path.join(frontendDir, 'cart.html')));
app.get('/checkout.html', (_req, res) => res.sendFile(path.join(frontendDir, 'checkout.html')));
app.get('/', (_req, res) => res.sendFile(path.join(frontendDir, 'index.html')));

initDb()
  .then(() => {
    app.listen(port, () => {
      console.log(`SulE-Com backend is running on http://localhost:${port}`);
    });
  })
  .catch((error) => {
    console.error('Database setup failed:', error);
    process.exit(1);
  });

process.on('SIGINT', () => {
  db.close();
  process.exit(0);
});
