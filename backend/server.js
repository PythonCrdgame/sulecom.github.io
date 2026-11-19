const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const port = Number(process.env.PORT) || 3000;
const frontendDir = path.join(__dirname, '..', 'frontend');

// MOCKED — in-memory replacement for native sqlite3, data lost on container sleep
const memoryDb = {
  users: [],
  products: [],
  orders: [],
  nextId: {
    users: 1,
    products: 1,
    orders: 1,
  },
};

const sanitizeUser = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  accountType: user.account_type || user.accountType,
  createdAt: user.created_at || user.createdAt,
});

const seedProducts = async () => {
  if (memoryDb.products.length > 0) return;

  const initialProducts = [
    {
      name: 'Wireless Headphones',
      price: 79.99,
      category: 'Electronics',
      description: 'Immersive sound and all-day comfort for work and travel.',
      image: 'https://images.unsplash.com/photo-1546435770-a3e426bf472b?auto=format&fit=crop&w=900&q=80',
      seller_id: 1,
    },
    {
      name: 'Smart Watch',
      price: 129.0,
      category: 'Electronics',
      description: 'Fitness tracking, notifications, and sleek design in one.',
      image: 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=900&q=80',
      seller_id: 1,
    },
    {
      name: 'Running Sneakers',
      price: 94.5,
      category: 'Fashion',
      description: 'Lightweight support for your commute and everyday workouts.',
      image: 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=900&q=80',
      seller_id: 1,
    },
    {
      name: 'Desk Lamp',
      price: 39.99,
      category: 'Home',
      description: 'Warm lighting with a clean design for any workspace.',
      image: 'https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?auto=format&fit=crop&w=900&q=80',
      seller_id: 1,
    },
  ];

  for (const item of initialProducts) {
    memoryDb.products.push({
      id: memoryDb.nextId.products++,
      ...item,
      created_at: new Date().toISOString(),
    });
  }
};

const initDb = async () => {
  const defaultSeller = memoryDb.users.find((u) => u.email === 'seller@sulecom.local');
  if (!defaultSeller) {
    const hash = await bcrypt.hash('seller123', 10);
    memoryDb.users.push({
      id: memoryDb.nextId.users++,
      name: 'SulE-Com Seller',
      email: 'seller@sulecom.local',
      password: hash,
      account_type: 'buyer-seller',
      created_at: new Date().toISOString(),
    });
  }

  await seedProducts();
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    name: 'sulecom.sid',
    secret: process.env.SESSION_SECRET || 'sulecom-local-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);
app.use(express.static(frontendDir));

app.get('/api/health', async (_req, res) => {
  res.json({ status: 'ok', users: memoryDb.users.length });
});

app.get('/api/session', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ authenticated: false, message: 'Not authenticated.' });
  }

  return res.json({ authenticated: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ message: 'Unable to log out right now.' });
    }

    return res.json({ message: 'Logged out successfully.' });
  });
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

    const existing = memoryDb.users.find((u) => u.email === normalizedEmail);
    if (existing) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(cleanedPassword, 10);
    const createdAt = new Date().toISOString();
    const newUser = {
      id: memoryDb.nextId.users++,
      name: normalizedName,
      email: normalizedEmail,
      password: passwordHash,
      account_type: normalizedAccountType,
      created_at: createdAt,
    };
    memoryDb.users.push(newUser);

    const user = sanitizeUser(newUser);
    req.session.user = user;

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
    const user = memoryDb.users.find((u) => u.email === normalizedEmail);

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(String(password), user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const safeUser = sanitizeUser(user);
    req.session.user = safeUser;

    return res.json({ message: 'Sign in successful.', user: safeUser });
  } catch (error) {
    console.error('Signin error:', error);
    return res.status(500).json({ message: 'Could not sign in.' });
  }
});

app.get('/api/users', async (_req, res) => {
  try {
    const rows = [...memoryDb.users]
      .sort((a, b) => b.id - a.id)
      .map((u) => ({
        id: u.id,
        name: u.name,
        email: u.email,
        accountType: u.account_type,
        createdAt: u.created_at,
      }));
    return res.json(rows);
  } catch (error) {
    console.error('Users error:', error);
    return res.status(500).json({ message: 'Could not load users.' });
  }
});

app.get('/api/products', async (_req, res) => {
  try {
    const rows = [...memoryDb.products]
      .sort((a, b) => b.id - a.id)
      .map((p) => ({
        id: p.id,
        name: p.name,
        price: p.price,
        category: p.category,
        description: p.description,
        image: p.image,
        sellerId: p.seller_id,
      }));
    return res.json(rows);
  } catch (error) {
    console.error('Products error:', error);
    return res.status(500).json({ message: 'Could not load products.' });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.status(401).json({ message: 'Please sign in to publish products.' });
    }

    const { name, price, category, description, image } = req.body || {};

    if (!name || !price || !category || !description) {
      return res.status(400).json({ message: 'Product name, price, category, and description are required.' });
    }

    const userRecord = memoryDb.users.find((u) => u.id === Number(req.session.user.id));
    if (!userRecord || userRecord.account_type !== 'buyer-seller') {
      return res.status(403).json({ message: 'Only buyer-seller accounts can list products.' });
    }

    const newProduct = {
      id: memoryDb.nextId.products++,
      name: String(name).trim(),
      price: Number(price),
      category: String(category).trim(),
      description: String(description).trim(),
      image: String(image || 'https://images.unsplash.com/photo-1524758631624-e2822e304c36?auto=format&fit=crop&w=900&q=80'),
      seller_id: Number(req.session.user.id),
      created_at: new Date().toISOString(),
    };
    memoryDb.products.push(newProduct);

    return res.status(201).json({ message: 'Product created successfully.', product: { id: newProduct.id } });
  } catch (error) {
    console.error('Create product error:', error);
    return res.status(500).json({ message: 'Could not create product.' });
  }
});

app.post('/api/orders', async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.status(401).json({ message: 'Please sign in to place an order.' });
    }

    const { items, total } = req.body || {};

    if (!Array.isArray(items) || !items.length) {
      return res.status(400).json({ message: 'A valid cart is required.' });
    }

    const newOrder = {
      id: memoryDb.nextId.orders++,
      user_id: Number(req.session.user.id),
      items: JSON.stringify(items),
      total: Number(total || 0),
      created_at: new Date().toISOString(),
    };
    memoryDb.orders.push(newOrder);

    return res.status(201).json({ message: 'Order placed successfully.', orderId: newOrder.id });
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
    app.listen(port, '0.0.0.0', () => {
      console.log(`SulE-Com backend is running on http://0.0.0.0:${port}`);
    });
  })
  .catch((error) => {
    console.error('Database setup failed:', error);
    process.exit(1);
  });

process.on('SIGINT', () => {
  process.exit(0);
});
