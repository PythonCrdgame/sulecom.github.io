const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

const app = express();
const port = 3000;
const frontendDir = path.join(__dirname, "..", "frontend");
const usersFile = path.join(__dirname, "users.json");

const ensureUsersFile = () => {
  if (!fs.existsSync(usersFile)) {
    fs.writeFileSync(usersFile, JSON.stringify([], null, 2));
  }
};

const readUsers = () => {
  ensureUsersFile();
  try {
    const data = fs.readFileSync(usersFile, "utf8");
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    return [];
  }
};

const writeUsers = (users) => {
  ensureUsersFile();
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
};

let users = readUsers();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(frontendDir));

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", users: users.length });
});

app.post("/api/signup", async (req, res) => {
  const { name, email, password, accountType } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Name, email, and password are required." });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const normalizedName = String(name).trim();
  const normalizedAccountType = accountType === "buyer" ? "buyer" : "buyer-seller";

  if (!normalizedEmail || !normalizedName || !String(password).trim()) {
    return res.status(400).json({ message: "Please complete all required fields." });
  }

  users = readUsers();
  const existingUser = users.find((user) => user.email.toLowerCase() === normalizedEmail);
  if (existingUser) {
    return res.status(409).json({ message: "An account with this email already exists." });
  }

  const passwordHash = await bcrypt.hash(String(password), 10);

  const newUser = {
    id: Date.now(),
    name: normalizedName,
    email: normalizedEmail,
    password: passwordHash,
    accountType: normalizedAccountType,
    createdAt: new Date().toISOString(),
  };

  users.push(newUser);
  writeUsers(users);

  const { password: _password, ...userWithoutPassword } = newUser;
  return res.status(201).json({
    message: "Account created successfully.",
    user: userWithoutPassword,
  });
});

app.post("/api/signin", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  users = readUsers();
  const foundUser = users.find((user) => user.email.toLowerCase() === String(email).trim().toLowerCase());

  if (!foundUser) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  const isMatch = await bcrypt.compare(String(password), foundUser.password);
  if (!isMatch) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  const { password: _password, ...safeUser } = foundUser;
  return res.json({
    message: "Sign in successful.",
    user: safeUser,
  });
});

app.get("/api/users", (req, res) => {
  users = readUsers();
  const safeUsers = users.map(({ password, ...user }) => user);
  res.json(safeUsers);
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(frontendDir, "signup.html"));
});

app.get("/signin", (req, res) => {
  res.sendFile(path.join(frontendDir, "signin.html"));
});

app.get("/home", (req, res) => {
  res.sendFile(path.join(frontendDir, "home.html"));
});

app.get("/home.html", (req, res) => {
  res.sendFile(path.join(frontendDir, "home.html"));
});

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendDir, "index.html"));
});

app.listen(port, () => {
  console.log(`SulE-Com backend is running on http://localhost:${port}`);
});
