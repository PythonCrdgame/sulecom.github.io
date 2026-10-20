const express = require("express");
const path = require("path");

const app = express();
const port = 3000;
const frontendDir = path.join(__dirname, "..", "frontend");

const users = [];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(frontendDir));

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", users: users.length });
});

app.post("/api/signup", (req, res) => {
  const { name, email, password, accountType } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Name, email, and password are required." });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const normalizedName = String(name).trim();
  const normalizedAccountType = accountType === "buyer" ? "buyer" : "buyer-seller";

  if (!normalizedEmail || !normalizedName || !password.trim()) {
    return res.status(400).json({ message: "Please complete all required fields." });
  }

  const existingUser = users.find((user) => user.email.toLowerCase() === normalizedEmail);
  if (existingUser) {
    return res.status(409).json({ message: "An account with this email already exists." });
  }

  const newUser = {
    id: Date.now(),
    name: normalizedName,
    email: normalizedEmail,
    password: String(password),
    accountType: normalizedAccountType,
    createdAt: new Date().toISOString(),
  };

  users.push(newUser);

  const { password: _password, ...userWithoutPassword } = newUser;
  return res.status(201).json({
    message: "Account created successfully.",
    user: userWithoutPassword,
  });
});

app.post("/api/signin", (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  const foundUser = users.find(
    (user) => user.email.toLowerCase() === String(email).trim().toLowerCase() && user.password === String(password)
  );

  if (!foundUser) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  const { password: _password, ...safeUser } = foundUser;
  return res.json({
    message: "Sign in successful.",
    user: safeUser,
  });
});

app.get("/api/users", (req, res) => {
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
