const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;

app.use(bodyParser.json());



const users = [];
const secretKey = 'your_secret_key';

const generateToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
};

const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(403).send('Access denied');
  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
};

// Register a new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Username and password are required');
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, username, password: hashedPassword };
  users.push(user);
  res.status(201).send('User registered');
});

// Login and get a JWT token
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).send('Invalid username or password');
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).send('Invalid username or password');
  const token = generateToken(user);
  res.json({ token });
});

// Get user details (protected route)
app.get('/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).send('User not found');
  res.json({ username: user.username, id: user.id });
});

// Logout (clear token)
app.post('/logout', (req, res) => {
  res.send('Logged out');
});

// Error handling for invalid routes
app.use((req, res) => {
  res.status(404).send('Route not found');
});

app.listen(port, () => {
  console.log(`User authentication API running at http://localhost:${port}`);
});
