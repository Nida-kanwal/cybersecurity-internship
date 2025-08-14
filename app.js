const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const logger = require('./logger'); // logger.js file pehle se hona chahiye

const app = express();

// Middlewares
app.use(helmet());
app.use(bodyParser.json());

// Simulated Database (in-memory)
const users = [];

// ✅ Register Route (Password Hashing + Validation)
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Validate email
  if (!validator.isEmail(email)) {
    return res.status(400).send('Invalid email');
  }

  // Check if user exists
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).send('User already exists.');
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Save user
  users.push({ email, password: hashedPassword });

  res.send('User registered successfully!');
});

// ✅ Login Route (Password Compare + JWT Token)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).send('Invalid email or password.');
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).send('Invalid email or password.');
  }

  // Create token
  const token = jwt.sign({ email: user.email }, 'your-secret-key', { expiresIn: '1h' });

  res.send({ message: 'Login successful!', token });
});

// ✅ Start Server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
  logger.info('Juice Shop is running with logging!');
});


