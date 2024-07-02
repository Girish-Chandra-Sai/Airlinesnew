const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/Users'); // Ensure this path is correct
const JWT_SECRET = process.env.JWT_SECRET;



// Registration route
router.post('/register', async (req, res) => {
  const { username, name, email, password, phoneNumber } = req.body;

  try {
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Create new user
    user = new User({
      username,
      name,
      email,
      password,
      phoneNumber,
    });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    // Return JWT
    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(
      payload,
      JWT_SECRET,
      { expiresIn: '7d' }, // Changed to 7 days
      (err, token) => {
        if (err) throw err;
        res.json({ token, isLoggedIn: true });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});


router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt for:', email);

  try {
    // Check if user exists
    let user = await User.findOne({ email });
    if (!user) {
      console.log('User not found');
      return res.status(400).json({ msg: 'Invalid Credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    console.log('Password match:', isMatch);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid Credentials' });
    }

    // Create and send JWT token
    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(
      payload,
      JWT_SECRET,
      { expiresIn: '7d' },
      (err, token) => {
        if (err) throw err;
        console.log('Login successful, sending token');
        res.json({ token, isLoggedIn: true });
      }
    );
  } catch (err) {
    console.error('Server error:', err.message);
    res.status(500).send('Server Error');
  }
});

// New route for checking authentication
router.get('/check-auth', (req, res) => {
  const token = req.header('Authorization')?.split(' ')[1];
  
  if (!token) {
    return res.json({ isLoggedIn: false });
  }

  try {
    jwt.verify(token, JWT_SECRET);
    res.json({ isLoggedIn: true });
  } catch (error) {
    res.json({ isLoggedIn: false });
  }
});

module.exports = router;