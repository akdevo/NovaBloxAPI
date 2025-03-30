const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const uuid = require('uuid');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

require('dotenv').config();

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.log('Error connecting to MongoDB:', error);
});

// User schema and model
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

// In-memory OTP store (could be replaced by a database in production)
let otpStore = {};

// Set up a nodemailer transporter (use a real email service in production)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // Your email
        pass: process.env.EMAIL_PASS, // Your email password or app-specific password
    }
});

// Log email credentials (only for development/debugging)
console.log('Email user:', process.env.EMAIL_USER);
console.log('Email pass:', process.env.EMAIL_PASS);

// Login route with OTP
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        // Generate OTP for login
        const otp = uuid.v4().slice(0, 6); // Generate a 6-character OTP
        otpStore[user.email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 }; // OTP expires in 5 minutes

        // Send OTP to user's email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'NovaBlox - OTP Verification',
            text: `Your OTP code is: ${otp}`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'OTP sent to your email. Please verify to complete login.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// OTP verification route to complete login
app.post('/verify-otp', async (req, res) => {
    const { email, otpInput } = req.body;

    // Check if OTP exists and is not expired
    const storedOtp = otpStore[email];
    if (!storedOtp) return res.status(400).json({ error: 'OTP not generated or expired' });

    // Validate OTP and check expiration
    if (storedOtp.otp !== otpInput || Date.now() > storedOtp.expiresAt) {
        return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Clear the OTP from memory after successful verification
    delete otpStore[email];

    // Generate JWT token
    const token = jwt.sign({ id: email }, 'secretkey', { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', token });
});

// Start server
app.listen(3000, () => console.log('Server running on port 3000'));
