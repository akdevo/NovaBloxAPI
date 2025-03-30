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
    console.error('Error connecting to MongoDB:', error);
    process.exit(1); // Stop server if DB connection fails
});

// User schema and model
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

// In-memory OTP store (use DB in production)
let otpStore = {};

// Set up nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    }
});

// Ensure email credentials exist
if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error("Missing EMAIL_USER or EMAIL_PASS in environment variables.");
}

// Login route (Step 1: Request OTP)
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user by username
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        // Generate and store OTP
        const otp = uuid.v4().slice(0, 6);
        const normalizedEmail = user.email.toLowerCase();
        otpStore[normalizedEmail] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

        // Send OTP via email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'NovaBlox - Login OTP Verification',
            text: `Hi again! Your OTP code is: ${otp}`
        };
        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'OTP sent to your email. Please verify to complete login.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if username or email already exists
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) return res.status(400).json({ error: 'Username or email already exists' });

        // Generate OTP (One-Time Password)
        const otp = uuid.v4().slice(0, 6); // Generate a 6-character OTP
        otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 }; // OTP expires in 5 minutes

        // Send OTP to user's email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'NovaBlox - Register OTP Verification',
            text: `Hi! Thanks for registering your account! To register, you need to enter your OTP code, which is: ${otp}`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'OTP sent to your email. Please verify to complete registration.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// OTP Verification Route (Step 2: Verify and Login)
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otpInput, username, password } = req.body;
        const normalizedEmail = email.toLowerCase();

        const storedOtp = otpStore[normalizedEmail];
        if (!storedOtp || Date.now() > storedOtp.expiresAt) {
            return res.status(400).json({ error: 'OTP expired or invalid' });
        }

        if (storedOtp.otp !== otpInput) {
            return res.status(400).json({ error: 'Incorrect OTP' });
        }

        let user = await User.findOne({ email: normalizedEmail });

        if (!user) {
            if (!password || !username) {
                return res.status(400).json({ error: 'Username and password required for registration' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            user = new User({ username, email: normalizedEmail, password: hashedPassword });
            await user.save();
        }

        const token = jwt.sign({ id: user._id }, 'secretkey', { expiresIn: '1h' });

        delete otpStore[normalizedEmail];

        res.status(200).json({ message: 'Verification successful', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
