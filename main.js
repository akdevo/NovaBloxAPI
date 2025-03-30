const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const uuid = require('uuid');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1);
});

// User schema and model
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

// OTP store (use database in production)
let otpStore = {};

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    }
});

// Registration endpoint (Step 1: Send OTP)
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) return res.status(400).json({ error: 'Username or email already exists' });

        const otp = uuid.v4().slice(0, 6);
        otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'NovaBlox - Register OTP Verification',
            text: `Your OTP code is: ${otp}`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'OTP sent to your email. Please verify to complete registration.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login endpoint (Step 1: Send OTP)
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const otp = uuid.v4().slice(0, 6);
        otpStore[user.email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'NovaBlox - Login OTP Verification',
            text: `Your OTP code is: ${otp}`
        };
        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'OTP sent to your email. Please verify to complete login.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// OTP verification endpoint (Step 2: Verify OTP)
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otpInput, username, password } = req.body;
        const storedOtp = otpStore[email];

        // Debugging logs
        console.log("Received email:", email);
        console.log("Received OTP Input:", otpInput);
        console.log("Stored OTP Object:", storedOtp);
        console.log("Stored OTP:", storedOtp ? storedOtp.otp : "None");
        console.log("Stored Expiry Time:", storedOtp ? storedOtp.expiresAt : "None");
        console.log("Current Time:", Date.now());
        console.log("Expired?", storedOtp && Date.now() > storedOtp.expiresAt);

        // Check if OTP exists and is not expired
        if (!storedOtp) return res.status(400).json({ error: 'OTP not found. Request a new one.' });
        if (Date.now() > storedOtp.expiresAt) return res.status(400).json({ error: 'OTP expired. Request a new one.' });
        if (String(storedOtp.otp) !== String(otpInput)) return res.status(400).json({ error: 'Incorrect OTP. Try again.' });

        // Check if user exists
        let user = await User.findOne({ email });

        // If new user, register them
        if (!user) {
            if (!username || !password) {
                return res.status(400).json({ error: 'Missing username or password for registration.' });
            }

            console.log(`Registering new user: ${username}`);
            const hashedPassword = await bcrypt.hash(password, 10);
            user = new User({ username, email, password: hashedPassword });
            await user.save();
        }

        // Generate JWT token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'default_secret', { expiresIn: '1h' });

        // Remove OTP after successful verification
        delete otpStore[email];

        res.status(200).json({ message: 'Verification successful', token });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
