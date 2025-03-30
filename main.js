const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch((error) => {
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

// OTP store (in-memory for now)
let otpStore = {};

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    }
});

// Generate and send OTP
const sendOtp = async (email) => {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };
    console.log("OTP Stored:", otpStore);

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is: ${otp}`
    };
    await transporter.sendMail(mailOptions);
};

// Register (Send OTP)
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) return res.status(400).json({ error: 'User already exists' });

        // Send OTP to the email
        await sendOtp(email);
        res.status(200).json({ message: 'OTP sent. Verify to complete registration.' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login (Send OTP)
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Send OTP to the user's email for verification
        await sendOtp(user.email);
        res.status(200).json({ message: 'OTP sent. Verify to complete login.' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify OTP (Step 2: Verify OTP)
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otpInput, username, password } = req.body;
        const storedOtp = otpStore[email];

        // Check if OTP exists and if it's expired or incorrect
        if (!storedOtp) {
            console.error("oh bro shit there's no stored OTP");
            return res.status(400).json({ error: 'OTP not found. Request a new one.' });
        }
        if (Date.now() > storedOtp.expiresAt) {
            console.error("oh bro shit OTP is expired!");
            return res.status(400).json({ error: 'OTP expired. Request a new one.' });
        }
        if (storedOtp.otp !== otpInput) {
            console.error("bro what the fuck OTP is incorrect");
            return res.status(400).json({ error: 'Incorrect OTP. Try again.' });
        }

        // Remove OTP from store after it's been used
        delete otpStore[email];

        // Check if user exists
        let user = await User.findOne({ email });
        
        // If new user, register them
        if (!user) {
            if (!username || !password) {
                return res.status(400).json({ error: 'Missing username or password for registration.' });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            user = new User({ username, email, password: hashedPassword });
            await user.save();
        }

        // Generate JWT token for the user
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'default_secret', { expiresIn: '1h' });

        res.status(200).json({ message: 'Verification successful', token });
    } catch (error) {
        console.error('Error during OTP verification:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
