const express = require('express');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const helmet = require('helmet');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// Middleware setup
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(mongoSanitize());

// Ensure uploads folder exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Serve static files (CSS, images, JavaScript) from frontend assets folder
app.use(express.static(path.join(__dirname, '../frontend/assets')));

// Rate limiter to prevent brute-force attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: 'Too many requests, please try again later.',
});
app.use(limiter);

// Connect to MongoDB using Mongoose
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        process.exit(1); // Exit if connection fails
    });

// User Schema and Model
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profile: {
        username: { type: String, required: true },
        profilePicture: { type: String },
        theme: { type: String, default: 'dark' }
    },
    loginAttempts: { type: Number, default: 0 },
    lastLogin: { type: Date }
});

const User = mongoose.model('User', userSchema);

// Multer setup for file uploads (e.g., profile pictures)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir); // Save profile pictures in 'uploads' folder
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}_${file.originalname}`);
    },
});

const upload = multer({ storage });

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentication token is missing' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Input validation
const validateUserInput = [
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('username').notEmpty().withMessage('Username is required'),
];

// Registration endpoint
app.post('/api/auth/register', validateUserInput, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password, username } = req.body;

        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = new User({
            email,
            password: hashedPassword,
            profile: { username }
        });

        await newUser.save();
        res.status(201).json({ message: 'User registered successfully', user: newUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Compare the password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            user.loginAttempts += 1;
            await user.save();
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Reset login attempts and update last login
        user.loginAttempts = 0;
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Return user without password
        const { password: _, ...userWithoutPassword } = user._doc;

        res.status(200).json({ message: 'Login successful', token, user: userWithoutPassword });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Profile Setup Endpoint
app.post('/api/auth/profile-setup', authenticateToken, upload.single('profilePic'), async (req, res) => {
    try {
        const { username, theme } = req.body;
        const profilePicPath = req.file ? `/uploads/${req.file.filename}` : '';

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Update profile details
        user.profile.username = username || user.profile.username;
        user.profile.profilePicture = profilePicPath || user.profile.profilePicture;
        user.profile.theme = theme || user.profile.theme;

        await user.save();
        res.status(200).json({ message: 'Profile updated successfully', user });
    } catch (error) {
        console.error('Error in profile setup:', error);
        res.status(500).json({ error: 'Profile setup failed' });
    }
});

// Serve uploaded profile pictures
app.use('/uploads', express.static(uploadDir));

// Routes to serve static HTML files from the 'frontend/pages'
const serveStaticFile = (filePath) => (req, res) => res.sendFile(path.join(__dirname, filePath));

app.get('/', serveStaticFile('../frontend/pages/index.html'));
app.get('/login', serveStaticFile('../frontend/pages/login.html'));
app.get('/signup', serveStaticFile('../frontend/pages/signup.html'));
app.get('/chat', authenticateToken, serveStaticFile('../frontend/pages/chat.html'));
app.get('/profile-setup', authenticateToken, serveStaticFile('../frontend/pages/profile-setup.html'));

// Handle 404 - Page not found
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, '../frontend/pages/404.html'));
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error handler:', err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
