const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const User = require("./models/User.js");
const Course = require("./models/Course.js");
const cookieParser = require("cookie-parser");
const { body, validationResult } = require('express-validator');

const app = express();
const bcryptSalt = bcrypt.genSaltSync(12); // Increased salt rounds for better security
const jwtSecret = process.env.JWT_SECRET; // Use environment variable for secret
const mongoUrl = process.env.MONGO_URL; // Use MONGO_URL from environment variables

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    credentials: true,
    origin: ['http://localhost:5173', 'https://kimcresults-ac-ke.vercel.app'],
}));

mongoose.connect(mongoUrl, {
    serverSelectionTimeoutMS: 10000 // Adjust as needed
});

app.get("/test", (req, res) => {
    res.json("test ok");
});

app.post("/register",
    // Input validation
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body;
        try {
            const userDoc = await User.create({
                name,
                email,
                password: bcrypt.hashSync(password, bcryptSalt),
            });
            res.json({ userDoc });
        } catch (e) {
            res.status(422).json({ error: 'Registration failed', details: e.message });
        }
    });

app.post("/login", 
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;
        try {
            const userDoc = await User.findOne({ email });
            if (userDoc) {
                const passOK = bcrypt.compareSync(password, userDoc.password);
                if (passOK) {
                    jwt.sign(
                        { email: userDoc.email, id: userDoc._id },
                        jwtSecret,
                        { expiresIn: '1h' }, // JWT token expires in 1 hour
                        (err, token) => {
                            if (err) throw err;
                            res.cookie("token", token, { httpOnly: true, secure: true }).json(userDoc);
                        }
                    );
                } else {
                    res.status(422).json({ error: 'Invalid password' });
                }
            } else {
                res.status(404).json({ error: 'User not found' });
            }
        } catch (e) {
            res.status(500).json({ error: 'Login failed', details: e.message });
        }
    });

app.get("/profile", (req, res) => {
    const { token } = req.cookies;
    if (token) {
        jwt.verify(token, jwtSecret, {}, async (err, userData) => {
            if (err) return res.status(401).json({ error: 'Invalid token' });
            try {
                const { name, email, _id } = await User.findById(userData.id);
                res.json({ name, email, _id });
            } catch (e) {
                res.status(500).json({ error: 'Failed to retrieve profile', details: e.message });
            }
        });
    } else {
        res.status(401).json({ error: 'No token provided' });
    }
});

app.post("/logout", (req, res) => {
    res.cookie("token", "", { httpOnly: true, secure: true }).json(true);
});

app.post("/courses", (req, res) => {
    const { token } = req.cookies;
    const {
        name, title, department,
        year, units, phone, admission,
        unitsEnrolled, gender
    } = req.body;

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        try {
            const courseDoc = await Course.create({
                owner: userData.id,
                name, title, department,
                year, units, phone, admission,
                unitsEnrolled, gender
            });
            res.json(courseDoc);
        } catch (e) {
            res.status(422).json({ error: 'Course creation failed', details: e.message });
        }
    });
});

app.get("/user-courses", (req, res) => {
    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        try {
            const courses = await Course.find({ owner: userData.id });
            res.json(courses);
        } catch (e) {
            res.status(500).json({ error: 'Failed to retrieve courses', details: e.message });
        }
    });
});

app.get("/courses/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const course = await Course.findById(id);
        if (course) {
            res.json(course);
        } else {
            res.status(404).json({ error: 'Course not found' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Failed to retrieve course', details: e.message });
    }
});

app.put("/courses", (req, res) => {
    const { token } = req.cookies;
    const {
        id, name, title, department,
        year, units, phone, admission,
        unitsEnrolled, gender
    } = req.body;
    
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        try {
            const courseDoc = await Course.findById(id);
            if (userData.id === courseDoc.owner.toString()) {
                courseDoc.set({
                    name, title, department,
                    year, units, phone, admission,
                    unitsEnrolled, gender
                });
                await courseDoc.save();
                res.json("ok");
            } else {
                res.status(403).json({ error: 'Unauthorized' });
            }
        } catch (e) {
            res.status(500).json({ error: 'Course update failed', details: e.message });
        }
    });
});

app.get("/courses", async (req, res) => {
    try {
        const courses = await Course.find();
        res.json(courses);
    } catch (e) {
        res.status(500).json({ error: 'Failed to retrieve courses', details: e.message });
    }
});

app.listen(4000, () => {
    console.log('Server is running on port 4000');
});