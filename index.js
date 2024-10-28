const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const User = require("./models/User.js");
const News = require('./models/News');
const Contact = require('./models/Contact'); // Import the Contact model
const cookieParser = require("cookie-parser");
const path = require('path');
const app = express();

const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = "yujlkjhfgdsrzxdtcfwgihopjmjjjnibuvyxrsc";

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    credentials: true,
    origin: ['http://localhost:5173', 'https://kimcresults-ac-ke.vercel.app'],
 }));




mongoose.connect(process.env.MONGO_URL);

// Role-based authorization middleware
function authorizeRole(role) {
    return (req, res, next) => {
        const { token } = req.cookies;
        if (!token) return res.status(401).json({ error: 'Unauthorized' });

        jwt.verify(token, jwtSecret, (err, userData) => {
            if (err || userData.role !== role) {
                return res.status(403).json({ error: 'Access denied' });
            }
            req.user = userData;
            next();
        });
    };
}

// Basic test route
app.get("/test", (req, res) => {
    res.json("test ok");
});

// Registration route

app.post("/register", async (req, res) => {
    const { name, identity, password, role } = req.body;
    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const userDoc = await User.create({
            name,
            identity,
            password: hashedPassword,
            role
        });
        res.status(201).json(userDoc);
    } catch (error) {
        if (error.code === 11000) {
            res.status(400).json({ error: "Identity already exists." });
        } else if (error.errors) {
            res.status(400).json({ error: error.errors });
        } else {
            res.status(500).json({ error: "An error occurred while registering the user." });
        }
    }
});
//login
app.post("/login", async (req, res) => {
    const { identity, password, role } = req.body;
    try {
        const userDoc = await User.findOne({ identity, role });
        if (userDoc) {
            const passOk = bcrypt.compareSync(password, userDoc.password);
            if (passOk) {
                jwt.sign({ identity: userDoc.identity, id: userDoc._id }, jwtSecret, {}, (err, token) => {
                    if (err) {
                        console.error("JWT signing error:", err);
                        return res.status(500).json({ success: false, message: "Error generating token" });
                    }
                    res.cookie("token", token).json({
                        success: true,
                        message: "Login successful",
                        user: { id: userDoc._id, name: userDoc.name, identity: userDoc.identity }
                    });
                });
            } else {
                res.status(400).json({ success: false, message: "Incorrect password" });
            }
        } else {
            res.status(404).json({ success: false, message: "User not found" });
        }
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ success: false, message: "An error occurred during login" });
    }
});


// Profile route
app.get("/profile", async (req, res) => {
    const { token } = req.cookies;
    if (token) {
        jwt.verify(token, jwtSecret, {}, async (err, userData) => {
            if (err) {
                console.error("JWT verification error:", err);
                return res.status(403).json({ success: false, message: "Invalid token" });
            }
            try {
                const { name, identity, _id } = await User.findById(userData.id);
                res.json({ success: true, user: { id: _id, name, identity } });
            } catch (error) {
                console.error("Error retrieving user profile:", error);
                res.status(500).json({ success: false, message: "An error occurred while fetching the profile" });
            }
        });
    } else {
        res.status(401).json({ success: false, message: "No token provided" });
    }
});



// News routes with role-based authorization
app.post('/news', authorizeRole('admin'), async (req, res) => {
    const { title, description, date, createdBy } = req.body;
    try {
        const newNews = new News({
            title,
            description,
            date,
            createdBy
        });
        const savedNews = await newNews.save();
        res.status(201).json(savedNews);
    } catch (error) {
        console.error('Error creating news:', error);
        res.status(500).json({ error: 'Failed to create news' });
    }
});

// Fetch all news
app.get('/news', async (req, res) => {
    try {
        const news = await News.find();
        res.json(news);
    } catch (error) {
        console.error('Error fetching news:', error);
        res.status(500).json({ error: 'Failed to fetch news' });
    }
});

// Contact form submission
app.post('/contact', async (req, res) => {
    const { name, email, message } = req.body;

    try {
        const newContact = new Contact({
            name,
            email,
            message,
        });
        await newContact.save();
        res.status(201).json({ success: true, message: 'Message sent successfully' });
    } catch (error) {
        console.error('Error saving contact message:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

app.listen(4000, () => {
    console.log('Server is running on port 4000');
});