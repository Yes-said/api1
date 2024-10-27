const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const User = require("./models/User.js");
const Course = require("./models/Course.js");
const News = require('./models/News');
const Results = require('./models/Results');
const cookieParser = require("cookie-parser");
const multer = require('multer');
const path = require('path');
const app = express();
const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = "yujlkjhfgdsrzxdtcfwgihopjmjjjnibuvyxrsc";

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    credentials: true,
    origin: (origin, callback) => {
        if (!origin || ['http://localhost:5173', 'https://kimcresults-ac-ke.vercel.app'].includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

mongoose.connect(process.env.MONGO_URL);

// Search functionality
async function searchDatabase(query) {
    try {
        const userResults = await User.find({ name: new RegExp(query, 'i') });
        const courseResults = await Course.find({ courseName: new RegExp(query, 'i') });
        return { users: userResults, courses: courseResults };
    } catch (error) {
        console.error("Error during search:", error);
        throw error;
    }
}

app.get("/search", async (req, res) => {
    const { query } = req.query;
    try {
        const results = await searchDatabase(query);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: "Failed to search the database." });
    }
});

app.get("/test", (req, res) => {
    res.json("test ok");
});

app.post("/register", async (req, res) => {
    const { name, identity, password, role } = req.body;

    if (!['student', 'admin'].includes(role)) {
        return res.status(400).json({ error: "Invalid role" });
    }

    try {
        const userDoc = new User({ name, identity, password, role });
        const newUser = await userDoc.save();
        res.json({ success: true, user: newUser });
    } catch (e) {
        console.error("Registration error:", e);
        if (e.name === 'ValidationError') {
            return res.status(400).json({ error: e.message });
        }
        res.status(422).json({ error: "Registration failed" });
    }
});

app.post("/login", async (req, res) => {
    const { identity, password, role } = req.body;
    const userDoc = await User.findOne({ identity });
    if (userDoc) {
        const passOK = bcrypt.compareSync(password, userDoc.password);
        if (passOK) {
            if (userDoc.role !== role) {
                return res.status(403).json("Permission denied. Please login with the correct role.");
            }

            jwt.sign({
                identity: userDoc.identity,
                id: userDoc._id,
                role: userDoc.role,
            }, jwtSecret, {}, (err, token) => {
                if (err) throw err;
                res.cookie("token", token, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'None',
                }).json(userDoc);
            });
        } else {
            res.status(422).json("Incorrect password.");
        }
    } else {
        res.status(404).json("User not found.");
    }
});

app.get("/profile", (req, res) => {
    const { token } = req.cookies;
    if (token) {
        jwt.verify(token, jwtSecret, {}, async (err, userData) => {
            if (err) throw err;
            const { name, identity, _id } = await User.findById(userData.id);
            res.json({ name, identity, _id });
        });
    } else {
        res.json(null);
    }
});

app.put("/update-profile", async (req, res) => {
    const { token } = req.cookies;
    const { name, identity, password } = req.body;

    if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) {
            return res.status(401).json({ error: "Invalid token" });
        }

        try {
            const user = await User.findById(userData.id);

            if (name) user.name = name;
            if (identity) user.identity = identity;
            if (password) {
                user.password = bcrypt.hashSync(password, bcryptSalt);
            }

            await user.save();
            res.json(user);
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: "Failed to update profile" });
        }
    });
});

app.delete("/delete-profile", async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) {
            return res.status(401).json({ error: "Invalid token" });
        }

        try {
            const user = await User.findByIdAndDelete(userData.id);
            if (!user) {
                return res.status(404).json({ error: "User not found" });
            }

            res.cookie("token", "", {
                httpOnly: true,
                secure: true,
                sameSite: 'None',
            }).json({ success: true, message: "Profile deleted successfully" });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: "Failed to delete profile" });
        }
    });
});

app.post("/logout", (req, res) => {
    res.cookie("token", "", {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
    }).json(true);
});

app.post("/courses", (req, res) => {
    const { token } = req.cookies;
    const {
        name, courseName, department, year, units, phone, gender
    } = req.body;

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        const courseDoc = await Course.create({
            owner: userData.id,
            name, courseName, department, year, units, phone, gender
        });
        res.json(courseDoc);
    });
});

app.get("/user-courses", (req, res) => {
    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        const { id } = userData;
        res.json(await Course.find({ owner: id }));
    });
});

app.get("/courses/:id", async (req, res) => {
    const { id } = req.params;
    res.json(await Course.findById(id));
});

app.put("/courses", async (req, res) => {
    const { token } = req.cookies;
    const {
        id, name, courseName, department, year, units, phone, gender
    } = req.body;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) throw err;
        const courseDoc = await Course.findById(id);
        if (userData.id === courseDoc.owner.toString()) {
            courseDoc.set({
                name, courseName, department, year, units, phone, gender
            });
            await courseDoc.save();
            res.json("ok");
        }
    });
});

app.get("/courses", async (req, res) => {
    res.json(await Course.find());
});

app.get("/result", async (req, res) => {
    try {
        const results = await Results.find()
            .populate('student', 'name')
            .populate('course', 'courseName department year');
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch results" });
    }
});


app.post('/news', async (req, res) => {
    try {
      const { title, description, date, createdBy } = req.body;
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

// News Routes
// Get all news
app.get('/news', async (req, res) => {
    try {
        const news = await News.find();
        res.json(news);
    } catch (error) {
        console.error('Error fetching news:', error);
        res.status(500).json({ error: 'Failed to fetch news' });
    }
});

// Get news by ID
app.get('/news/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const newsItem = await News.findById(id);
        if (!newsItem) {
            return res.status(404).json({ error: 'News not found' });
        }
        res.json(newsItem);
    } catch (error) {
        console.error('Error fetching news:', error);
        res.status(500).json({ error: 'Failed to fetch news' });
    }
});

// Update news
app.put('/news/:id', async (req, res) => {
    const { id } = req.params;
    const { title, description, date, createdBy } = req.body;

    try {
        const updatedNews = await News.findByIdAndUpdate(id, {
            title,
            description,
            date,
            createdBy
        }, { new: true, runValidators: true });

        if (!updatedNews) {
            return res.status(404).json({ error: 'News not found' });
        }

        res.json(updatedNews);
    } catch (error) {
        console.error('Error updating news:', error);
        res.status(500).json({ error: 'Failed to update news' });
    }
});

// Delete news
app.delete('/news/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const deletedNews = await News.findByIdAndDelete(id);
        if (!deletedNews) {
            return res.status(404).json({ error: 'News not found' });
        }

        res.json({ success: true, message: 'News deleted successfully' });
    } catch (error) {
        console.error('Error deleting news:', error);
        res.status(500).json({ error: 'Failed to delete news' });
    }
});


const upload = multer({ dest: 'uploads/' });

function isAdmin(req, res, next) {
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) {
            return res.status(401).json({ error: "Invalid token" });
        }

        const user = await User.findById(userData.id);
        if (user.role !== 'admin') {
            return res.status(403).json({ error: "Permission denied" });
        }

        next();
    });
}

const Contact = require('./models/Contact'); // Import the Contact model

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


app.post('/upload-results', isAdmin, upload.single('file'), async (req, res) => {
    const { student, course, marks } = req.body;

    if (!req.file) {
        return res.status(400).json({ error: 'Please upload a file' });
    }

    try {
        const result = new Results({
            student,
            course,
            marks,
            pdf: req.file.path
        });

        await result.save();
        res.status(200).json({ success: true, message: 'Result uploaded successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to upload result' });
    }
});

app.listen(4000, () => {
    console.log('Server is running on port 4000');
});



