const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto"); // For generating reset tokens
require("dotenv").config();
const nodemailer = require('nodemailer'); // For sending emails
const User = require("./models/User.js");
const Course = require("./models/Course.js");
const News = require('./models/News'); // Adjust the path as necessary
const Results = require('./models/Results'); // Import Results model
const cookieParser = require("cookie-parser");
const multer = require('multer');
const app = express();
const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = "yujlkjhfgdsrzxdtcfwgihopjmjjjnibuvyxrsc";
const resetTokenSecret = "resetTokenSecret"; // Separate secret for reset tokens

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

mongoose.connect(process.env.MONGO_URL);

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
    },
});

app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
        return res.status(404).json({ error: "User not found." });
    }
    
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedResetToken = bcrypt.hashSync(resetToken, bcryptSalt);

    user.resetToken = hashedResetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    const resetLink = `http://localhost:5173/reset-password/${resetToken}`;

    transporter.sendMail({
        from: process.env.EMAIL,
        to: user.email,
        subject: "Password Reset",
        text: `You requested a password reset. Click the link to reset your password: ${resetLink}`,
    });

    res.json({ message: "Password reset link sent to your email." });
});

app.post("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    const user = await User.findOne({
        resetToken: token,
        resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) {
        return res.status(400).json({ error: "Invalid or expired token." });
    }

    user.password = bcrypt.hashSync(password, bcryptSalt);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: "Password has been reset successfully." });
});

app.get("/test", (req, res) => {
    res.json("test ok");
});

app.post("/register", async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const userDoc = await User.create({
            name,
            email,
            password: bcrypt.hashSync(password, bcryptSalt),
            role, // Save role
        });
        res.json({ userDoc });
    } catch (e) {
        res.status(422).json(e);
    }
});

app.post("/login", async (req, res) => {
    const { email, password, role } = req.body; // Include role in the request body
    const userDoc = await User.findOne({ email });
    if (userDoc) {
        const passOK = bcrypt.compareSync(password, userDoc.password);
        if (passOK) {
            // Check if the provided role matches the registered role
            if (userDoc.role !== role) {
                return res.status(403).json("Permission denied. Please login with the correct role.");
            }

            jwt.sign({
                email: userDoc.email,
                id: userDoc._id,
                role: userDoc.role, // Include role in the token
            }, jwtSecret, {}, (err, token) => {
                if (err) throw err;
                res.cookie("token", token, {
                    httpOnly: true,
                    secure: true, // Set to true if your environment is HTTPS
                    sameSite: 'None', // Required for cross-site requests
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
            const { name, email, _id } = await User.findById(userData.id);
            res.json({ name, email, _id });
        });
    } else {
        res.json(null);
    }
});

app.post("/logout", (req, res) => {
    res.cookie("token", "", {
        httpOnly: true,
        secure: true, // Set to true if your environment is HTTPS
        sameSite: 'None', // Required for cross-site requests
    }).json(true);
});

app.post("/courses", (req, res) => {
    const { token } = req.cookies;
    const {
        name, courseName, department,
        year, units, phone, admission,
        unitsEnrolled, gender
    } = req.body;

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        const courseDoc = await Course.create({
            owner: userData.id,
            name, courseName, department,
            year, units, phone, admission,
            unitsEnrolled, gender
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
        id, name, courseName, department,
        year, units, phone, admission,
        unitsEnrolled, gender
    } = req.body;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) throw err;
        const courseDoc = await Course.findById(id);
        if (userData.id === courseDoc.owner.toString()) {
            courseDoc.set({
                name, courseName, department,
                year, units, phone, admission,
                unitsEnrolled, gender
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
        const results = await Results.find(); // Fetch results from Results collection
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch results" });
    }
});

const upload = multer({ dest: 'uploads/' }); // Adjust the destination as needed

// Add this middleware to your route
app.post("/upload-results", upload.single('pdfFile'), async (req, res) => {
    const { studentName, registrationNumber, course, units, marks } = req.body;
    const pdfFile = req.file;

    if (!pdfFile) {
        return res.status(400).json({ error: "PDF file is required" });
    }

    try {
        // Save the result and the file information to the Results collection
        const result = await Results.create({
            studentName,
            registrationNumber,
            course,
            units,
            marks,
            pdf: pdfFile.path,
        });

        res.json({ success: true, result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to upload results" });
    }
});

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
        if (user && user.role === 'admin') {
            req.user = user; // Attach the user to the request
            next(); // Proceed to the next middleware or route handler
        } 
    });
}

app.post("/upload-results", isAdmin, upload.single('pdfFile'), async (req, res) => {
    const { studentName, registrationNumber, course, units, marks } = req.body;
    const pdfFile = req.file;

    if (!pdfFile) {
        return res.status(400).json({ error: "PDF file is required" });
    }

    try {
        // Save the result and the file information to the Results collection
        const result = await Results.create({
            studentName,
            registrationNumber,
            course,
            units,
            marks,
            pdf: pdfFile.path,
        });

        res.json({ success: true, result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to upload results" });
    }
});

// Post news to the database (Admin only)
app.post('/news', isAdmin, async (req, res) => {
    console.log('Received request to post news:', req.body); // Log the incoming request body
    const { title, description, date, createdBy, category } = req.body; // Match the fields

    try {
        const newsDoc = await News.create({ 
            title, 
            description, 
            date, 
            createdBy, 
            updatedAt: new Date() 
        }); // Add updatedAt or any other fields if necessary

        console.log('News created successfully:', newsDoc); // Log the created news document
        res.json(newsDoc);
    } catch (err) {
        console.error('Failed to post news:', err); // Log the error details
        res.status(500).json({ error: "Failed to post news" });
    }
});


app.get('/news', async (req, res) => {
    try {
        const news = await News.find();
        res.json(news);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch news" });
    }
});

app.listen(4000, () => {
    console.log('Server is running on port 4000');
});
