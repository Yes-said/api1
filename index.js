const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const User = require("./models/User.js");
const Course = require("./models/Course.js");
const News = require('./models/News'); // Adjust the path as necessary
const Results = require('./models/Results'); // Import Results model
const cookieParser = require("cookie-parser");
const multer = require('multer');
const path = require('path');
const app = express();
const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = "yujlkjhfgdsrzxdtcfwgihopjmjjjnibuvyxrsc";
//const resetTokenSecret = "resetTokenSecret"; // Separate secret for reset tokens

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

//search
async function searchDatabase(query) {
    try {
        // Assuming you want to search in the User and Course collections
        const userResults = await User.find({ name: new RegExp(query, 'i') }); // Case-insensitive search by name
        const courseResults = await Course.find({ courseName: new RegExp(query, 'i') }); // Case-insensitive search by course name

        return { users: userResults, courses: courseResults };
    } catch (error) {
        console.error("Error during search:", error);
        throw error; // Rethrow the error for handling in the route
    }
}

// Use the function in your search route
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
    const { name, admission, email, password, role } = req.body;
    try {
        const userDoc = await User.create({
            name,
            admission,
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

app.put("/update-profile", async (req, res) => {
    const { token } = req.cookies;
    const { name, email, password } = req.body;

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
            if (email) user.email = email;
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

// DELETE route to delete the user's profile
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

            // Invalidate the token
            res.cookie("token", "", {
                httpOnly: true,
                secure: true, // Set to true if your environment is HTTPS
                sameSite: 'None', // Required for cross-site requests
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
app.post("/upload-results", isAdmin, upload.single('pdfFile'), async (req, res) => {
    const { studentName, registrationNumber, course } = req.body;

    try {
        // Validate if the student exists in the User collection
        const student = await User.findOne({ name: studentName, registrationNumber: registrationNumber });
        if (!student) {
            return res.status(404).json({ error: "Student not found. Ensure the student is registered before adding results." });
        }

        // Validate if the course exists in the Course collection
        const courseExists = await Course.findOne({ courseName: course });
        if (!courseExists) {
            return res.status(404).json({ error: "Course not found. Ensure the course is registered before adding results." });
        }

        // Validate units structure
        const units = req.body.units.map((unit, index) => ({
            unit: req.body[`units[${index}][unit]`],
            marks: req.body[`units[${index}][marks]`],
        }));

        const pdfFile = req.file;
        if (!pdfFile) {
            return res.status(400).json({ error: "PDF file is required" });
        }

        // Create a new result entry
        const result = await Results.create({
            studentName,
            registrationNumber,
            course,
            units,
            pdf: pdfFile.path,
        });

        res.json({ success: true, result });
    } catch (err) {
        console.error("Failed to upload results:", err);
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
            req.user = user; 
            next(); 
        } else {
            return res.status(403).json({ error: "Forbidden: You do not have admin access" });
        }
        
    });
}

app.post("/upload-results", isAdmin, upload.single('pdfFile'), async (req, res) => {
    const { studentName, registrationNumber, course } = req.body;
    const units = req.body.units.map((units, index) => ({
        unit: req.body[`units[${index}][unit]`],
        marks: req.body[`units[${index}][marks]`],
    }));
    const pdfFile = req.file;

    if (!pdfFile) {
        return res.status(400).json({ error: "PDF file is required" });
    }

    try {
        const result = await Results.create({
            studentName,
            registrationNumber,
            course,
            units,
            pdf: pdfFile.path,
        });

        res.json({ success: true, result });
    } catch (err) {
        console.error("Failed to upload results:", err);
        res.status(500).json({ error: "Failed to upload results" });
    }
});

// PUT route to update a result by ID (Admin only)
app.put("/update-result/:id", isAdmin, upload.single('pdfFile'), async (req, res) => {
    const { id } = req.params;
    const { studentName, registrationNumber, course } = req.body;
    const units = req.body.units.map((unit, index) => ({
        unit: req.body[`units[${index}][unit]`],
        marks: req.body[`units[${index}][marks]`],
    }));
    const pdfFile = req.file;

    try {
        const result = await Results.findById(id);
        if (!result) {
            return res.status(404).json({ error: "Result not found" });
        }
 
         // Update fields
        result.studentName = studentName || result.studentName;
        result.registrationNumber = registrationNumber || result.registrationNumber;
        result.course = course || result.course;
        result.units = units || result.units;

        if (pdfFile) {
            result.pdf = pdfFile.path; // Update PDF path if a new file is uploaded
        }

        await result.save();
        res.json({ success: true, result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update result" });
    }
});

 // DELETE route to delete a result by ID (Admin only)
app.delete("/delete-result/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await Results.findByIdAndDelete(id);
        if (!result) {
            return res.status(404).json({ error: "Result not found" });
        }
        res.json({ success: true, message: "Result deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: "Failed to delete result" });
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