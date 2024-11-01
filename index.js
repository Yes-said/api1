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
const Course = require('./models/Course.js');
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
                // Include role in the JWT token
                jwt.sign(
                    { 
                        identity: userDoc.identity, 
                        id: userDoc._id,
                        role: userDoc.role  // Add role to token
                    }, 
                    jwtSecret, 
                    {}, 
                    (err, token) => {
                        if (err) {
                            console.error("JWT signing error:", err);
                            return res.status(500).json({ success: false, message: "Error generating token" });
                        }
                        res.cookie("token", token).json({
                            success: true,
                            message: "Login successful",
                            user: { 
                                id: userDoc._id, 
                                name: userDoc.name, 
                                identity: userDoc.identity,
                                role: userDoc.role  // Include role in response
                            }
                        });
                    }
                );
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


app.post("/logout", (req,res) => {
    res.cookie("token", "").json(true);
})

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


// Update profile
app.put("/profile", async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ success: false, message: "No token provided" });
    }

    try {
        const userData = jwt.verify(token, jwtSecret);
        const { name, identity } = req.body;
        
        const updatedUser = await User.findByIdAndUpdate(
            userData.id,
            { name, identity },
            { new: true }
        );

        res.json({ 
            success: true, 
            user: {
                id: updatedUser._id,
                name: updatedUser.name,
                identity: updatedUser.identity
            }
        });
    } catch (error) {
        console.error("Profile update error:", error);
        res.status(500).json({ success: false, message: "Failed to update profile" });
    }
});

// Delete profile
app.delete("/profile", async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ success: false, message: "No token provided" });
    }

    try {
        const userData = jwt.verify(token, jwtSecret);
        await User.findByIdAndDelete(userData.id);
        res.cookie("token", "").json({ success: true });
    } catch (error) {
        console.error("Profile deletion error:", error);
        res.status(500).json({ success: false, message: "Failed to delete profile" });
    }
});


const adminMiddleware = async (req, res, next) => {
    try {
        const { token } = req.cookies;
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: "Authentication required" 
            });
        }

        const decoded = jwt.verify(token, jwtSecret);
        const user = await User.findById(decoded.id);

        if (!user || user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: "Admin access required" 
            });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ 
            success: false, 
            message: "Invalid token" 
        });
    }
};

// Backend: Add this route to your Express app
app.get('/api/check-admin', adminMiddleware, (req, res) => {
    res.json({ success: true, user: req.user });
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

app.post("/student", async (req, res) => {
  try {
    const { name, identity, password, course } = req.body;
    
    // Basic validation
    if (!name || !identity || !password || !course) {
      return res.status(400).json({
        error: 'All fields are required'
      });
    }
    
    // Validate grade enum
    const validCourse = ['ict', 'nursing', 'clinical medicine'];
    if (!validCourse.includes(course)) {
      return res.status(400).json({
        error: 'Invalid course selection'
      });
    }
    
    // Check if student number already exists
    const existingUser = await User.findOne({ identity });
    if (existingUser) {
      return res.status(400).json({
        error: 'Student number already exists'
      });
    }
    
    // Create new user
    const newUser = new User({
      name,
      identity,
      password, // Note: In production, password should be hashed
      role: 'student',
      course
    });
    
    await newUser.save();
    
    res.status(201).json({
      message: 'Student created successfully',
      data: {
        name: newUser.name,
        identity: newUser.identity,
        course: newUser.course,
        role: newUser.role
      }
    });
    
  } catch (error) {
    console.error('Error creating student:', error);
    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// Get all students (filtered from users collection)
app.get('/api/students', async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: "Authentication required" 
        });
    }

    try {
        // Verify admin access
        const userData = jwt.verify(token, jwtSecret);
        const adminUser = await User.findById(userData.id);
        
        if (!adminUser || adminUser.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: "Admin access required" 
            });
        }

        // Fetch all users with role 'student'
        const students = await User.find({ role: 'student' })
            .select('-password') // Exclude password field
            .sort({ createdAt: -1 }); // Sort by newest first

        res.json({
            success: true,
            data: students
        });
    } catch (error) {
        console.error('Error fetching students:', error);
        res.status(500).json({ 
            success: false, 
            message: "Failed to fetch students" 
        });
    }
});

// Get single student by ID
app.get('/api/students/:id', async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: "Authentication required" 
        });
    }

    try {
        // Verify admin access
        const userData = jwt.verify(token, jwtSecret);
        const adminUser = await User.findById(userData.id);
        
        if (!adminUser || adminUser.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: "Admin access required" 
            });
        }

        const student = await User.findOne({ 
            _id: req.params.id, 
            role: 'student' 
        }).select('-password');

        if (!student) {
            return res.status(404).json({ 
                success: false, 
                message: "Student not found" 
            });
        }

        res.json({
            success: true,
            data: student
        });
    } catch (error) {
        console.error('Error fetching student:', error);
        res.status(500).json({ 
            success: false, 
            message: "Failed to fetch student" 
        });
    }
});

// Delete student
app.delete('/api/students/:id', async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: "Authentication required" 
        });
    }

    try {
        // Verify admin access
        const userData = jwt.verify(token, jwtSecret);
        const adminUser = await User.findById(userData.id);
        
        if (!adminUser || adminUser.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: "Admin access required" 
            });
        }

        // Verify the user being deleted is actually a student
        const studentToDelete = await User.findById(req.params.id);
        if (!studentToDelete || studentToDelete.role !== 'student') {
            return res.status(404).json({ 
                success: false, 
                message: "Student not found" 
            });
        }

        await User.findByIdAndDelete(req.params.id);
        
        res.json({
            success: true,
            message: "Student deleted successfully"
        });
    } catch (error) {
        console.error('Error deleting student:', error);
        res.status(500).json({ 
            success: false, 
            message: "Failed to delete student" 
        });
    }
});

// Update student
app.put('/api/students/:id', async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: "Authentication required" 
        });
    }

    try {
        // Verify admin access
        const userData = jwt.verify(token, jwtSecret);
        const adminUser = await User.findById(userData.id);
        
        if (!adminUser || adminUser.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: "Admin access required" 
            });
        }

        const { name, identity, grade } = req.body;

        // Verify the user being updated is actually a student
        const student = await User.findById(req.params.id);
        if (!student || student.role !== 'student') {
            return res.status(404).json({ 
                success: false, 
                message: "Student not found" 
            });
        }

        // Check if new identity conflicts with existing users
        if (identity !== student.identity) {
            const existingUser = await User.findOne({ identity });
            if (existingUser) {
                return res.status(400).json({ 
                    success: false, 
                    message: "Student number already exists" 
                });
            }
        }

        // Update student
        const updatedStudent = await User.findByIdAndUpdate(
            req.params.id,
            {
                name,
                identity,
                grade
            },
            { 
                new: true,
                runValidators: true 
            }
        ).select('-password');

        res.json({
            success: true,
            data: updatedStudent
        });
    } catch (error) {
        console.error('Error updating student:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ 
                success: false, 
                message: error.message 
            });
        }
        res.status(500).json({ 
            success: false, 
            message: "Failed to update student" 
        });
    }
});

//addnewcourse route
app.post('/courses', async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ success: false, message: "No token provided" });
    }

    try {
        // Verify the token and check if the user is an admin
        const userData = jwt.verify(token, jwtSecret);
        const user = await User.findById(userData.id);
        
        if (user.role !== 'admin') {
            return res.status(403).json({ success: false, message: "Only admins can create courses" });
        }

        const { name, description } = req.body;
        const course = new Course({
            name,
            description,
            createdBy: userData.id
        });

        await course.save();
        res.status(201).json({
            success: true,
            data: course
        });
    } catch (error) {
        console.error('Error creating course:', error);
        res.status(500).json({ success: false, message: "Failed to create course" });
    }
});

// Get all courses
app.get('/courses', async (req, res) => {
    try {
        const courses = await Course.find()
            .sort({ createdAt: -1 }) // Sort by newest first
            .populate('createdBy', 'name'); // Include creator's name if needed
        
        res.json({
            success: true,
            data: courses
        });
    } catch (error) {
        console.error('Error fetching courses:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch courses' 
        });
    }
});

// Delete a course
app.delete('/courses/:id', async (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: "No token provided" 
        });
    }

    try {
        const userData = jwt.verify(token, jwtSecret);
        const user = await User.findById(userData.id);
        
        if (user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: "Only admins can delete courses" 
            });
        }

        const course = await Course.findByIdAndDelete(req.params.id);
        
        if (!course) {
            return res.status(404).json({ 
                success: false, 
                message: "Course not found" 
            });
        }

        res.json({
            success: true,
            message: "Course deleted successfully"
        });
    } catch (error) {
        console.error('Error deleting course:', error);
        res.status(500).json({ 
            success: false, 
            message: "Failed to delete course" 
        });
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