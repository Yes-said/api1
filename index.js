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
app.use(express.static(path.join(__dirname, 'dist')));
app.use(cors({
    credentials: true,
    origin: ['http://localhost:5173', 'https://saiddev.vercel.app'],
 }));

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
app.get("/api/test", (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    res.json("test ok");
});

// Registration route

app.post("/api/register", async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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
app.post("/api/login", async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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


app.post("/api/logout", (req,res) => {
    res.cookie("token", "").json(true);
})

// Profile route
app.get("/api/profile", async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ success: false, message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        
        // Use findById instead of findByIdAdmin
        const user = await User.findById(decoded.id);

        if (!user || user.isDeleted) {
            return res.status(404).json({
                success: false,
                message: "User not found or has been deleted"
            });
        }

        res.json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                identity: user.identity,
                role: user.role,
                course: user.role === 'student' ? user.course : undefined
            }
        });
    } catch (error) {
        console.error("Error retrieving user profile:", error);
        if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({ 
                success: false, 
                message: "Invalid token" 
            });
        }
        res.status(500).json({ 
            success: false, 
            message: "An error occurred while fetching the profile" 
        });
    }
});

// Utility function to verify token and get user
const getAuthenticatedUser = async (token) => {
    const decoded = jwt.verify(token, jwtSecret);
    const user = await User.findById(decoded.id);
    
    if (!user || user.isDeleted) {
        throw new Error('User not found or has been deleted');
    }
    
    return user;
};

// Update adminMiddleware to use getAuthenticatedUser
const adminMiddleware = async (req, res, next) => {
    try {
        const { token } = req.cookies;
        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const user = await getAuthenticatedUser(token);

        if (user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: "Admin access required"
            });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Admin middleware error:', error);
        return res.status(401).json({
            success: false,
            message: error.message || "Authentication failed"
        });
    }
};


// Backend: Add this route to your Express app
app.get('/api/check-admin', adminMiddleware, (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    res.json({ success: true, user: req.user });
});

// News routes with role-based authorization
app.post('/api/news', authorizeRole('admin'), async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

app.post("/api/student", async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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
    mongoose.connect(process.env.MONGO_URL);
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
    mongoose.connect(process.env.MONGO_URL);
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


//update student
app.put('/api/students/:id', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

        const { name, identity, course } = req.body;
        
        // Validate required fields
        if (!name || !identity || !course) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        // Validate course enum
        const validCourses = ['ict', 'nursing', 'clinical medicine'];
        if (!validCourses.includes(course)) {
            return res.status(400).json({
                success: false,
                message: "Invalid course selection"
            });
        }

        // Check if student exists
        const student = await User.findOne({ 
            _id: req.params.id, 
            role: 'student',
            isDeleted: false
        });

        if (!student) {
            return res.status(404).json({
                success: false,
                message: "Student not found"
            });
        }

        // Check if new identity conflicts with existing one (excluding current student)
        if (identity !== student.identity) {
            const existingUser = await User.findOne({ 
                identity, 
                _id: { $ne: req.params.id },
                isDeleted: false
            });
            
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
                course
            },
            { 
                new: true,
                runValidators: true,
                select: '-password'
            }
        );

        res.json({
            success: true,
            message: "Student updated successfully",
            data: updatedStudent
        });

    } catch (error) {
        console.error('Error updating student:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: "Validation error",
                errors: Object.values(error.errors).map(err => err.message)
            });
        }

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token"
            });
        }

        res.status(500).json({
            success: false,
            message: "Failed to update student"
        });
    }
});



// Modified delete endpoint with better error handling
app.delete('/api/users/:id', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

        // Verify the user exists and is a student
        const studentToDelete = await User.findById(req.params.id);
        if (!studentToDelete) {
            return res.status(404).json({ 
                success: false, 
                message: "Student not found" 
            });
        }

        if (studentToDelete.role !== 'student') {
            return res.status(403).json({ 
                success: false, 
                message: "Can only delete student accounts" 
            });
        }

        // Perform the soft delete
        const updatedStudent = await User.findByIdAndUpdate(
            req.params.id,
            {
                isDeleted: true,
                deletedAt: new Date()
            },
            { new: true } // Return the updated document
        );

        if (!updatedStudent) {
            return res.status(500).json({
                success: false,
                message: "Failed to update student status"
            });
        }
        
        res.json({
            success: true,
            message: "Student deleted successfully",
            data: {
                id: updatedStudent._id,
                deletedAt: updatedStudent.deletedAt
            }
        });
    } catch (error) {
        console.error('Error in delete student endpoint:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid authentication token" 
            });
        }
        
        if (error.name === 'CastError') {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid student ID format" 
            });
        }
        
        res.status(500).json({ 
            success: false, 
            message: "Failed to delete student",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});


// Modified get endpoints to handle deleted status
app.get('/api/students', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

        // Include deleted parameter in query if specified
        const showDeleted = req.query.showDeleted === 'true';
        const query = { role: 'student' };
        if (!showDeleted) {
            query.isDeleted = false;
        }

        // Fetch students based on query
        const students = await User.find(query)
            .select('-password')
            .sort({ createdAt: -1 });

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


// Create new teacher (Admin only)
app.post('/api/manage-teachers/create', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

        const { name, email, password, subject } = req.body;
        
        // Validate required fields
        if (!name || !email || !password || !subject) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        // Check if email already exists
        const existingTeacher = await User.findOne({ 
            email,
            role: 'teacher',
            isDeleted: false
        });

        if (existingTeacher) {
            return res.status(400).json({
                success: false,
                message: "Email already registered"
            });
        }

        // Generate unique identity for teacher (e.g., TCH2024001)
        const teacherCount = await User.countDocuments({ role: 'teacher' });
        const identity = `TCH${new Date().getFullYear()}${(teacherCount + 1).toString().padStart(3, '0')}`;

        // Hash password
        const hashedPassword = bcrypt.hashSync(password, bcryptSalt);

        // Create new teacher
        const newTeacher = new User({
            name,
            email,
            identity,
            password: hashedPassword,
            subject,
            role: 'teacher'
        });

        await newTeacher.save();

        // Remove password from response
        const teacherResponse = newTeacher.toObject();
        delete teacherResponse.password;

        res.status(201).json({
            success: true,
            message: "Teacher created successfully",
            data: teacherResponse
        });

    } catch (error) {
        console.error('Error creating teacher:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: "Validation error",
                errors: Object.values(error.errors).map(err => err.message)
            });
        }

        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: "Email or identity already exists"
            });
        }

        res.status(500).json({
            success: false,
            message: "Failed to create teacher"
        });
    }
});

// Get all teachers
app.get('/api/manage-teachers', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

        // Include deleted parameter in query if specified
        const showDeleted = req.query.showDeleted === 'true';
        const query = { role: 'teacher' };
        if (!showDeleted) {
            query.isDeleted = false;
        }

        // Fetch teachers
        const teachers = await User.find(query)
            .select('-password')
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            data: teachers
        });
    } catch (error) {
        console.error('Error fetching teachers:', error);
        res.status(500).json({ 
            success: false, 
            message: "Failed to fetch teachers" 
        });
    }
});

// Get single teacher
app.get('/api/manage-teachers/:id', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

        const teacher = await User.findOne({ 
            _id: req.params.id, 
            role: 'teacher' 
        }).select('-password');

        if (!teacher) {
            return res.status(404).json({ 
                success: false, 
                message: "Teacher not found" 
            });
        }

        res.json({
            success: true,
            data: teacher
        });
    } catch (error) {
        console.error('Error fetching teacher:', error);
        res.status(500).json({ 
            success: false, 
            message: "Failed to fetch teacher" 
        });
    }
});

// Update teacher
app.put('/api/manage-teachers/:id', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

        const { name, email, subject } = req.body;
        
        // Validate required fields
        if (!name || !email || !subject) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        // Find the teacher
        const teacher = await User.findOne({ 
            _id: req.params.id, 
            role: 'teacher',
            isDeleted: false
        });

        if (!teacher) {
            return res.status(404).json({
                success: false,
                message: "Teacher not found"
            });
        }

        // Check if new email conflicts with existing one
        if (email !== teacher.email) {
            const existingTeacher = await User.findOne({ 
                email, 
                _id: { $ne: req.params.id },
                role: 'teacher',
                isDeleted: false
            });
            
            if (existingTeacher) {
                return res.status(400).json({
                    success: false,
                    message: "Email already exists"
                });
            }
        }

        // Update teacher
        const updatedTeacher = await User.findByIdAndUpdate(
            req.params.id,
            {
                name,
                email,
                subject
            },
            { 
                new: true,
                runValidators: true,
                select: '-password'
            }
        );

        res.json({
            success: true,
            message: "Teacher updated successfully",
            data: updatedTeacher
        });

    } catch (error) {
        console.error('Error updating teacher:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: "Validation error",
                errors: Object.values(error.errors).map(err => err.message)
            });
        }

        res.status(500).json({
            success: false,
            message: "Failed to update teacher"
        });
    }
});

/// Delete teacher (soft delete)
app.delete('/api/users/:id', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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

        // Verify the teacher exists and is actually a teacher
        const userToDelete = await User.findById(req.params.id);

        if (!userToDelete) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (userToDelete.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: "Can only delete teacher accounts from this endpoint"
            });
        }

        // Perform soft delete
        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            {
                isDeleted: true,
                deletedAt: new Date()
            },
            { new: true }
        );

        res.json({
            success: true,
            message: "Teacher deleted successfully",
            data: {
                id: updatedUser._id,
                deletedAt: updatedUser.deletedAt
            }
        });
    } catch (error) {
        console.error('Error deleting teacher:', error);
        res.status(500).json({
            success: false,
            message: "Failed to delete teacher"
        });
    }
});

//addnewcourse route
app.post('/api/courses', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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
app.get('/api/courses', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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
app.delete('/api/courses/:id', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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


// Authentication middleware
const authMiddleware = async (req, res, next) => {
    const { token } = req.cookies;
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: "Authentication required" 
        });
    }

    try {
        // Verify token and decode user data
        const userData = jwt.verify(token, jwtSecret);
        
        // Find user in database
        const user = await User.findById(userData.id);
        
        if (!user || user.isDeleted) {
            return res.status(401).json({
                success: false,
                message: "User not found or has been deleted"
            });
        }

        // Attach user to request object
        req.user = user;
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid authentication token" 
            });
        }
        
        return res.status(500).json({ 
            success: false, 
            message: "Authentication failed" 
        });
    }
};



// Update result
app.put('/api/results/:id',  async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    try {
        const {
            studentId,
            studentName,
            courseId,
            courseName,
            score,
            semester,
            academicYear
        } = req.body;

        // Check if result exists
        const result = await Results.findById(req.params.id);
        if (!result) {
            return res.status(404).json({
                success: false,
                message: "Result not found"
            });
        }

        // Update the result
        const updatedResult = await Results.findByIdAndUpdate(
            req.params.id,
            {
                studentId,
                studentName,
                courseId,
                courseName,
                score,
                semester,
                academicYear,
                updatedBy: req.user.id,
                updatedAt: new Date()
            },
            {
                new: true,
                runValidators: true
            }
        );

        res.json({
            success: true,
            message: "Result updated successfully",
            data: updatedResult
        });

    } catch (error) {
        console.error('Error updating result:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: "Validation error",
                errors: Object.values(error.errors).map(err => err.message)
            });
        }

        res.status(500).json({
            success: false,
            message: "Failed to update result"
        });
    }
});

// Delete result
app.delete('/api/results/:id',  async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    try {
        // Check if result exists
        const result = await Results.findById(req.params.id);
        if (!result) {
            return res.status(404).json({
                success: false,
                message: "Result not found"
            });
        }

        // Implement soft delete
        const deletedResult = await Results.findByIdAndUpdate(
            req.params.id,
            {
                isDeleted: true,
                deletedAt: new Date(),
                deletedBy: req.user.id
            },
            { new: true }
        );

        res.json({
            success: true,
            message: "Result deleted successfully",
            data: {
                id: deletedResult._id,
                deletedAt: deletedResult.deletedAt
            }
        });

    } catch (error) {
        console.error('Error deleting result:', error);
        res.status(500).json({
            success: false,
            message: "Failed to delete result"
        });
    }
});

// Get single result
app.get('/api/results/:id', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    try {
        const result = await Results.findOne({
            _id: req.params.id,
            isDeleted: false
        });

        if (!result) {
            return res.status(404).json({
                success: false,
                message: "Result not found"
            });
        }

        res.json({
            success: true,
            data: result
        });

    } catch (error) {
        console.error('Error fetching result:', error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch result"
        });
    }
});

// Get results by student
app.get('/api/results/student/:studentId',  async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    try {
        const results = await Results.find({
            studentId: req.params.studentId,
            isDeleted: false
        }).sort({ createdAt: -1 });

        res.json({
            success: true,
            data: results
        });

    } catch (error) {
        console.error('Error fetching student results:', error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch student results"
        });
    }
});

// Get results by course
app.get('/api/results/course/:courseId', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    try {
        const results = await Results.find({
            courseId: req.params.courseId,
            isDeleted: false
        }).sort({ createdAt: -1 });

        res.json({
            success: true,
            data: results
        });

    } catch (error) {
        console.error('Error fetching course results:', error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch course results"
        });
    }
});


// Fetch all news
app.get('/api/news', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    try {
        const news = await News.find();
        res.json(news);
    } catch (error) {
        console.error('Error fetching news:', error);
        res.status(500).json({ error: 'Failed to fetch news' });
    }
});

// Contact form submission
app.post('/api/contact', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
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