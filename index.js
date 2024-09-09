const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs")
require("dotenv").config()
const User = require("./models/User.js");
const Course = require("./models/Course.js");
const Results = require('./models/Results'); // Import Results model
const cookieParser = require("cookie-parser");
const multer = require('multer');
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
}));




mongoose.connect(process.env.MONGO_URL);

app.get("/test", (req, res) => {
res.json("test ok");
});

app.post("/register", async (req, res) => {
const{name,email,password,role} = req.body;
try {
    const userDoc = await User.create({
        name,
        email,
        password:bcrypt.hashSync(password,bcryptSalt),
        role, // Save role
    });
    res.json({userDoc});
} catch (e) {
    res.status(422).json(e);
}


});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const userDoc = await User.findOne({ email });
    if (userDoc) {
        const passOK = bcrypt.compareSync(password, userDoc.password);
        if (passOK) {
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
            res.status(422).json("pass not ok");
        }
    } else {
        res.json("not found");
    }
});

app.get("/profile", (req,res) => {
    const {token} = req.cookies;
    if (token) {
jwt.verify(token, jwtSecret, {}, async (err, userData) => {
if (err) throw err;
const {name,email,_id} = await User.findById(userData.id);
res.json({name,email,_id});
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
        name,courseName, department,
        year, units, phone, admission,
        unitsEnrolled, gender
    } = req.body;

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
         if (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
        const courseDoc = await Course.create({
            owner: userData.id,
            name,courseName, department,
            year, units, phone, admission,
            unitsEnrolled, gender
        });
        res.json(courseDoc);
    });
});



app.get("/user-courses", (req,res) => {
    const {token} = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        const {id} = userData;
        res.json( await Course.find({owner:id}) );
    });
   
});



app.get("/courses/:id", async (req,res) => {
const {id} = req.params;
res.json(await Course.findById(id));

});

app.put("/courses", async (req,res) => {
    const {token} = req.cookies;
    const {
        id, name,courseName,department,
        year,units,phone,admission,
        unitsEnrolled,gender
    } = req.body;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) throw err;
        const courseDoc = await Course.findById(id);
if (userData.id === courseDoc.owner.toString()) {
    courseDoc.set({
        name,courseName,department,
       year,units,phone,admission,
        unitsEnrolled,gender

    });
   await courseDoc.save();
    res.json("ok");
}
    });

});

app.get("/courses", async (req,res) => {
    res.json( await Course.find() );

})


app.get("/result", async (req, res) => {
    try {
        const results = await Results.find(); // Fetch results from Results collection
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch results" });
    }
});


const upload = multer({ dest: 'uploads/' }); // Adjust the destination as needed

app.post('/upload-results', upload.single('pdfFile'), async (req, res) => {
    
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



app.listen(4000);