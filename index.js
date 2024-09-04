const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs")
require("dotenv").config()
const User = require("./models/User.js");
const Course = require("./models/Course.js");
const cookieParser = require("cookie-parser");


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

app.get("/test", (req, res) => {
res.json("test ok");
});

app.post("/register", async (req, res) => {
const{name,email,password} = req.body;
try {
    const userDoc = await User.create({
        name,
        email,
        password:bcrypt.hashSync(password,bcryptSalt),
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
         }, jwtSecret, { expiresIn: '1h' }, (err, token) => {
              if (err) throw err;

              res.cookie("token", token, { httpOnly: true }).json(userDoc);
          });
      } else {
          res.status(422).json("pass not ok");
      }
  } else {
      res.json("not found");
  }
});

app.get("/profile", (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
    }

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        const { name, email, _id } = await User.findById(userData.id);
        res.json({ name, email, _id });
    });
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


app.get("/user-courses", (req, res) => {
    const { token } = req.cookies;
    
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) {
            console.error("JWT verification error:", err);
            return res.status(401).json({ error: 'Invalid token or session expired' });
        }

        const { id } = userData;
        if (!id) {
            return res.status(400).json({ error: 'User ID not found' });
        }

        try {
            const courses = await Course.find({ owner: id });
            res.json(courses);
        } catch (error) {
            console.error("Database query error:", error);
            res.status(500).json({ error: 'Failed to retrieve courses' });
        }
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


app.listen(4000);
