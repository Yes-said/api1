const mongoose  = require("mongoose");

const courseSchema = new mongoose.Schema({
owner: {type:mongoose.Schema.Types.ObjectId, ref: "User"},
name: String,
title: String,
department: String,
year: String,
units: [String],
phone: String,
admission: Number,
unitsEnrolled: Number,
gender: String,
});

const CourseModel = mongoose.model("Course", courseSchema);

module.exports = CourseModel;