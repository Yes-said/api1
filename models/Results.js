const mongoose = require('mongoose');

const ResultSchema = new mongoose.Schema({
    studentName: String,
    registrationNumber: String,
    course: String,
    units: String,
    marks: Number,
    pdf: String // Path to the uploaded PDF file
});

const Results = mongoose.model("Results", ResultSchema);

module.exports = Results;