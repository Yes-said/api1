const mongoose = require("mongoose");

const ResultsSchema = new mongoose.Schema({
    studentName: { type: String, required: true },
    registrationNumber: { type: String, required: true, unique: true },
    course: { type: String, required: true },
    units: [
        {
            unit: { type: String, required: true },
            marks: { type: String, required: true },
        }
    ],
    pdf: { type: String, required: false }, // Path to the uploaded PDF file
}, { timestamps: true });

const ResultsModel = mongoose.model("Results", ResultsSchema);

module.exports = ResultsModel;