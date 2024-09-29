const mongoose = require("mongoose");
const { Schema } = mongoose; // Destructure Schema from mongoose

const ResultsSchema = new Schema({
    student: { type: Schema.Types.ObjectId, ref: 'User', required: true }, // reference to the student
    course: { type: Schema.Types.ObjectId, ref: 'Course', required: true }, // reference to the course
    studentName: { type: String, required: true },
    registrationNumber: { type: String, required: true, unique: true },
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
