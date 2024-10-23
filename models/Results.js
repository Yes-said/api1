const mongoose = require("mongoose");
const { Schema } = mongoose; // Destructure Schema from mongoose

const ResultsSchema = new Schema({
    student: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    course: { type: Schema.Types.ObjectId, ref: 'Course', required: true },
    units: [
        {
            unit: { type: String, required: true },
            marks: { type: String, required: true },
        }
    ],
    pdf: { type: String }, // Path to the uploaded PDF file
}, { timestamps: true });


const ResultsModel = mongoose.model("Results", ResultsSchema);

module.exports = ResultsModel;
