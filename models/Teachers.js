const mongoose = require('mongoose');

const teacherSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
    },
    phone: {
        type: String,
        required: true,
        trim: true,
    },
    department: {
        type: String,
        required: true,
        trim: true,
    },
    unitsTaught: {
        type: String,
        required: true,
        trim: true,
    },
}, {
    timestamps: true,
});

const Teacher = mongoose.model('Teacher', teacherSchema);

module.exports = Teacher;
