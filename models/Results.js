const mongoose = require("mongoose");
const { Schema } = mongoose;

const ResultsSchema = new Schema({
  studentId: {
    type: String,
    required: [true, 'Student ID is required'],
    ref: 'User'  // Reference to User model for students
  },
  studentName: {
    type: String,
    required: [true, 'Student name is required']
  },
  courseId: {
    type: String,
    required: [true, 'Course ID is required']
  },
  courseName: {
    type: String,
    required: [true, 'Course name is required']
  },
  score: {
    type: Number,
    required: [true, 'Score is required'],
    min: [0, 'Score cannot be less than 0'],
    max: [100, 'Score cannot be more than 100']
  },
  grade: {
    type: String,
    required: [true, 'Grade is required'],
    enum: ['A', 'B', 'C', 'D', 'F']
  },
  semester: {
    type: String,
    required: [true, 'Semester is required'],
    enum: ['Fall', 'Spring', 'Summer']
  },
  academicYear: {
    type: String,
    required: [true, 'Academic year is required'],
    match: [/^\d{4}-\d{4}$/, 'Please enter academic year in format YYYY-YYYY']
  },
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: {
    type: Date,
    default: null
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',  // Reference to User model for teachers
    required: [true, 'Created by is required']
  }
}, {
  timestamps: true
});

// Indexes for better query performance
ResultsSchema.index({ studentId: 1, courseId: 1, academicYear: 1, semester: 1 }, { 
  unique: true,
  partialFilterExpression: { isDeleted: false }
});
ResultsSchema.index({ studentId: 1 });
ResultsSchema.index({ courseId: 1 });
ResultsSchema.index({ academicYear: 1 });

// Middleware to handle soft deletes in queries
ResultsSchema.pre('find', function() {
  this.where({ isDeleted: false });
});

ResultsSchema.pre('findOne', function() {
  this.where({ isDeleted: false });
});

// Method to calculate grade based on score
ResultsSchema.methods.calculateGrade = function() {
  const score = this.score;
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
};

// Middleware to automatically calculate grade before saving
ResultsSchema.pre('save', function(next) {
  this.grade = this.calculateGrade();
  next();
});

// Virtual for formatted grade display
ResultsSchema.virtual('formattedGrade').get(function() {
  return `${this.grade} (${this.score}%)`;
});

const Results = mongoose.model('Results', ResultsSchema);

module.exports = Results;