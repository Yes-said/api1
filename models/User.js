const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: [true, 'Name is required'] 
    },
    identity: {  
        type: String, 
        required: [true, 'Student No/Employee No is required'],  
        unique: true,
        trim: true,
        validate: {
            validator: function(v) {
                return /^[A-Za-z0-9]+$/.test(v);  
            },
            message: props => `${props.value} is not a valid Student No/Employee No!`
        }
    },
    password: { 
        type: String, 
        required: [true, 'Password is required']
    },
    role: {
        type: String,
        required: [true, 'Role is required'],
        enum: ['student', 'admin']
    }
}, { timestamps: true });

// Password validation middleware
UserSchema.pre('validate', function(next) {
    if (this.isModified('password')) {
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
        if (!passwordRegex.test(this.password)) {
            this.invalidate('password', 'Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, and a number');
        }
    }
    next();
});

// Password hashing middleware
UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        try {
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
        } catch (error) {
            return next(error);
        }
    }
    next();
});

// Method to compare passwords
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', UserSchema);

module.exports = User;