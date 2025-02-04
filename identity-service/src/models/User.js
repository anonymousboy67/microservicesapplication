const mongoose = require('mongoose'); // Import mongoose to connect with the database
const argon2 = require('argon2'); // Import argon2 for password encryption

// Define the structure of the user data
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
}, { timestamps: true }); // Automatically adds createdAt and updatedAt fields

// Before saving, we encrypt the password
userSchema.pre('save', async function (next) {
    if (this.isModified('password')) { // If password is changed or new
        try {
            this.password = await argon2.hash(this.password); // Encrypt password
            next();
        } catch (error) {
            next(error);
        }
    } else {
        next();
    }
});

// Function to compare password when logging in
userSchema.methods.comparePassword = async function (candidatePassword) {
    try {
        return await argon2.verify(this.password, candidatePassword); // Check password match
    } catch (error) {
        throw error;
    }
};

// Add an index to quickly search by username
userSchema.index({ username: 'text' });

const User = mongoose.model('User', userSchema); // Create a model from the schema

module.exports = User; // Export the model so we can use it elsewhere
