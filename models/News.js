const mongoose = require("mongoose");

const NewsSchema = new mongoose.Schema({
    title: String,
    description: String,
    date: { type: Date, default: Date.now },
    createdBy: String,
    updatedAt: Date, // This will be updated each time news is modified
});

const NewsModel = mongoose.model("News", NewsSchema);

module.exports = NewsModel;