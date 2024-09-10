const mongoose = require("mongoose");

const NewsSchema = new mongoose.Schema({
    title: String,
    description: String,
    date: Date,
    createdBy: String,
    category: String,
    createdAt: Date,
    updatedAt: Date,
});

const NewsModel = mongoose.model("News", NewsSchema);

module.exports = NewsModel;