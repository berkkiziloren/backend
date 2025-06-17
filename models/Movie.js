const mongoose = require('mongoose');

const movieSchema = new mongoose.Schema({
    title: { type: String, required: true },
    year: { type: Number },
    runtime: { type: Number },
    plot: { type: String },
    poster: { type: String },
    genres: [{ type: String }],
    cast: [{ type: String }],
    directors: [{ type: String }],
    rated: { type: String },
    imdb: {
        rating: { type: Number },
        votes: { type: Number },
        id: { type: Number }
    },
    type: { type: String },
    lastupdated: { type: String }
}, {
    timestamps: true
});

module.exports = mongoose.model('Movie', movieSchema); 