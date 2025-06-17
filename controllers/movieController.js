const Movie = require('../models/Movie');

// Get all movies with pagination
exports.getAllMovies = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const movies = await Movie.find()
            .skip(skip)
            .limit(limit)
            .sort({ title: 1 });

        const total = await Movie.countDocuments();

        res.json({
            movies,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalMovies: total
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Get a single movie by ID
exports.getMovieById = async (req, res) => {
    try {
        const movie = await Movie.findById(req.params.id);
        if (!movie) {
            return res.status(404).json({ message: 'Movie not found' });
        }
        res.json(movie);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Create a new movie
exports.createMovie = async (req, res) => {
    try {
        const movie = new Movie(req.body);
        const savedMovie = await movie.save();
        res.status(201).json(savedMovie);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

// Update a movie
exports.updateMovie = async (req, res) => {
    try {
        const movie = await Movie.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        );
        if (!movie) {
            return res.status(404).json({ message: 'Movie not found' });
        }
        res.json(movie);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

// Delete a movie
exports.deleteMovie = async (req, res) => {
    try {
        const movie = await Movie.findByIdAndDelete(req.params.id);
        if (!movie) {
            return res.status(404).json({ message: 'Movie not found' });
        }
        res.json({ message: 'Movie deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Search movies
exports.searchMovies = async (req, res) => {
    try {
        const { query } = req.query;
        const movies = await Movie.find({
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { plot: { $regex: query, $options: 'i' } },
                { genres: { $regex: query, $options: 'i' } }
            ]
        }).limit(20);
        res.json(movies);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
}; 