const express = require('express');
const router = express.Router();
const movieController = require('../controllers/movieController');

// Get all movies with pagination
router.get('/', movieController.getAllMovies);

// Search movies
router.get('/search', movieController.searchMovies);

// Get a single movie by ID
router.get('/:id', movieController.getMovieById);

// Create a new movie
router.post('/', movieController.createMovie);

// Update a movie
router.put('/:id', movieController.updateMovie);

// Delete a movie
router.delete('/:id', movieController.deleteMovie);

module.exports = router; 