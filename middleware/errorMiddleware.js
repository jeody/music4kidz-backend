const ErrorResponse = require('../utils/errorResponse');

const errorHandler = (err, req, res, next) => {
  let error = { ...err };

  error.message = err.message;
  // log to console for the developer
  console.log(err);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = `Resource not found`;
    error = new ErrorResponse(message, 404);
  }

  const statusCode = res.statusCode ? res.statusCode : 500;
  res.status(statusCode);

  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : null
  });
};

module.exports = errorHandler;
