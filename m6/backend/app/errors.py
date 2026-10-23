"""JSON error responses. Stack traces are logged, never returned to the client."""
from flask import jsonify
from werkzeug.exceptions import HTTPException

from .integrations.base import IntegrationError


class ApiError(Exception):
    """Raised by M6 routes/services for expected client errors."""

    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(code, message, status):
    return jsonify(error={"code": code, "message": message}), status


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def handle_api_error(exc):
        return error_response(exc.code, exc.message, exc.status)

    @app.errorhandler(IntegrationError)
    def handle_integration_error(exc):
        return error_response(exc.code, exc.message, exc.status)

    @app.errorhandler(HTTPException)
    def handle_http_error(exc):
        return error_response(exc.name.upper().replace(" ", "_"), exc.description, exc.code)

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc):
        app.logger.exception("Unhandled error: %s", exc)
        return error_response("INTERNAL_ERROR", "An internal error occurred.", 500)
