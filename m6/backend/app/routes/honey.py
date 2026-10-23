from flask import Blueprint, current_app, jsonify

from ..services.honey_service import honey_files

bp = Blueprint("honey", __name__)


@bp.get("/honey-files")
def get_honey_files():
    return jsonify(honey_files(current_app.extensions["adapters"]["m3"]))
