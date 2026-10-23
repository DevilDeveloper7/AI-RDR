"""Start the M6 Flask API:  python backend/run.py  (run from the repo root)."""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5001")),
        # Debug mode exposes an interactive debugger, so it is opt-in only.
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
