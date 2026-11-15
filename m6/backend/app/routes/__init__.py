from . import alerts, health, honey, integrations, intel, m5


def register_routes(app):
    prefix = app.config["API_PREFIX"]
    for module in (health, alerts, honey, intel, integrations, m5):
        app.register_blueprint(module.bp, url_prefix=prefix)