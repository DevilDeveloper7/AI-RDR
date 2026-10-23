from . import alerts, health, honey, integrations, intel


def register_routes(app):
    prefix = app.config["API_PREFIX"]
    for module in (health, alerts, honey, intel, integrations):
        app.register_blueprint(module.bp, url_prefix=prefix)
