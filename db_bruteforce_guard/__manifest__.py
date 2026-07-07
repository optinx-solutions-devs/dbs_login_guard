{
    "name": "Database Brute Force Guard",
    "version": "17.0.1.0.0",
    "category": "Tools",
    "summary": "Track failed logins, alert admins, and block attacking IP addresses.",
    "description": """
        Protect your Odoo database from repeated login attacks.

        Main features:
        - Track failed and successful login attempts
        - Automatically block IP addresses after repeated failures
        - Send email alerts to administrators
        - Store browser, device, route, and geolocation details
        - Review security attempts from the backend
        - Unblock IP addresses manually when needed
    """,
    "author": "Optin Solutions",
    "support": "optinassist@gmail.com",
    "price": 11,
    "currency": "USD",
    "license": "LGPL-3",
    "depends": ["base", "mail", "web"],
    "data": [
        "security/ir.model.access.csv",
        "views/res_config_settings_views.xml",
        "views/security_attempt_views.xml",
    ],
    "images": ["static/description/banner.png"],
    "installable": True,
    "application": False,
    "auto_install": False,
}
