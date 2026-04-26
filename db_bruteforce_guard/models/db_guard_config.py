from odoo import _, api, fields, models
from odoo.exceptions import ValidationError
from odoo.tools import email_split


class DbGuardConfig(models.Model):
    _name = "db.guard.config"
    _description = "Brute Force Guard Configuration"
    _rec_name = "name"
    _order = "id desc"

    name = fields.Char(required=True, default="Default")
    active = fields.Boolean(default=True)
    alert_email_to = fields.Text(
        string="Alert Recipient Emails",
        help="Comma or newline separated email list for brute-force alerts.",
    )
    alert_after = fields.Integer(
        string="Alert After Failed Attempts",
        default=5,
        help="Send alert when failed attempts exceed this value inside the time window.",
    )
    block_after = fields.Integer(
        string="Block After Failed Attempts",
        default=10,
        help="Block IP when failed attempts exceed this value inside the time window.",
    )
    failure_window_minutes = fields.Integer(
        string="Failure Window (minutes)",
        default=15,
        help="Only failed attempts inside this time window are counted.",
    )
    geo_enabled = fields.Boolean(
        string="Enable Geolocation Lookup",
        default=True,
        help="Look up country/city/ISP from public IP addresses.",
    )

    @api.constrains("alert_after", "block_after", "failure_window_minutes")
    def _check_thresholds(self):
        for rec in self:
            if rec.alert_after < 1:
                raise ValidationError(_("Alert threshold must be at least 1."))
            if rec.block_after < 1:
                raise ValidationError(_("Block threshold must be at least 1."))
            if rec.block_after <= rec.alert_after:
                raise ValidationError(_("Block threshold must be greater than alert threshold."))
            if rec.failure_window_minutes < 1:
                raise ValidationError(_("Failure window must be at least 1 minute."))

    @api.constrains("alert_email_to")
    def _check_alert_emails(self):
        for rec in self:
            value = (rec.alert_email_to or "").strip()
            if value and not email_split(value):
                raise ValidationError(_("Please provide at least one valid alert email address."))
