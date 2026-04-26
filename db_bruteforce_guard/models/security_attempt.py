import ipaddress
import json
import logging
from datetime import timedelta
import urllib.error
import urllib.request

from odoo import _, api, fields, models
from odoo.exceptions import AccessDenied
from odoo.http import request
from odoo.tools import email_split, html_escape

_logger = logging.getLogger(__name__)


class DbGuardAttempt(models.Model):
    _name = "db.guard.attempt"
    _description = "Brute Force Attempt"
    _order = "create_date desc"

    state_id = fields.Many2one("db.guard.ip.state", string="IP State", index=True, ondelete="set null")
    status = fields.Selection([
        ("failed", "Failed"),
        ("blocked", "Blocked"),
        ("success", "Success"),
    ], required=True, default="failed", index=True)
    login = fields.Char(index=True)
    database = fields.Char(string="Database", index=True)
    ip_address = fields.Char(required=True, index=True)
    route = fields.Char()
    method = fields.Char()
    user_agent = fields.Char()
    forwarded_for = fields.Char()
    accept_language = fields.Char()
    browser = fields.Char()
    os_name = fields.Char(string="OS")
    device_type = fields.Char()
    country = fields.Char()
    region = fields.Char()
    city = fields.Char()
    timezone = fields.Char()
    latitude = fields.Float(digits=(10, 5))
    longitude = fields.Float(digits=(10, 5))
    isp = fields.Char()
    organization = fields.Char()
    details_json = fields.Text()


class DbGuardIPState(models.Model):
    _name = "db.guard.ip.state"
    _description = "Brute Force IP State"
    _rec_name = "ip_address"
    _order = "last_seen desc"

    ip_address = fields.Char(required=True, index=True)
    failure_count = fields.Integer(default=0)
    first_seen = fields.Datetime(default=fields.Datetime.now)
    last_seen = fields.Datetime(default=fields.Datetime.now)
    blocked = fields.Boolean(default=False, index=True)
    blocked_at = fields.Datetime()
    alert_sent = fields.Boolean(default=False)
    last_login = fields.Char()
    country = fields.Char()
    city = fields.Char()
    region = fields.Char()
    timezone = fields.Char()
    isp = fields.Char()
    organization = fields.Char()

    _sql_constraints = [
        ("db_guard_ip_unique", "unique(ip_address)", "The IP address already exists."),
    ]

    def action_unblock(self):
        for rec in self:
            rec.write({"blocked": False, "blocked_at": False, "failure_count": 0, "alert_sent": False})


class DbGuardService(models.AbstractModel):
    _name = "db.guard.service"
    _description = "Brute Force Protection Service"

    @api.model
    def _config(self):
        config = self.env["db.guard.config"].sudo().search([("active", "=", True)], limit=1, order="id desc")
        if not config:
            config = self.env["db.guard.config"].sudo().search([], limit=1, order="id desc")
        return config

    @api.model
    def _config_int(self, field_name, default, min_value=1):
        config = self._config()
        raw = config[field_name] if config else default
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = default
        return max(value, min_value)

    @api.model
    def _threshold_alert(self):
        return self._config_int("alert_after", 5)

    @api.model
    def _threshold_block(self):
        return self._config_int("block_after", 10)

    @api.model
    def _failure_window_minutes(self):
        return self._config_int("failure_window_minutes", 15)

    @api.model
    def _geo_enabled(self):
        config = self._config()
        return bool(config.geo_enabled) if config else True

    @api.model
    def _client_ip(self):
        if not request:
            return "n/a"
        forwarded_for = (request.httprequest.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return forwarded_for or request.httprequest.remote_addr or "n/a"

    @api.model
    def _device_meta(self):
        if not request:
            return {}
        headers = request.httprequest.headers
        user_agent = headers.get("User-Agent", "")
        ua_lower = user_agent.lower()

        device_type = "Desktop"
        if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
            device_type = "Mobile"
        elif "ipad" in ua_lower or "tablet" in ua_lower:
            device_type = "Tablet"

        browser = "Unknown"
        browser_tokens = [
            ("edg/", "Edge"),
            ("chrome/", "Chrome"),
            ("firefox/", "Firefox"),
            ("safari/", "Safari"),
            ("opr/", "Opera"),
        ]
        for token, label in browser_tokens:
            if token in ua_lower:
                browser = label
                break

        os_name = "Unknown"
        os_tokens = [
            ("windows", "Windows"),
            ("mac os", "macOS"),
            ("linux", "Linux"),
            ("android", "Android"),
            ("iphone", "iOS"),
        ]
        for token, label in os_tokens:
            if token in ua_lower:
                os_name = label
                break

        return {
            "route": request.httprequest.path,
            "method": request.httprequest.method,
            "user_agent": user_agent,
            "forwarded_for": headers.get("X-Forwarded-For"),
            "accept_language": headers.get("Accept-Language"),
            "browser": browser,
            "os_name": os_name,
            "device_type": device_type,
        }

    @api.model
    def _geo_lookup(self, ip_address):
        if not ip_address or ip_address == "n/a" or not self._geo_enabled():
            return {}
        try:
            if ipaddress.ip_address(ip_address).is_private:
                return {}
        except ValueError:
            return {}

        endpoint = f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,timezone,lat,lon,isp,org"
        try:
            req = urllib.request.Request(endpoint, headers={"User-Agent": "odoo-db-guard/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if payload.get("status") != "success":
                return {}
            return {
                "country": payload.get("country"),
                "region": payload.get("regionName"),
                "city": payload.get("city"),
                "timezone": payload.get("timezone"),
                "latitude": payload.get("lat") or 0.0,
                "longitude": payload.get("lon") or 0.0,
                "isp": payload.get("isp"),
                "organization": payload.get("org"),
            }
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            _logger.debug("Geo lookup failed for IP %s: %s", ip_address, exc)
            return {}

    @api.model
    def _ensure_not_blocked(self, login=None):
        ip = self._client_ip()
        state = self.env["db.guard.ip.state"].sudo().search([("ip_address", "=", ip)], limit=1)
        if state and state.blocked:
            self._create_attempt_record(
                ip,
                status="blocked",
                login=login,
                state=state,
                extra={"reason": "blocked_ip"},
            )
            # Keep blocked-attempt evidence even though AccessDenied ends the request.
            self.env.cr.commit()
            raise AccessDenied(_("Your IP address has been blocked after too many failed attempts."))

    @api.model
    def _record_success(self, login=None, database=None):
        ip = self._client_ip()
        state = self.env["db.guard.ip.state"].sudo().search([("ip_address", "=", ip)], limit=1)
        if state and not state.blocked:
            state.write({"failure_count": 0, "alert_sent": False, "last_seen": fields.Datetime.now(), "last_login": login or state.last_login})
        self._create_attempt_record(ip, status="success", login=login, state=state, database=database)

    @api.model
    def _record_failure(self, login=None, database=None):
        ip = self._client_ip()
        state_model = self.env["db.guard.ip.state"].sudo()
        state = state_model.search([("ip_address", "=", ip)], limit=1)
        now = fields.Datetime.now()
        window_start = now - timedelta(minutes=self._failure_window_minutes())
        geo = self._geo_lookup(ip)

        if not state:
            values = {
                "ip_address": ip,
                "failure_count": 1,
                "first_seen": now,
                "last_seen": now,
                "last_login": login,
            }
            values.update({k: v for k, v in geo.items() if k in state_model._fields})
            state = state_model.create(values)
        else:
            vals = {
                "last_seen": now,
                "last_login": login or state.last_login,
            }
            for key in ("country", "region", "city", "timezone", "isp", "organization"):
                if geo.get(key):
                    vals[key] = geo[key]
            state.write(vals)

        self._create_attempt_record(ip, status="failed", login=login, state=state, database=database, geo=geo)

        recent_failures = self.env["db.guard.attempt"].sudo().search_count([
            ("ip_address", "=", ip),
            ("status", "=", "failed"),
            ("create_date", ">=", window_start),
        ])

        state_updates = {"failure_count": recent_failures}
        if recent_failures < self._threshold_alert():
            state_updates["alert_sent"] = False

        if recent_failures >= self._threshold_block() and not state.blocked:
            state_updates.update({"blocked": True, "blocked_at": now})

        state.write(state_updates)
        self._maybe_send_alert(state)
        # Failed logins raise AccessDenied upstream; commit so attempts/state/mail are not rolled back.
        self.env.cr.commit()

    @api.model
    def _create_attempt_record(self, ip, status, login=None, state=None, database=None, extra=None, geo=None):
        meta = self._device_meta()
        geo = geo or {}
        payload = {
            "status": status,
            "login": login,
            "database": database or (request.db if request else "n/a"),
            "ip_address": ip,
            "state_id": state.id if state else False,
            **meta,
            "country": geo.get("country") or (state.country if state else False),
            "region": geo.get("region") or (state.region if state else False),
            "city": geo.get("city") or (state.city if state else False),
            "timezone": geo.get("timezone") or (state.timezone if state else False),
            "latitude": geo.get("latitude") or 0.0,
            "longitude": geo.get("longitude") or 0.0,
            "isp": geo.get("isp") or (state.isp if state else False),
            "organization": geo.get("organization") or (state.organization if state else False),
        }
        details = {
            "route": payload.get("route"),
            "method": payload.get("method"),
            "forwarded_for": payload.get("forwarded_for"),
            "accept_language": payload.get("accept_language"),
            "extra": extra or {},
        }
        payload["details_json"] = json.dumps(details, ensure_ascii=True)
        self.env["db.guard.attempt"].sudo().create(payload)

    @api.model
    def _alert_recipients(self):
        config = self._config()
        configured = (config.alert_email_to or "").strip() if config else ""
        if configured:
            return email_split(configured)

        admins = self.env.ref("base.group_system").users.filtered(lambda u: u.email)
        return list(dict.fromkeys(admins.mapped("email")))

    @api.model
    def _alert_sender(self):
        sender = self.env.company.email_formatted or self.env.user.email_formatted
        if sender:
            return sender
        return "noreply@localhost"

    @api.model
    def _maybe_send_alert(self, state):
        alert_after = self._threshold_alert()
        should_alert = state.failure_count >= alert_after and not state.alert_sent
        just_blocked = state.failure_count >= self._threshold_block() and state.blocked
        if not should_alert and not just_blocked:
            return

        recipients = self._alert_recipients()
        if not recipients:
            _logger.warning("db_bruteforce_guard: no alert recipients configured")
            return

        last_attempt = self.env["db.guard.attempt"].sudo().search([("state_id", "=", state.id)], limit=1, order="id desc")
        blocked_msg = "YES" if state.blocked else "NO"

        body_html = """
            <p>Security alert: repeated failed login attempts detected.</p>
            <ul>
                <li><strong>IP:</strong> {ip}</li>
                <li><strong>Blocked:</strong> {blocked}</li>
                <li><strong>Failed attempts:</strong> {count}</li>
                <li><strong>Last login tried:</strong> {login}</li>
                <li><strong>Route:</strong> {route}</li>
                <li><strong>Method:</strong> {method}</li>
                <li><strong>Device:</strong> {device}</li>
                <li><strong>Browser:</strong> {browser}</li>
                <li><strong>OS:</strong> {os_name}</li>
                <li><strong>Country/City:</strong> {country} / {city}</li>
                <li><strong>Region:</strong> {region}</li>
                <li><strong>Timezone:</strong> {timezone}</li>
                <li><strong>ISP:</strong> {isp}</li>
                <li><strong>Organization:</strong> {org}</li>
            </ul>
        """.format(
            ip=html_escape(state.ip_address or ""),
            blocked=blocked_msg,
            count=state.failure_count,
            login=html_escape(state.last_login or "n/a"),
            route=html_escape(last_attempt.route or "n/a"),
            method=html_escape(last_attempt.method or "n/a"),
            device=html_escape(last_attempt.device_type or "n/a"),
            browser=html_escape(last_attempt.browser or "n/a"),
            os_name=html_escape(last_attempt.os_name or "n/a"),
            country=html_escape(state.country or "n/a"),
            city=html_escape(state.city or "n/a"),
            region=html_escape(state.region or "n/a"),
            timezone=html_escape(state.timezone or "n/a"),
            isp=html_escape(state.isp or "n/a"),
            org=html_escape(state.organization or "n/a"),
        )

        try:
            mail = self.env["mail.mail"].sudo().create({
                "subject": _("[Security] Brute-force attempts from %s") % (state.ip_address,),
                "email_to": ",".join(recipients),
                "email_from": self._alert_sender(),
                "body_html": body_html,
            })
            mail.send(raise_exception=False)
        except Exception as exc:
            _logger.warning("db_bruteforce_guard: failed to create/send alert email: %s", exc)
            return

        if should_alert:
            state.write({"alert_sent": True})
