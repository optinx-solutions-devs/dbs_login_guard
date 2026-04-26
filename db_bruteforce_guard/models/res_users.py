from odoo import SUPERUSER_ID, api, models
from odoo.exceptions import AccessDenied


class ResUsers(models.Model):
    _inherit = "res.users"

    @classmethod
    def _login(cls, db, credential, user_agent_env):
        login = credential.get("login")

        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            guard = env["db.guard.service"].sudo()
            guard._ensure_not_blocked(login=login)

        try:
            auth_info = super()._login(db, credential, user_agent_env)
        except AccessDenied:
            with cls.pool.cursor() as cr:
                env = api.Environment(cr, SUPERUSER_ID, {})
                env["db.guard.service"].sudo()._record_failure(login=login, database=db)
            raise

        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            env["db.guard.service"].sudo()._record_success(login=login, database=db)
        return auth_info
