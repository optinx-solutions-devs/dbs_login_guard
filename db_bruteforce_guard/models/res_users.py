from odoo import models
from odoo.exceptions import AccessDenied


class ResUsers(models.Model):
    _inherit = "res.users"

    def _login(self, credential, user_agent_env):
        guard = self.env["db.guard.service"].sudo()
        login = credential.get("login")

        guard._ensure_not_blocked(login=login)
        try:
            auth_info = super()._login(credential, user_agent_env)
        except AccessDenied:
            guard._record_failure(login=login, database=self.env.cr.dbname)
            raise

        guard._record_success(login=login, database=self.env.cr.dbname)
        return auth_info
