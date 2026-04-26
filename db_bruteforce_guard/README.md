# Database Brute Force Guard

Database Brute Force Guard enhances Odoo authentication security by detecting repeated failed login attempts from the same IP address, sending alerts, and automatically blocking suspicious IPs.

## Key Features

- Track failed, successful, and blocked login attempts
- Rolling failure window per IP address
- Automatic IP block after configurable threshold
- Alert email notifications for suspicious activity
- Request metadata capture (route, method, browser, OS, device)
- Optional geolocation enrichment (country, city, ISP, organization)
- Back-office security audit views for attempts and IP states
- Manual unblock action for blocked IPs

## Configuration

1. Go to: Settings -> Login Security -> Configuration
2. Configure:
   - Failure Window (minutes)
   - Alert After Failed Attempts
   - Block After Failed Attempts
   - Alert Recipient Emails
   - Enable Geolocation Lookup

## Functional Flow

1. Every login request is checked against IP block list
2. If blocked, access is denied and event is logged as "blocked"
3. If login fails, failure count is recomputed inside rolling window
4. On threshold breach, alert email is sent
5. On higher threshold breach, IP is blocked automatically
6. If login succeeds, failure counter for that IP is reset

## Access Rights

- Security Attempts: read-only for system administrators
- IP States: read/write/create for system administrators
- Configuration: read/write/create for system administrators

## Dependencies

- base
- mail
- web

## Version

- Odoo: 19.0
- Module: 19.0.1.0.0

## Support

For support or customizations: optinassist@gmail.com
