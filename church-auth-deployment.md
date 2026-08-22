# Church WebUI Authentication Deployment Guide

This guide covers deploying multi-user authentication with Google OIDC and GitHub OAuth for your church staff.

## 1. Prerequisites

- Hermes WebUI fork at v0.52+ with auth_users.py and updated auth routes
- Python 3.11+
- Access to manage OAuth applications in your church's Google Workspace and/or GitHub organization
- HTTPS reverse proxy (recommended) or SSH tunnel access

## 2. Configuration Environment Variables

Set these environment variables before starting the server:

```bash
# Enable passwordless authentication
HERMES_WEBUI_PASSWORD=disabled

# Google OIDC Configuration (required if using Google login)
HERMES_WEBUI_GOOGLE_CLIENT_ID="your-client-id"
HERMES_WEBUI_GOOGLE_CLIENT_SECRET="your-client-secret"
# Optional: Restrict to specific Google Workspace domain
d # HERMES_WEBUI_GOOGLE_DOMAIN="church.org"

# GitHub OAuth Configuration (required if using GitHub login)
HERMES_WEBUI_GITHUB_CLIENT_ID="your-client-id"
HERMES_WEBUI_GITHUB_CLIENT_SECRET="your-client-secret"
# Required: Your church's GitHub organization name
d # HERMES_WEBUI_GITHUB_ORG="your-church-org"

# First Admin Bootstrap (one must be configured)
# Option A: Google email
HERMES_WEBUI_BOOTSTRAP_ADMIN_EMAIL="admin@church.org"
# OR Option B: GitHub numeric user ID
# HERMES_WEBUI_BOOTSTRAP_ADMIN_USER_ID="12345678"

# Default profiles that all users get assigned
HERMES_WEBUI_DEFAULT_PROFILES="default,church-staff"
```

## 3. OAuth Application Setup

### Google OIDC Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project or select existing one
3. Navigate to "APIs & Services" → "Credentials"
4. Click "Create Credentials" → "OAuth client ID"
5. Application type: "Web application"
6. Name: `Hermes Church Admin`
7. Add authorized redirect URIs:
   - `https://your-domain.com/api/auth/google/callback`
   - `http://localhost:8787/api/auth/google/callback` (for testing)
8. Copy Client ID and Client Secret to environment variables

### GitHub OAuth Setup

1. Go to your GitHub organization settings
2. Navigate to "Developer settings" → "OAuth Apps"
3. Click "New OAuth App"
4. Application name: `Hermes Church Admin`
5. Homepage URL: `https://your-domain.com`
6. Authorization callback URL: `https://your-domain.com/api/auth/github/callback`
7. Save and copy Client ID and Client Secret to environment variables

## 4. First Admin Bootstrap

On first startup with an empty user store:

1. The system will check for bootstrap configuration
2. Only one bootstrap method allowed (Google email OR GitHub ID, not both)
3. When someone authenticates with the matching identity, they become the first admin
4. After first admin creation, bootstrap variables are ignored

> **Security Note**: Bootstrap only works when no users exist. Once bootstrapped, add additional admins through the admin interface.

## 5. User Management Workflow

### Adding New Staff Members

**Method A: Invitation (Recommended)**

1. Admin goes to Settings → User Management
2. Click "Invite Member"
3. Enter Google email or GitHub username
4. System sends single-use invitation link
5. Invitee clicks link and authenticates with their provider
6. Account created with member role

**Method B: Self-Registration (If enabled)**

1. Configure `HERMES_WEBUI_AUTO_CREATE_MEMBER=true`
2. Any staff member can authenticate with Google/GitHub
3. Automatically created as member role

### Promoting to Admin

1. Admin goes to Settings → User Management
2. Find user and click "Edit"
3. Change role from "member" to "admin"
4. Save

> **Safety Check**: Cannot demote/remove the last admin

## 6. Roles and Permissions

### Admin Role
- Full access to all features
- Can manage other users (create, edit, disable)
- Can use all Hermes profiles
- Can create scheduled tasks
- Can view audit logs

### Member Role
- Access only to explicitly assigned profiles
- No user management capabilities
- Cannot create scheduled tasks
- Cannot access sensitive system information

## 7. Profile Assignment

Profiles control what tools and data a user can access:

```python
# Example profile assignments
user_profiles = {
    "pastor": ["default", "sermons", "counseling-private"],
    "finance": ["default", "budget", "receipts"],
    "volunteer-coordinator": ["default", "events"]
}
```

> **Important**: Users can only access files and tools within their assigned profiles. Always assign the `default` profile for basic functionality.

## 8. Security Considerations

### Data Isolation
- Shared profiles are intentionally shared
- For private work (pastoral counseling, finance), use separate isolated profiles
- Never share credentials between profiles

### Session Security
- Sessions use signed HTTP-only cookies (24h TTL)
- All sensitive endpoints require CSRF protection
- Provider tokens are never stored
- Identity claims are validated on every request

### Audit Trail
- All user actions are logged with timestamp and identity
- Login attempts are recorded
- Profile changes are audited

## 9. Testing the Deployment

1. Start the server with your configuration
2. Access the login page at `/login`
3. Verify Google and GitHub buttons appear
4. Test first admin bootstrap with your configured identity
5. Log in as admin and verify you can access user management
6. Invite a test user and verify they can log in with member permissions
7. Test profile isolation by attempting to access unauthorized profiles

## 10. Troubleshooting

### Common Issues

**Issue**: Login buttons don't appear
- Check environment variables are set correctly
- Verify OAuth app redirect URIs match exactly
- Ensure `HERMES_WEBUI_PASSWORD=disabled`

**Issue**: Bootstrap fails
- Verify user store is empty (`~/.hermes/webui/.auth_users.json`)
- Check bootstrap email/ID matches exactly
- Confirm default profiles exist

**Issue**: Users can't access assigned profiles
- Verify profile names match exactly (case-sensitive)
- Check the profile exists in the system
- Ensure the user has been assigned the profile

**Issue**: GitHub authentication fails
- Verify organization name is correct
- Check user is a member of the organization
- Confirm OAuth app has necessary permissions

## 11. Maintenance

### Regular Tasks

- Review active users monthly
- Revoke access for departed staff immediately
- Audit profile assignments quarterly
- Update OAuth secrets annually

### Backup Strategy

Backup these critical files:
- `~/.hermes/webui/.auth_users.json` (user identities and roles)
- `~/.hermes/webui/.auth_users.lock` (authentication lock file)
- Your custom `config.yaml` files

> **Disaster Recovery**: Keep encrypted backups of user store in multiple locations

## 12. Support

For issues with this implementation:
- Check server logs at `~/.hermes/webui.log`
- Verify environment variables with `printenv | grep HERMES_WEBUI`
- Test OAuth endpoints directly with curl
- Contact support with error messages and relevant configuration (redact secrets)