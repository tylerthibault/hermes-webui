# Deploy profile-scoped Matrix Channels on Coolify

This branch adds **Settings → Channels → Matrix** to Hermes WebUI. Matrix credentials, allowlists, gateway processes, sessions, and status are isolated by the active Hermes profile.

## Before deployment

1. Back up the persistent Hermes volume mounted at:

   ```text
   /home/hermeswebui/.hermes
   ```

2. Keep the current Coolify service and its storage definitions. Do not create a new empty Hermes volume.
3. Push this branch to a repository Coolify can access.

## Coolify configuration

Point the existing Hermes WebUI service at this repository and branch.

- **Build pack:** Dockerfile
- **Dockerfile:** `/Dockerfile`
- **Exposed port:** `8787`
- **Health endpoint:** `/health`
- **Required persistent mount:** existing Hermes data volume → `/home/hermeswebui/.hermes`
- **Workspace mount:** existing workspace volume → `/workspace`

Keep the existing Quick Install environment variables, including:

```text
HERMES_WEBUI_HOST=0.0.0.0
HERMES_WEBUI_PORT=8787
HERMES_WEBUI_STATE_DIR=/home/hermeswebui/.hermes/webui
```

The image installs `libolm` and the complete Hermes 0.15.1 Matrix/E2EE Python dependency set. The mounted Hermes Agent source must remain available at:

```text
/home/hermeswebui/.hermes/hermes-agent
```

## Optional: create Matrix accounts from Channels

Synapse must have `registration_shared_secret` configured in `homeserver.yaml`. Do **not** copy that secret into the WebUI/Coolify environment or any Hermes profile: WebUI agents run in-process, so durable process secrets are not an appropriate isolation boundary.

Configure the non-secret WebUI operator environment variable below with one exact HTTPS origin (no path or trailing slash), then redeploy:

```dotenv
HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER=https://matrix.example.org
```

The provisioning endpoint rejects every requested homeserver that is not an exact match. The registration shared secret must never be placed in an environment variable; it remains a one-time masked form value.

Then select an unconfigured Hermes profile and open **Settings → Channels → Matrix**. Enter:

1. The HTTPS Matrix homeserver origin.
2. A new Matrix password of at least 12 characters.
3. At least one explicitly allowed Matrix user.
4. Synapse's registration shared secret in the masked **one-time** field.

Choose **Create Matrix account**. The backend locks account creation to the lowercase active Hermes profile name and hard-codes `admin: false`; profile `bookkeeper` may create only Matrix username `bookkeeper`. The registration secret is used only to calculate Synapse's nonce HMAC. It is cleared from the browser after submission, never sent to Synapse, never returned by the API, and never written to profile storage. The new account's Matrix ID and password are saved only to the active profile.

Then choose **Save & Restart Gateway** to connect. If creation fails, the one-time secret remains cleared and must be entered again. If the shared secret is ever disclosed, rotate it in Synapse before using provisioning again.

## Deploy and verify

1. Redeploy the existing Coolify service from this branch.
2. Wait for `/health` to return HTTP 200.
3. Confirm container logs include:

   ```text
   Profile channel gateway supervisor started
   ```

4. Open Hermes WebUI and select the `maverick` profile.
5. Go to **Settings → Channels → Matrix**.
6. Enter Maverick's Matrix homeserver, user ID, and write-only credential.
7. Add only explicitly authorized Matrix users. Start with:

   ```text
   @tyler:thibaultsolutions.com
   ```

8. Leave **Allowed rooms** blank for the first direct-message test, keep **Require mention** enabled for rooms, and select **E2EE required**.
9. Choose **Save & Restart Gateway**.
10. Confirm the status badge changes to **Running**.
11. Invite Maverick only to a new, non-sensitive test room and verify:
    - An unauthorized user receives no response.
    - An authorized user can receive a response.
    - Room messages require a mention.
    - Direct-message and room sessions remain separate.
    - Restarting the Coolify container restores the enabled Maverick gateway.

Only after these checks should Maverick be invited into the family room.

## Rollback

1. Select the previous Coolify deployment/image.
2. Redeploy without deleting or replacing `/home/hermeswebui/.hermes`.
3. If necessary, disable Matrix before rollback with **Disconnect**. This stops the managed profile gateway and removes only Matrix-specific profile values.

The feature preserves unrelated `.env` and `config.yaml` content. Matrix secrets are never returned by the API and are stored with file mode `0600`.
