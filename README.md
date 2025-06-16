# AWS SAM OAuth 2.0 service
Had some fun learning about OAuth 2.0 spec and thought I'd use that as an opportunity to create my first AWS SAM project. 

This supports both public and private clients. This also supports authorization code flow for private clients and PKCE with public client.

- Signup and login by email and password.

## To add a client...
- Just add a row to the clients table.
- Set `client_id` to something of your choice.
- Set `redirect_uris` as a "String Set" containing all accepted redirect uris.
- Optionally, add a `client_secret` column as a "String" if you want a private client, otherwise, it'll be public and force PKCE.
