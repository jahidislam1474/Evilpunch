Comparison with Other Certificate Directories:

| Directory | Purpose | Content | Persistence |
| :--- | :--- | :--- | :--- |
| `runtime_certs/` | Runtime SSL certificates | Dynamic certificates from DB | Temporary |
| `certs/` | Default certificates | Static fallback certificates | Permanent |
| `server_ssl/` | Server configuration | Server-specific SSL settings | Permanent |
