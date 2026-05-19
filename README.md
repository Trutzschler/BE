# CS4150 Blockchain Engineering

Run
```bash
uv run assignment-2/main.py
```
to run the code for assignment 1.
The code mines a nonce (or uses a precomputed one) with a configurable
difficulty target (28 by default),
and uses this to send the submission message to the server.
Before running the code make sure to create a `.env` file containing the
following (see `.env.sample`):
- `EMAIL`: included in the submission message.
- `GITHUB_URL`: included in the submission message.
- `KEY_FILE`: path to store the private key (`.pem` file) for this client.
- `PRECOMPUTED_NONCE` (optional): precomputed nonce to avoid mining when re-running the code.

## Assignment 2
To run assignment 2, run

```bash
uv run assignment-2/main.py
```

The `.env` file should contain:
- `TEAMMATES`: public keys (hexadecimal) of teammates. Order does not matter, as they will be sorted anyway.
- `GROUP_ID`: group id (optional).
- `KEY_FILE`: path to store the private key (`.pem` file) for this client.
