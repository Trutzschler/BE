# CS4150 Blockchain Engineering

Run `main.py` to run the code for assignment 1.
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
