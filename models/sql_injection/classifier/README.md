# SQL injection classifier: not trained

SecLists SQLi payload lists (MIT) are downloaded as positives. No benign corpus has been chosen, and no model is trained. The SQL lexer and normalizer groundwork is in backend/app/detectors/sqli/.

This folder is tracked so the model registry lists the model as `trained: false` (Models page, `GET /api/v1/models`) on every checkout. A model becomes available only when its training script writes `metadata.json` with the artifact's SHA-256 next to the artifact.
