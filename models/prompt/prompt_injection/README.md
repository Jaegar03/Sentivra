# Prompt-injection classifier: not trained

The deepset/prompt-injections dataset (Apache-2.0) is downloaded, but no model is trained, and the prompt-injection detector isn't wired (POST /api/v1/analyze/prompt answers 501).

This folder is tracked so the model registry lists the model as `trained: false` (Models page, `GET /api/v1/models`) on every checkout. A model becomes available only when its training script writes `metadata.json` with the artifact's SHA-256 next to the artifact.
