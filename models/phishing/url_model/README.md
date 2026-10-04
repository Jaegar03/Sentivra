# Phishing URL model: not trained

The PhiUSIIL dataset (CC BY 4.0) is downloaded by research/datasets/fetch_datasets.py, but no model is trained. See the dataset notes in docs/model-card.md: its labels are inverted and its legitimate class is homepages only.

This folder is tracked so the model registry lists the model as `trained: false` (Models page, `GET /api/v1/models`) on every checkout. A model becomes available only when its training script writes `metadata.json` with the artifact's SHA-256 next to the artifact.
