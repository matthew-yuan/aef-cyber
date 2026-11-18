"""One-time, resumable chat-model availability scan. Makes real, small inference calls."""
from webapp.models import scan_models

if __name__ == "__main__":
    scan_models()
