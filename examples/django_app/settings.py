# examples/django_app/settings.py — the smallest settings that can serve the upload views
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-change-me")
DEBUG = True
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "urls"
INSTALLED_APPS: list = []
MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]
DATABASES: dict = {}
USE_TZ = True
USE_I18N = False

MEDIA_ROOT = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads"))
DATA_UPLOAD_MAX_MEMORY_SIZE = 6 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 6 * 1024 * 1024
