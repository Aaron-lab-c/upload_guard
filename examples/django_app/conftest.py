# examples/django_app/conftest.py — configure Django for the tests without pytest-django
import os

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()
