"""Thin framework adapters. Import the submodule you need::

    from upload_guard.integrations.fastapi import Guarded
    from upload_guard.integrations.django import UploadGuardValidator
    from upload_guard.integrations.flask import validate_upload
"""
from ._http import http_status_for, problem_detail

__all__ = ["http_status_for", "problem_detail"]
