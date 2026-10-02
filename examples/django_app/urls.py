# examples/django_app/urls.py
import views
from django.urls import path

urlpatterns = [
    path("upload/form", views.upload_form),
    path("upload/api", views.upload_api),
]
