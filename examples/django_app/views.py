# examples/django_app/views.py
from pathlib import Path

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from upload_guard import UploadGuard
from upload_guard.integrations.django import UploadGuardValidator, validate_upload

# ---- 1. 設定一次 --------------------------------------------------------------------
guard = UploadGuard(allowed=["image/*", "application/pdf"], max_size=5 * 1024 * 1024)


# ---- 2a. 表單 / Model 欄位：掛 validator，錯誤進 form.errors ------------------------------
class UploadForm(forms.Form):
    file = forms.FileField(validators=[UploadGuardValidator(guard)])


@csrf_exempt            # 範例用；真實專案請走 CSRF token 或 API key 驗證
@require_POST
def upload_form(request):
    form = UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        return JsonResponse({"errors": form.errors.get_json_data()}, status=400)
    f = form.cleaned_data["file"]
    result = guard.scan(f)                                  # 取得 ScanResult（消毒結果、安全檔名）
    _store(result, f)
    return JsonResponse({"mime": result.mime, "filename": result.safe_filename})


# ---- 2b. 直接在 view 內驗證：失敗時拋 ValidationError -------------------------------------
@csrf_exempt
@require_POST
def upload_api(request):
    f = request.FILES["file"]
    try:
        result = validate_upload(f, guard)
    except ValidationError as exc:
        return JsonResponse({"errors": [{"code": e.code, "message": e.message} for e in exc.error_list]}, status=400)
    _store(result, f)
    return JsonResponse({"mime": result.mime, "filename": result.safe_filename, "warnings": [w.code for w in result.warnings]})


def _store(result, uploaded):
    root = Path(settings.MEDIA_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    data = result.sanitized if result.sanitized is not None else uploaded.read()   # 位置已還原
    (root / result.safe_filename).write_bytes(data)
