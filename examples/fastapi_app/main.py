# examples/fastapi_app/main.py
import os
from pathlib import Path

from fastapi import Depends, FastAPI, File, UploadFile

from upload_guard import UploadGuard
from upload_guard.integrations.fastapi import Guarded, validate_upload

# ---- 1. 設定一次：允許的類型以「偵測到的真實類型」為準 -------------------------------
guard = UploadGuard(
    allowed=["image/*", "application/pdf", ".docx"],
    max_size=5 * 1024 * 1024,
    sanitize_svg=True,                        # SVG 會被消毒後接受，而不是整個拒絕
)

app = FastAPI()


def upload_dir() -> Path:
    path = Path(os.environ.get("UPLOAD_DIR", "uploads"))
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---- 2. 在 handler 內驗證：失敗時自動回 413 / 415 / 422 --------------------------------
@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    result = validate_upload(file, guard)     # raises HTTPException on rejection
    data = result.sanitized or await file.read()   # 消毒後的 SVG，否則原始內容（位置已還原）
    (upload_dir() / result.safe_filename).write_bytes(data)
    return {
        "mime": result.mime,
        "filename": result.safe_filename,
        "warnings": [f.code for f in result.warnings],
    }


# ---- 3. 或者當成 dependency：欄位名由 field= 決定 -----------------------------------------
@app.post("/avatar")
async def avatar(result=Depends(Guarded(guard, field="avatar"))):
    return {"mime": result.mime, "size": result.size}
