# examples/flask_app/app.py
import os
from pathlib import Path

from flask import Flask, jsonify, request

from upload_guard import UploadGuard
from upload_guard.integrations.flask import validate_upload

# ---- 1. 設定一次 --------------------------------------------------------------------
guard = UploadGuard(allowed=["image/*", "application/pdf"], max_size=5 * 1024 * 1024)


def create_app(upload_dir=None):
    app = Flask(__name__)
    app.config["UPLOAD_DIR"] = Path(upload_dir or os.environ.get("UPLOAD_DIR", "uploads"))
    app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024   # 第一道防線：Werkzeug 直接擋掉超大請求

    # ---- 2. 驗證失敗時 validate_upload 會 abort(413/415/422)，Flask 回對應錯誤頁 -------------
    @app.post("/upload")
    def upload():
        f = request.files["file"]
        result = validate_upload(f, guard)
        app.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)
        target = app.config["UPLOAD_DIR"] / result.safe_filename   # 永遠用消毒後的檔名
        if result.sanitized is not None:
            target.write_bytes(result.sanitized)                     # 消毒後的 SVG
        else:
            f.save(target)                                           # 串流位置已還原，可直接存
        return jsonify(mime=result.mime, filename=result.safe_filename, warnings=[w.code for w in result.warnings])

    # ---- 3. 想自己決定回應格式：用 scan() 取得完整結果 -------------------------------------------
    @app.post("/check")
    def check():
        result = guard.scan(request.files["file"])
        return jsonify(result.to_dict()), (200 if result.ok else 400)

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
