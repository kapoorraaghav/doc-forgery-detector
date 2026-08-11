import os
import uuid
import cv2
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from forensics import analyze_document

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
RESULT_DIR = os.path.join(BASE_DIR, "static", "results")
ALLOWED_EXT = {"png", "jpg", "jpeg"}

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("document")
    if not file or file.filename == "":
        return redirect(url_for("index"))
    if not allowed_file(file.filename):
        return "Unsupported file type. Use PNG or JPG.", 400

    uid = uuid.uuid4().hex[:8]
    filename = f"{uid}_{secure_filename(file.filename)}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)

    result = analyze_document(filepath)

    ela_filename = f"{uid}_ela.png"
    cm_filename = f"{uid}_copymove.png"
    result["_ela_image"].save(os.path.join(RESULT_DIR, ela_filename))
    cv2.imwrite(os.path.join(RESULT_DIR, cm_filename), result["_cm_annotated"])

    return render_template(
        "result.html",
        original=f"uploads/{filename}",
        ela_img=f"results/{ela_filename}",
        cm_img=f"results/{cm_filename}",
        verdict=result["verdict"],
        final_score=result["final_score"],
        ela_score=result["ela_score"],
        metadata_score=result["metadata_score"],
        copy_move_score=result["copy_move_score"],
        flags=result["flags"],
        cm_pairs=result["copy_move_pairs_found"],
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
