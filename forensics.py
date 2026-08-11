"""
Document Forgery Detector - core forensics engine
Implements:
  1. Error Level Analysis (ELA)
  2. EXIF metadata inspection
  3. Copy-move forgery detection (ORB keypoint matching)
Returns a combined suspicion score + heatmap overlay.
"""

import io
import os
import numpy as np
import cv2
from PIL import Image, ImageChops, ExifTags

#recompress check

def compute_ela(image_path, quality=90, scale=15):

    original = Image.open(image_path).convert("RGB")

    buffer = io.BytesIO()
    original.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    resaved = Image.open(buffer)

    diff = ImageChops.difference(original, resaved)
    diff_arr = np.array(diff).astype(np.float32)

    # amplify for visibility
    max_diff = diff_arr.max() if diff_arr.max() > 0 else 1
    ela_arr = np.clip(diff_arr * (255.0 * scale / max_diff), 0, 255).astype(np.uint8)
    ela_image = Image.fromarray(ela_arr)

    # score: how much of the image has abnormally high error (proxy for tampering)
    gray_diff = cv2.cvtColor(diff_arr.astype(np.uint8), cv2.COLOR_RGB2GRAY)
    threshold = gray_diff.mean() + 2 * gray_diff.std()
    hot_pixels = np.sum(gray_diff > threshold)
    ela_score = min(100.0, (hot_pixels / gray_diff.size) * 1000)

    return ela_image, round(float(ela_score), 2), gray_diff


# ---------- 2. Metadata inspection
SOFTWARE_FLAGS = ["photoshop", "gimp", "paint.net", "pixlr", "canva", "snapseed"]


def check_metadata(image_path):
  
    result = {"flags": [], "exif": {}}
    score = 0

    try:
        img = Image.open(image_path)
        exif_data = img._getexif() if hasattr(img, "_getexif") else None

        if exif_data is None:
            result["flags"].append("No EXIF metadata found (common in screenshots/edited exports)")
            score += 20
        else:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                result["exif"][str(tag)] = str(value)

            software = str(result["exif"].get("Software", "")).lower()
            if software:
                for flag in SOFTWARE_FLAGS:
                    if flag in software:
                        result["flags"].append(f"Edited with '{result['exif']['Software']}'")
                        score += 40
                        break

            # datetime consistency check
            dt_original = result["exif"].get("DateTimeOriginal")
            dt_modified = result["exif"].get("DateTime")
            if dt_original and dt_modified and dt_original != dt_modified:
                result["flags"].append("Modification timestamp differs from original capture time")
                score += 25
    except Exception as e:
        result["flags"].append(f"Could not fully parse metadata: {e}")
        score += 10

    result["metadata_score"] = min(100, score)
    return result


#  3. Copy-move forgery detection

def detect_copy_move(image_path, match_ratio=0.75, min_matches=8):

    img = cv2.imread(image_path)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    orb = cv2.ORB_create(nfeatures=2000)
    kp, des = orb.detectAndCompute(gray, None)

    annotated = img.copy()
    if des is None or len(kp) < min_matches:
        return 0.0, [], annotated

    bf = cv2.BFMatcher(cv2.NORM_HAMMING)
    matches = bf.knnMatch(des, des, k=3)  # k=3 because best match to itself is always distance 0

    suspicious_pairs = []
    for m in matches:
        if len(m) < 3:
            continue
        # m[0] is always the point matched to itself (distance 0), so compare m[1] vs m[2]
        best, second = m[1], m[2]
        if best.distance < match_ratio * second.distance:
            pt1 = kp[best.queryIdx].pt
            pt2 = kp[best.trainIdx].pt
            dist_px = np.linalg.norm(np.array(pt1) - np.array(pt2))
            if dist_px > 25:  # ignore near-duplicate neighboring keypoints
                suspicious_pairs.append((pt1, pt2))

    for pt1, pt2 in suspicious_pairs:
        p1 = tuple(map(int, pt1))
        p2 = tuple(map(int, pt2))
        cv2.circle(annotated, p1, 6, (0, 0, 255), 2)
        cv2.circle(annotated, p2, 6, (0, 0, 255), 2)
        cv2.line(annotated, p1, p2, (0, 255, 255), 1)

    score = min(100.0, len(suspicious_pairs) * 3.5)
    return round(score, 2), suspicious_pairs, annotated


# ---------- Combined verdict ----------

def analyze_document(image_path):
    ela_image, ela_score, ela_diff = compute_ela(image_path)
    meta_result = check_metadata(image_path)
    cm_score, cm_pairs, cm_annotated = detect_copy_move(image_path)

    # weighted combination
    final_score = round(
        0.45 * ela_score + 0.25 * meta_result["metadata_score"] + 0.30 * cm_score, 2
    )

    if final_score >= 60:
        verdict = "LIKELY FORGED"
    elif final_score >= 30:
        verdict = "SUSPICIOUS - Manual review recommended"
    else:
        verdict = "LIKELY AUTHENTIC"

    return {
        "verdict": verdict,
        "final_score": final_score,
        "ela_score": ela_score,
        "metadata_score": meta_result["metadata_score"],
        "copy_move_score": cm_score,
        "flags": meta_result["flags"],
        "copy_move_pairs_found": len(cm_pairs),
        "_ela_image": ela_image,
        "_cm_annotated": cm_annotated,
    }
