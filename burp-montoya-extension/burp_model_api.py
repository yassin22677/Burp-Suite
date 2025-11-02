# burp_model_api.py
# Defensive Flask API that accepts 7 raw features from Burp extension,
# and either: (A) if a preprocessor is saved with the model, pass the 7 raw cols
# through the preprocessor and predict; OR (B) if no preprocessor, expand to the
# engineered 47 features server-side and predict.

import os
import logging
import traceback
from flask import Flask, request, jsonify, make_response

# optional libs
try:
    import joblib
except Exception:
    joblib = None

try:
    import pandas as pd
except Exception:
    pd = None

import json
import numpy as np

# ==========================================================
# CONFIG
# ==========================================================
MODEL_PATH = os.path.join("ml_model", "best_adaboost_burp.joblib")
API_KEY = "my_secret_key_123"  # must match Java extension

# ==========================================================
# Logging + app
# ==========================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)
app = Flask(__name__)

# ==========================================================
# Hard-coded fallback engineered features (47) — used only if no preprocessor present
# Keep this list if your model expects these columns when no preprocessor exists.
EXPECTED_MODEL_FEATURES = [
    "num__status_code",
    "num__matched_rules_count",
    "cat__http_method_DELETE",
    "cat__http_method_GET",
    "cat__http_method_OPTIONS",
    "cat__http_method_PATCH",
    "cat__http_method_POST",
    "cat__http_method_PUT",
    "cat__attack_type_API Vulnerability",
    "cat__attack_type_Access Control Issue",
    "cat__attack_type_Authentication Flaw",
    "cat__attack_type_Business Logic Flaw",
    "cat__attack_type_CORS Misconfiguration",
    "cat__attack_type_CSRF",
    "cat__attack_type_Clickjacking",
    "cat__attack_type_Command Injection",
    "cat__attack_type_DOM-based Vulnerability",
    "cat__attack_type_Information Disclosure",
    "cat__attack_type_NoSQL Injection",
    "cat__attack_type_Path Traversal",
    "cat__attack_type_Race Condition",
    "cat__attack_type_SQL Injection",
    "cat__attack_type_SSRF",
    "cat__attack_type_Unrestricted File Upload",
    "cat__attack_type_Web Cache Deception",
    "cat__attack_type_WebSockets",
    "cat__attack_type_XSS",
    "cat__attack_type_XXE",
    "cat__attack_subtype_case-1",
    "cat__attack_subtype_case-10",
    "cat__attack_subtype_case-2",
    "cat__attack_subtype_case-3",
    "cat__attack_subtype_case-4",
    "cat__attack_subtype_case-5",
    "cat__attack_subtype_case-6",
    "cat__attack_subtype_case-7",
    "cat__attack_subtype_case-8",
    "cat__attack_subtype_case-9",
    "cat__attack_subtype_generic",
    "cat__severity_Critical",
    "cat__severity_High",
    "cat__severity_Low",
    "cat__severity_Medium",
    "cat__confidence_Certain",
    "cat__confidence_High",
    "cat__confidence_Low",
    "cat__confidence_Medium"
]

# ==========================================================
# LOAD MODEL (defensive)
# ==========================================================
bundle = {}
model = None
preprocessor = None
expected_feature_names = None

if joblib is None:
    logger.error("joblib is not installed. Please run: pip install joblib")
else:
    if not os.path.exists(MODEL_PATH):
        logger.error("Model file not found at %s", MODEL_PATH)
    else:
        try:
            bundle = joblib.load(MODEL_PATH)
            if isinstance(bundle, dict):
                model = bundle.get("model", None)
                preprocessor = bundle.get("preprocessor", None)
            else:
                model = bundle
            logger.info("✅ Model loaded successfully from %s", MODEL_PATH)
        except Exception:
            logger.exception("❌ Failed to load model from %s", MODEL_PATH)
            bundle = {}
            model = None

# Try to extract expected feature names from preprocessor (if present)
try:
    if preprocessor is not None:
        try:
            if hasattr(preprocessor, "get_feature_names_out"):
                names = preprocessor.get_feature_names_out()
                expected_feature_names = [str(x) for x in list(names)]
        except Exception:
            expected_feature_names = None
    # fallback to model.feature_names_in_ if available
    if model is not None and expected_feature_names is None and hasattr(model, "feature_names_in_"):
        expected_feature_names = [str(x) for x in list(model.feature_names_in_)]
except Exception:
    logger.exception("Error determining expected feature names")
    expected_feature_names = None

# If still None, but model exists and no preprocessor, we will use hard-coded engineered names
if expected_feature_names is None and preprocessor is None:
    expected_feature_names = EXPECTED_MODEL_FEATURES
    logger.info("Using fallback engineered expected feature names (count=%d).", len(expected_feature_names))

if expected_feature_names:
    logger.info("Model/preprocessor expects %d features (server will attempt to honor this).", len(expected_feature_names))
else:
    logger.warning("No expected feature names available; server will accept raw features only.")

# ==========================================================
# Helper to sanitize incoming raw features (7 expected keys)
# ==========================================================
def sanitize_raw_features(raw):
    sanitized = {}
    # ensure keys exist
    for k in ["status_code", "matched_rules_count", "http_method", "attack_type", "attack_subtype", "severity", "confidence"]:
        v = raw.get(k, None)
        if v is None:
            sanitized[k] = ""
        else:
            sanitized[k] = v
    # coerce numeric
    try:
        sanitized["status_code"] = int(sanitized.get("status_code", 0) or 0)
    except Exception:
        sanitized["status_code"] = 0
    try:
        sanitized["matched_rules_count"] = int(sanitized.get("matched_rules_count", 0) or 0)
    except Exception:
        sanitized["matched_rules_count"] = 0
    return sanitized

# ==========================================================
# If we don't have a preprocessor, build engineered one-hot features server-side
# ==========================================================
def build_engineered_features_from_raw(raw):
    # raw is sanitized dict (status_code int, matched_rules_count int, http_method str, attack_type str, attack_subtype str, severity str, confidence str)
    status_code = raw.get("status_code", 0)
    matched_rules_count = raw.get("matched_rules_count", 0)
    http_method = str(raw.get("http_method", "") or "")
    attack_type = str(raw.get("attack_type", "") or "")
    attack_subtype = str(raw.get("attack_subtype", "") or "")
    severity = str(raw.get("severity", "") or "")
    confidence = str(raw.get("confidence", "") or "")

    feat = {}
    for name in expected_feature_names:
        feat[name] = 0

    # numeric fields
    if "num__status_code" in feat:
        feat["num__status_code"] = int(status_code)
    if "num__matched_rules_count" in feat:
        feat["num__matched_rules_count"] = int(matched_rules_count)

    # method
    mk = f"cat__http_method_{http_method}"
    if mk in feat:
        feat[mk] = 1
    else:
        mu = f"cat__http_method_{http_method.upper()}"
        if mu in feat:
            feat[mu] = 1

    # attack type
    ak = f"cat__attack_type_{attack_type}"
    if ak in feat:
        feat[ak] = 1
    else:
        # try normalized
        ak2 = f"cat__attack_type_{attack_type.strip()}"
        if ak2 in feat:
            feat[ak2] = 1

    # subtype
    sk = f"cat__attack_subtype_{attack_subtype}"
    if sk in feat:
        feat[sk] = 1
    else:
        if "cat__attack_subtype_generic" in feat:
            feat["cat__attack_subtype_generic"] = 1

    # severity
    sevk = f"cat__severity_{severity}"
    if sevk in feat:
        feat[sevk] = 1
    else:
        if "cat__severity_Medium" in feat:
            feat["cat__severity_Medium"] = 1

    # confidence
    confk = f"cat__confidence_{confidence}"
    if confk in feat:
        feat[confk] = 1
    else:
        if "cat__confidence_Low" in feat:
            feat["cat__confidence_Low"] = 1

    return feat

# ==========================================================
# ROUTES
# ==========================================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "model_loaded": model is not None,
        "model_path": MODEL_PATH,
        "expected_feature_count": len(expected_feature_names) if expected_feature_names else None
    })


@app.route("/expected_features", methods=["GET"])
def expected_features_route():
    return jsonify({"expected_feature_names": expected_feature_names, "model_loaded": model is not None})


@app.route("/recommend", methods=["POST"])
def recommend():
    # AUTH
    req_key = request.headers.get("x-api-key")
    if API_KEY and req_key != API_KEY:
        logger.warning("Unauthorized request. Provided key: %s", req_key)
        return make_response(jsonify({"error": "unauthorized"}), 401)

    # dependencies
    if joblib is None:
        return make_response(jsonify({"error": "server_missing_dependency", "message": "joblib not installed"}), 500)
    if pd is None:
        return make_response(jsonify({"error": "server_missing_dependency", "message": "pandas not installed"}), 500)
    if model is None:
        return make_response(jsonify({"error": "model_not_loaded", "message": f"Model not loaded from {MODEL_PATH}"}), 500)

    # parse body
    try:
        data = request.get_json(force=True)
    except Exception as e:
        logger.exception("Failed to parse JSON body")
        return make_response(jsonify({"error": "invalid_json", "detail": str(e)}), 400)

    if not isinstance(data, dict):
        return make_response(jsonify({"error": "bad_payload", "detail": "payload must be a JSON object"}), 400)
    if "session_id" not in data:
        return make_response(jsonify({"error": "bad_payload", "detail": "missing session_id"}), 400)

    features = data.get("features", {})
    if not isinstance(features, dict):
        return make_response(jsonify({"error": "bad_payload", "detail": "features must be a JSON object"}), 400)

    # sanitize raw features (the 7 that your extension sends)
    try:
        raw = sanitize_raw_features(features)

        # If preprocessor exists, give it the raw columns it expects
        if preprocessor is not None:
            # build raw DataFrame with the exact raw column names your preprocessor expects
            # Most training pipelines expect these raw columns: status_code, matched_rules_count, http_method, attack_type, attack_subtype, severity, confidence
            raw_df = pd.DataFrame([{
                "status_code": raw["status_code"],
                "matched_rules_count": raw["matched_rules_count"],
                "http_method": raw["http_method"],
                "attack_type": raw["attack_type"],
                "attack_subtype": raw["attack_subtype"],
                "severity": raw["severity"],
                "confidence": raw["confidence"]
            }])

            # ensure column names are strings
            raw_df.columns = raw_df.columns.astype(str)

            try:
                X_proc = preprocessor.transform(raw_df)
                pred = model.predict(X_proc)
                try:
                    probs = model.predict_proba(X_proc)
                    confidence = float(probs.max(axis=1)[0])
                except Exception:
                    confidence = 0.0
            except Exception as e:
                tb = traceback.format_exc()
                logger.error("❌ Preprocessor transform failed: %s\n%s", e, tb)
                return make_response(jsonify({
                    "error": "preprocessor_transform_failed",
                    "message": str(e),
                    "traceback": tb.splitlines()[-40:]
                }), 500)

        else:
            # no preprocessor saved: expand into engineered 47 features and predict
            full_feat = build_engineered_features_from_raw(raw)
            X = pd.DataFrame([full_feat], columns=expected_feature_names)
            X = X.apply(pd.to_numeric, errors="coerce").fillna(0)
            try:
                pred = model.predict(X)
                try:
                    probs = model.predict_proba(X)
                    confidence = float(probs.max(axis=1)[0])
                except Exception:
                    confidence = 0.0
            except Exception as e:
                tb = traceback.format_exc()
                logger.error("❌ Model predict failed: %s\n%s", e, tb)
                return make_response(jsonify({
                    "error": "prediction_failed",
                    "message": str(e),
                    "traceback": tb.splitlines()[-40:]
                }), 500)

        # convert prediction value safely
        if hasattr(pred, "__len__"):
            pred_val = pred[0]
        else:
            pred_val = pred

        response = {
            "session_id": data.get("session_id"),
            "prediction": int(pred_val) if isinstance(pred_val, (int, float, bool)) else str(pred_val),
            "confidence": float(confidence),
            "model_version": bundle.get("model_version", "unknown") if isinstance(bundle, dict) else "unknown"
        }

        logger.info("✅ Prediction OK for %s: %s", data.get("session_id"), response)
        return jsonify(response)

    except Exception as e:
        tb = traceback.format_exc()
        logger.error("❌ Unexpected failure in recommend: %s\n%s", e, tb)
        return make_response(jsonify({
            "error": "unexpected_error",
            "message": str(e),
            "traceback": tb.splitlines()[-40:]
        }), 500)


# ==========================================================
# Run server
# ==========================================================
if __name__ == "__main__":
    logger.info("Starting model API on http://127.0.0.1:5001 (API_KEY required in header x-api-key)")
    app.run(host="127.0.0.1", port=5001, threaded=True)
