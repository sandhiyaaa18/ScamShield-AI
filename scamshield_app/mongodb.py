from pymongo import MongoClient
from datetime import datetime


MONGO_URI = "mongodb://localhost:27017/"

client = MongoClient(MONGO_URI)

db = client["scamshield_db"]

scam_logs = db["scam_logs"]


def save_scam_log(
    user_id,
    input_type,
    input_data,
    result,
    risk_score,
    detection_reasons
):
    log = {
        "user_id": str(user_id),
        "input_type": input_type,
        "input": input_data,
        "result": result,
        "risk_score": risk_score,
        "detection_reasons": detection_reasons,
        "timestamp": datetime.utcnow()
    }

    result = scam_logs.insert_one(log)

    return result.inserted_id