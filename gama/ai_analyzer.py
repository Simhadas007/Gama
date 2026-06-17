from transformers import pipeline

classifier = pipeline(
    "text-classification",
    model="martin-ha/toxic-comment-model"
)

def ai_risk_analysis(text):
    try:
        result = classifier(text[:1000])

        return {
            "label": result[0]["label"],
            "score": float(result[0]["score"])
        }

    except Exception as e:
        return {
            "label": "UNKNOWN",
            "score": 0,
            "error": str(e)
        }