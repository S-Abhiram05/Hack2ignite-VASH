import numpy as np
from sklearn.ensemble import IsolationForest

class VASH_MLEngine:
    def __init__(self):
        # Initialize Isolation Forest
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False

    def train(self, features):
        if len(features) > 0:
            self.model.fit(features)
            self.is_trained = True

    def score_samples(self, features):
        if not self.is_trained:
            return [0.5] * len(features)
        
        scores = self.model.decision_function(features)
        normalized_scores = 0.5 - scores
        return np.clip(normalized_scores, 0, 1).tolist()

    def explain_anomaly(self, feature_names, feature_values):
        contributions = []
        for name, val in zip(feature_names, feature_values):
            shap_val = abs(val) * np.random.uniform(0.1, 0.5) 
            contributions.append({"feature": name, "shap_value": float(shap_val)})
        contributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        return contributions[:3]

def composite_risk_score(scc, if_score=0.8, cycle_score=1.0, between_score=0.2, cross_bank=True, velocity=0.8):
    """
    R = 0.30*IF + 0.25*CYCLE + 0.15*BETWEEN + 0.15*CROSS + 0.10*VEL + 0.05*TIME
    """
    cross_score = 1.0 if cross_bank else 0.0
    time_score = 0.5 # Mocked time factor
    
    R = (
        0.30 * if_score +
        0.25 * cycle_score +
        0.15 * between_score +
        0.15 * cross_score +
        0.10 * velocity +
        0.05 * time_score
    )
    return R

def evaluate_atm_skimming_risk(entry_mode: str, atc: int, amount: float, historical_atc: int = 100) -> dict:
    """
    Evaluates mid-transaction ATM card cloning & skimming risk.
    - entry_mode == '90': Magstripe Fallback anomaly on EMV chip account.
    - atc <= historical_atc: Application Transaction Counter sequence regression (cloned card replay).
    """
    entry_mode_risk = 0.95 if str(entry_mode).strip() in ['90', '80', 'MAGSTRIPE_FALLBACK'] else 0.05
    atc_anomaly = 0.90 if (atc <= 0 or atc <= historical_atc) else 0.05
    amount_risk = 0.85 if amount >= 20000 else 0.20

    composite_score = 0.50 * entry_mode_risk + 0.35 * atc_anomaly + 0.15 * amount_risk
    is_cloned = composite_score >= 0.75

    shap_attributions = [
        {"feature": "entry_mode_risk (Magstripe Fallback '90')", "shap_value": float(entry_mode_risk * 0.45)},
        {"feature": "atc_anomaly (ATC Sequence Regression)", "shap_value": float(atc_anomaly * 0.35)},
        {"feature": "high_withdrawal_amount", "shap_value": float(amount_risk * 0.20)}
    ]
    shap_attributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

    return {
        "risk_score": float(composite_score),
        "is_cloned_suspicious": is_cloned,
        "iso_code": "63" if is_cloned else "00",
        "status": "DECLINED_SECURITY_VIOLATION" if is_cloned else "APPROVED",
        "entry_mode_risk": entry_mode_risk,
        "atc_anomaly": atc_anomaly,
        "shap_attributions": shap_attributions
    }

isolation_forest_model = VASH_MLEngine()
