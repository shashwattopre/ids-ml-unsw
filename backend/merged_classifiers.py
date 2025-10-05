
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
import os
import logging
import time
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest
from sklearn.base import BaseEstimator

logger = logging.getLogger(__name__)

# Configuration paths (backward compatible)
MODEL_PATH = os.getenv("MODEL_PATH", "./model/enhanced_pipeline.joblib")
SCHEMA_PATH = os.getenv("SCHEMA_PATH", "./model/enhanced_schema.json") 
FALLBACK_MODEL_PATH = "./model/pipeline.joblib"  # Original model fallback
FALLBACK_SCHEMA_PATH = "./model/feature_schema.json"  # Original schema fallback
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "0.90"))

class TwoStageClassifier:
    """Two-stage detection system with isolation forest + ensemble classifier"""

    def __init__(self):
        self.models = None
        self.schema = None
        self.feature_order = None
        self.is_enhanced = False
        self.load_models()

    def load_models(self):
        """Load models with fallback to original single-stage model"""
        try:
            # Try enhanced model first
            if os.path.exists(MODEL_PATH) and os.path.exists(SCHEMA_PATH):
                self.models = joblib.load(MODEL_PATH)
                with open(SCHEMA_PATH, "r") as f:
                    self.schema = json.load(f)
                if isinstance(self.models, dict) and "isolation_forest" in self.models:
                    self.is_enhanced = True
                    self.feature_order = self.schema["selected_features"]
                    logger.info("Loaded enhanced two-stage detection model")
                    return

            # Fallback to original model
            logger.warning("Enhanced model not found, falling back to original model")
            self.models = joblib.load(FALLBACK_MODEL_PATH)
            with open(FALLBACK_SCHEMA_PATH, "r") as f:
                self.schema = json.load(f)
            self.feature_order = self.schema["selected_features"]
            self.is_enhanced = False
            logger.info("Loaded original single-stage model")

        except Exception as e:
            logger.error(f"Failed to load any model: {e}")
            raise RuntimeError("No usable model found")

    def row_from_features(self, feats: Dict[str, Any]) -> list:
        """Extract feature row, handling missing features gracefully"""
        row = []
        for col in self.feature_order:
            if col in feats:
                row.append(feats[col])
            else:
                # Handle missing enhanced features with reasonable defaults
                if col in ["L7_PROTO"]:
                    row.append("UNKNOWN")
                elif col in ["SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT"]:
                    row.append(0.0)
                elif col in ["NUM_PKTS_UP_TO_128_BYTES"]:
                    row.append(0)
                elif col in ["MIN_TTL", "MAX_TTL"]:
                    row.append(64)  # Common default TTL
                elif col in ["SRC_TO_DST_IAT_AVG", "DST_TO_SRC_IAT_AVG"]:
                    row.append(0.0)
                else:
                    row.append(0)  # Generic default
                logger.debug(f"Missing feature {col}, using default")
        return row

    def predict_two_stage(self, feats: Dict[str, Any]) -> Tuple[int, float, Dict[str, float]]:
        """Two-stage prediction with detailed stage information"""
        try:
            X = pd.DataFrame([self.row_from_features(feats)], columns=self.feature_order)

            if self.is_enhanced:
                # Stage 1: Isolation Forest (fast anomaly screening)
                iso_forest = self.models["isolation_forest"]
                anomaly_score = iso_forest.decision_function(X)[0]
                is_outlier = iso_forest.predict(X)[0] == -1

                # Stage 2: Ensemble Classification (detailed classification)
                ensemble_clf = self.models["ensemble_classifier"]
                ensemble_proba = ensemble_clf.predict_proba(X)[0]
                malicious_prob = float(ensemble_proba[1]) if len(ensemble_proba) > 1 else float(ensemble_proba[0])

                # Combine stages: if isolation forest flags as anomaly, trust ensemble more
                if is_outlier:
                    combined_prob = 0.3 * abs(anomaly_score) + 0.7 * malicious_prob
                else:
                    combined_prob = malicious_prob * 0.5  # Reduce confidence if not flagged as outlier

            else:
                # Single stage fallback
                ensemble_proba = self.models.predict_proba(X)[0]
                combined_prob = float(ensemble_proba[1]) if len(ensemble_proba) > 1 else float(ensemble_proba[0])
                anomaly_score = 0.0

            final_label = int(combined_prob >= ALERT_THRESHOLD)

            stage_info = {
                "stage1_anomaly_score": float(anomaly_score),
                "stage2_malicious_prob": float(malicious_prob) if self.is_enhanced else float(combined_prob),
                "combined_probability": float(combined_prob),
                "model_type": "two_stage" if self.is_enhanced else "single_stage"
            }

            return final_label, combined_prob, stage_info

        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return 0, 0.5, {"error": str(e)}

# Global classifier instance
classifier_instance = None

def get_classifier():
    """Get global classifier instance with lazy loading"""
    global classifier_instance
    if classifier_instance is None:
        classifier_instance = TwoStageClassifier()
    return classifier_instance

# ==== ATTACK SIGNATURE DETECTION (MERGED FROM attack_detection.py) ====

class AttackSignatureDetector:
    """Enhanced attack detection with signature-based rules"""

    def __init__(self):
        self.time_window = 60
        self.flows = deque()
        self.source_stats = defaultdict(lambda: {
            'ports': set(),
            'destinations': set(), 
            'udp_count': 0,
            'tcp_count': 0,
            'bytes_total': 0,
            'packets_total': 0,
            'last_seen': 0,
            'malformed_count': 0
        })

        self.thresholds = {
            'port_scan': {
                'unique_ports_per_minute': 15,
                'destinations_per_minute': 5,
                'syn_ratio_threshold': 0.8
            },
            'udp_flood': {
                'udp_packets_per_second': 50,
                'udp_bytes_per_second': 30000,
                'single_port_ratio': 0.7
            },
            'fuzzer': {
                'malformed_ratio': 0.05,
                'unusual_size_count': 5,
                'invalid_combinations': 3
            }
        }

    def add_flow(self, feats: dict):
        """Add flow to sliding window for analysis"""
        current_time = feats.get('TIMESTAMP', time.time())

        # Clean old flows
        cutoff_time = current_time - self.time_window
        while self.flows and self.flows[0]['timestamp'] < cutoff_time:
            self.flows.popleft()

        # Add new flow
        flow_data = {
            'timestamp': current_time,
            'src_ip': feats.get('SRC_IP', ''),
            'dst_ip': feats.get('DST_IP', ''),
            'src_port': feats.get('L4_SRC_PORT', 0),
            'dst_port': feats.get('L4_DST_PORT', 0),
            'protocol': feats.get('PROTOCOL', ''),
            'tcp_flags': feats.get('TCP_FLAGS', ''),
            'packet_size': feats.get('IN_BYTES', 0) + feats.get('OUT_BYTES', 0),
            'packet_count': feats.get('IN_PKTS', 0) + feats.get('OUT_PKTS', 0)
        }

        self.flows.append(flow_data)
        self.update_source_stats(flow_data)

    def update_source_stats(self, flow: dict):
        """Update statistics for source IP"""
        src_ip = flow['src_ip']
        stats = self.source_stats[src_ip]

        stats['ports'].add(flow['dst_port'])
        stats['destinations'].add(flow['dst_ip'])
        stats['last_seen'] = flow['timestamp']
        stats['bytes_total'] += flow['packet_size']
        stats['packets_total'] += flow['packet_count']

        if flow['protocol'].upper() == 'UDP':
            stats['udp_count'] += 1
        elif flow['protocol'].upper() == 'TCP':
            stats['tcp_count'] += 1

        # Check for malformed packets
        if (flow['packet_size'] == 0 or flow['packet_size'] > 65535 or 
            flow['src_port'] == 0 or flow['dst_port'] == 0):
            stats['malformed_count'] += 1

    def detect_attacks(self, src_ip: str) -> Tuple[str, float]:
        """Detect specific attack types"""
        stats = self.source_stats.get(src_ip)
        if not stats:
            return 'unknown', 0.0

        # Port scan detection
        unique_ports = len(stats['ports'])
        if unique_ports >= self.thresholds['port_scan']['unique_ports_per_minute']:
            confidence = min(unique_ports / 20, 1.0)
            return 'port_scan', confidence

        # UDP flood detection  
        time_span = max(1, self.time_window)
        udp_rate = stats['udp_count'] / time_span
        if udp_rate >= self.thresholds['udp_flood']['udp_packets_per_second']:
            confidence = min(udp_rate / 100, 1.0)
            return 'udp_flood', confidence

        # Fuzzer detection
        total_packets = stats['tcp_count'] + stats['udp_count']
        if total_packets > 0:
            malformed_ratio = stats['malformed_count'] / total_packets
            if malformed_ratio >= self.thresholds['fuzzer']['malformed_ratio']:
                confidence = min(malformed_ratio / 0.2, 1.0)
                return 'fuzzer', confidence

        return 'unknown', 0.0

    def analyze_flow(self, feats: dict) -> dict:
        """Analyze flow for attack signatures"""
        self.add_flow(feats)

        src_ip = feats.get('SRC_IP', '')
        if not src_ip:
            return {'attack_detected': False, 'attack_type': 'unknown', 'confidence': 0.0}

        attack_type, confidence = self.detect_attacks(src_ip)

        return {
            'attack_detected': confidence > 0.3,
            'attack_type': attack_type,
            'confidence': confidence,
            'source_ip': src_ip
        }

# Global signature detector
signature_detector = AttackSignatureDetector()

def predict_with_stages(feats: Dict[str, Any]) -> Dict[str, Any]:
    """Enhanced prediction combining ML model with signature detection"""
    try:
        # Get ML model prediction (NO CIRCULAR IMPORT - using local get_classifier)
        classifier = get_classifier()
        ml_label, ml_prob, ml_stage_info = classifier.predict_two_stage(feats)

        # Get signature-based detection
        signature_analysis = signature_detector.analyze_flow(feats)

        # Combine predictions
        signature_detected = signature_analysis.get('attack_detected', False)
        signature_confidence = signature_analysis.get('confidence', 0)
        attack_type = signature_analysis.get('attack_type', 'unknown')

        # Enhanced decision logic
        if signature_detected and signature_confidence > 0.6:
            final_prob = max(ml_prob, 0.85 + signature_confidence * 0.1)
            final_label = 1
            detection_method = 'signature_primary'
        elif signature_detected and ml_prob > 0.7:
            final_prob = min(0.95, ml_prob + signature_confidence * 0.2)
            final_label = 1
            detection_method = 'hybrid'
        elif ml_prob > 0.85:
            final_prob = ml_prob
            final_label = ml_label
            detection_method = 'ml_primary'
        else:
            final_prob = ml_prob
            final_label = ml_label
            detection_method = 'ml_only'

        return {
            'prediction': final_label,
            'probability': final_prob,
            'alert': final_label == 1,
            'confidence': abs(final_prob - 0.5) * 2,
            'attack_type': attack_type if signature_detected else 'unknown',
            'detection_method': detection_method,
            'ml_details': {
                'probability': ml_prob,
                'stage_info': ml_stage_info
            },
            'signature_details': signature_analysis
        }

    except Exception as e:
        logger.error(f"Enhanced prediction failed: {e}")
        # Fallback to basic ML prediction
        try:
            classifier = get_classifier()
            ml_label, ml_prob, ml_stage_info = classifier.predict_two_stage(feats)
            return {
                'prediction': ml_label,
                'probability': ml_prob,
                'alert': ml_label == 1,
                'confidence': abs(ml_prob - 0.5) * 2,
                'attack_type': 'unknown',
                'detection_method': 'ml_fallback',
                'error': str(e)
            }
        except Exception as e2:
            logger.error(f"Fallback prediction also failed: {e2}")
            return {
                'prediction': 0,
                'probability': 0.5,
                'alert': False,
                'confidence': 0.0,
                'attack_type': 'unknown',
                'detection_method': 'error',
                'error': str(e2)
            }

# Backward compatibility
class ClassifierProxy:
    """Proxy class for backward compatibility"""
    def __getattr__(self, name):
        return getattr(get_classifier(), name)
    def __repr__(self):
        return f"CLASSIFIER proxy to {get_classifier()!r}"

CLASSIFIER = ClassifierProxy()
