"""
Criminal Behavior AI - Ensemble Pattern Recognition Model
Apollo Platform v0.1.0

Multi-model ensemble for robust criminal behavior detection.
Combines LSTM, Transformer, and traditional ML models for maximum accuracy.
"""

import numpy as np
from typing import Dict, List, Optional, Tuple
import logging
from pathlib import Path
import joblib

# Traditional ML models
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
import xgboost as xgb
import lightgbm as lgb

# Deep learning models
from .lstm_model import CriminalBehaviorLSTM
from .transformer_model import CriminalBehaviorTransformer

logger = logging.getLogger(__name__)


class EnsembleVotingStrategy:
    """Voting strategies for ensemble predictions."""

    @staticmethod
    def majority_voting(predictions: List[int]) -> int:
        """Simple majority voting."""
        return int(np.median(predictions))

    @staticmethod
    def weighted_voting(
        predictions: List[int],
        weights: List[float]
    ) -> int:
        """Weighted voting based on model performance."""
        weighted_sum = sum(p * w for p, w in zip(predictions, weights))
        return int(weighted_sum > 0.5)

    @staticmethod
    def confidence_weighted_voting(
        predictions: List[Tuple[int, float]],
        weights: List[float]
    ) -> Tuple[int, float]:
        """
        Voting weighted by both model performance and prediction confidence.

        Args:
            predictions: List of (prediction, confidence) tuples
            weights: Model performance weights

        Returns:
            (final_prediction, combined_confidence)
        """
        weighted_probs = []
        total_weight = 0

        for (pred, conf), weight in zip(predictions, weights):
            # Convert prediction to probability
            prob = conf if pred == 1 else (1 - conf)
            weighted_probs.append(prob * weight)
            total_weight += weight

        avg_prob = sum(weighted_probs) / total_weight
        final_pred = int(avg_prob > 0.5)
        confidence = avg_prob if final_pred == 1 else (1 - avg_prob)

        return final_pred, confidence


class CriminalBehaviorEnsemble:
    """
    Ensemble model combining multiple architectures for criminal behavior detection.

    Combines:
    - LSTM: Temporal pattern detection
    - Transformer: Long-range dependencies
    - Gradient Boosting: Tabular feature patterns
    - Random Forest: Robust baseline
    - XGBoost: High-performance gradient boosting
    """

    def __init__(
        self,
        sequence_length: int = 30,
        num_features: int = 8,
        use_deep_learning: bool = True,
        use_traditional_ml: bool = True
    ):
        """
        Initialize ensemble model.

        Args:
            sequence_length: Length of input sequences
            num_features: Number of features
            use_deep_learning: Include LSTM and Transformer
            use_traditional_ml: Include traditional ML models
        """
        self.sequence_length = sequence_length
        self.num_features = num_features
        self.use_deep_learning = use_deep_learning
        self.use_traditional_ml = use_traditional_ml

        self.models = {}
        self.weights = {}
        self.voting_strategy = EnsembleVotingStrategy()

        logger.info(
            f"Initializing CriminalBehaviorEnsemble: "
            f"deep_learning={use_deep_learning}, "
            f"traditional_ml={use_traditional_ml}"
        )

        self._build_ensemble()

    def _build_ensemble(self) -> None:
        """Build all models in ensemble."""

        # Deep learning models
        if self.use_deep_learning:
            # LSTM model
            self.models['lstm'] = CriminalBehaviorLSTM(
                sequence_length=self.sequence_length,
                features=self.num_features,
                hidden_layers=[128, 64, 32],
                dropout_rate=0.3
            )
            self.weights['lstm'] = 0.25

            # Transformer model (for longer sequences)
            if self.sequence_length <= 1000:
                self.models['transformer'] = CriminalBehaviorTransformer(
                    max_sequence_length=self.sequence_length,
                    num_features=self.num_features,
                    embedding_dim=128,
                    num_heads=4,
                    num_layers=3
                )
                self.weights['transformer'] = 0.25

        # Traditional ML models (work on flattened features)
        if self.use_traditional_ml:
            # Gradient Boosting
            self.models['gradient_boosting'] = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )
            self.weights['gradient_boosting'] = 0.20

            # Random Forest
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            self.weights['random_forest'] = 0.15

            # XGBoost
            self.models['xgboost'] = xgb.XGBClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss'
            )
            self.weights['xgboost'] = 0.15

        # Normalize weights
        total_weight = sum(self.weights.values())
        self.weights = {k: v / total_weight for k, v in self.weights.items()}

        logger.info(f"Built ensemble with {len(self.models)} models")
        logger.info(f"Model weights: {self.weights}")

    def _prepare_features_for_traditional_ml(
        self,
        sequences: np.ndarray
    ) -> np.ndarray:
        """
        Prepare sequence data for traditional ML models.
        Flatten sequences and extract statistical features.

        Args:
            sequences: Input sequences (samples, sequence_length, features)

        Returns:
            Feature matrix for traditional ML
        """
        samples = sequences.shape[0]
        features_list = []

        for i in range(samples):
            seq = sequences[i]

            # Statistical features for each feature dimension
            features = []
            for feature_idx in range(seq.shape[1]):
                feature_vals = seq[:, feature_idx]

                features.extend([
                    np.mean(feature_vals),
                    np.std(feature_vals),
                    np.min(feature_vals),
                    np.max(feature_vals),
                    np.median(feature_vals),
                    np.percentile(feature_vals, 25),
                    np.percentile(feature_vals, 75)
                ])

            features_list.append(features)

        return np.array(features_list)

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        epochs: int = 50
    ) -> Dict:
        """
        Train all models in ensemble.

        Args:
            X_train: Training sequences
            y_train: Training labels
            X_val: Validation sequences
            y_val: Validation labels
            epochs: Number of epochs for deep learning models

        Returns:
            Training history for all models
        """
        logger.info(f"Training ensemble on {X_train.shape[0]} samples")
        histories = {}

        # Prepare traditional ML features
        if self.use_traditional_ml:
            X_train_flat = self._prepare_features_for_traditional_ml(X_train)
            if X_val is not None:
                X_val_flat = self._prepare_features_for_traditional_ml(X_val)

        # Train each model
        for name, model in self.models.items():
            logger.info(f"Training {name}...")

            try:
                if name in ['lstm', 'transformer']:
                    # Deep learning models
                    history = model.train(
                        X_train, y_train,
                        X_val, y_val,
                        epochs=epochs
                    )
                    histories[name] = history

                else:
                    # Traditional ML models
                    model.fit(X_train_flat, y_train)

                    # Evaluate on validation set
                    if X_val is not None:
                        val_score = model.score(X_val_flat, y_val)
                        logger.info(f"{name} validation accuracy: {val_score:.4f}")
                        histories[name] = {'val_accuracy': val_score}

                logger.info(f"✓ {name} trained successfully")

            except Exception as e:
                logger.error(f"Error training {name}: {e}")
                # Remove failed model from ensemble
                del self.models[name]
                del self.weights[name]

        # Re-normalize weights
        total_weight = sum(self.weights.values())
        self.weights = {k: v / total_weight for k, v in self.weights.items()}

        return histories

    def predict(
        self,
        sequence: np.ndarray,
        return_individual_predictions: bool = False,
        voting_strategy: str = 'confidence_weighted'
    ) -> Dict:
        """
        Predict using ensemble.

        Args:
            sequence: Input sequence
            return_individual_predictions: Return predictions from each model
            voting_strategy: 'majority', 'weighted', or 'confidence_weighted'

        Returns:
            Ensemble prediction dictionary
        """
        if sequence.ndim == 2:
            sequence = np.expand_dims(sequence, axis=0)

        predictions = []
        confidences = []
        individual_results = {}

        # Get predictions from deep learning models
        for name in ['lstm', 'transformer']:
            if name in self.models:
                result = self.models[name].predict_criminal_behavior(sequence)
                pred = int(result['is_criminal'])
                conf = result['confidence']

                predictions.append(pred)
                confidences.append(conf)
                individual_results[name] = result

        # Get predictions from traditional ML models
        if self.use_traditional_ml:
            seq_flat = self._prepare_features_for_traditional_ml(sequence)

            for name in ['gradient_boosting', 'random_forest', 'xgboost']:
                if name in self.models:
                    pred = int(self.models[name].predict(seq_flat)[0])

                    # Get probability if available
                    if hasattr(self.models[name], 'predict_proba'):
                        proba = self.models[name].predict_proba(seq_flat)[0]
                        conf = float(max(proba))
                    else:
                        conf = 0.7  # Default confidence

                    predictions.append(pred)
                    confidences.append(conf)
                    individual_results[name] = {
                        'is_criminal': bool(pred),
                        'confidence': conf
                    }

        # Ensemble voting
        if voting_strategy == 'majority':
            final_pred = self.voting_strategy.majority_voting(predictions)
            final_conf = np.mean(confidences)

        elif voting_strategy == 'weighted':
            weights = [self.weights[name] for name in individual_results.keys()]
            final_pred = self.voting_strategy.weighted_voting(predictions, weights)
            final_conf = np.mean(confidences)

        else:  # confidence_weighted
            pred_conf_pairs = list(zip(predictions, confidences))
            weights = [self.weights[name] for name in individual_results.keys()]
            final_pred, final_conf = self.voting_strategy.confidence_weighted_voting(
                pred_conf_pairs, weights
            )

        result = {
            'is_criminal': bool(final_pred),
            'confidence': float(final_conf),
            'risk_level': self.calculate_risk_level(final_conf),
            'ensemble_size': len(predictions),
            'voting_strategy': voting_strategy
        }

        if return_individual_predictions:
            result['individual_predictions'] = individual_results

        return result

    def calculate_risk_level(self, confidence: float) -> str:
        """Calculate risk level from confidence."""
        if confidence < 0.3:
            return "LOW"
        elif confidence < 0.6:
            return "MEDIUM"
        elif confidence < 0.85:
            return "HIGH"
        else:
            return "CRITICAL"

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray
    ) -> Dict:
        """
        Evaluate ensemble performance.

        Args:
            X_test: Test sequences
            y_test: Test labels

        Returns:
            Evaluation metrics
        """
        predictions = []

        for sequence, label in zip(X_test, y_test):
            result = self.predict(sequence)
            predictions.append(int(result['is_criminal']))

        predictions = np.array(predictions)

        # Calculate metrics
        accuracy = np.mean(predictions == y_test)

        # Precision, Recall, F1
        tp = np.sum((predictions == 1) & (y_test == 1))
        fp = np.sum((predictions == 1) & (y_test == 0))
        fn = np.sum((predictions == 0) & (y_test == 1))
        tn = np.sum((predictions == 0) & (y_test == 0))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1_score),
            'true_positives': int(tp),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_negatives': int(tn)
        }

        logger.info(f"Ensemble evaluation: {metrics}")

        return metrics

    def save(self, directory: str) -> None:
        """Save ensemble models."""
        save_dir = Path(directory)
        save_dir.mkdir(parents=True, exist_ok=True)

        # Save deep learning models
        for name in ['lstm', 'transformer']:
            if name in self.models:
                model_path = save_dir / f"{name}_model"
                self.models[name].save(str(model_path))

        # Save traditional ML models
        for name in ['gradient_boosting', 'random_forest', 'xgboost']:
            if name in self.models:
                model_path = save_dir / f"{name}_model.joblib"
                joblib.dump(self.models[name], model_path)

        # Save weights
        weights_path = save_dir / "ensemble_weights.joblib"
        joblib.dump(self.weights, weights_path)

        logger.info(f"Ensemble saved to {directory}")

    def load(self, directory: str) -> None:
        """Load ensemble models."""
        load_dir = Path(directory)

        # Load deep learning models
        for name in ['lstm', 'transformer']:
            model_path = load_dir / f"{name}_model"
            if model_path.exists() and name in self.models:
                self.models[name].load(str(model_path))

        # Load traditional ML models
        for name in ['gradient_boosting', 'random_forest', 'xgboost']:
            model_path = load_dir / f"{name}_model.joblib"
            if model_path.exists() and name in self.models:
                self.models[name] = joblib.load(model_path)

        # Load weights
        weights_path = load_dir / "ensemble_weights.joblib"
        if weights_path.exists():
            self.weights = joblib.load(weights_path)

        logger.info(f"Ensemble loaded from {directory}")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    # Create sample data
    X_train = np.random.randn(1000, 30, 8)
    y_train = np.random.randint(0, 2, 1000)
    X_test = np.random.randn(200, 30, 8)
    y_test = np.random.randint(0, 2, 200)

    # Train ensemble
    ensemble = CriminalBehaviorEnsemble()
    ensemble.train(X_train, y_train, epochs=10)

    # Predict
    test_sequence = np.random.randn(30, 8)
    result = ensemble.predict(
        test_sequence,
        return_individual_predictions=True,
        voting_strategy='confidence_weighted'
    )
    print(f"Ensemble prediction: {result}")

    # Evaluate
    metrics = ensemble.evaluate(X_test, y_test)
    print(f"Evaluation metrics: {metrics}")
