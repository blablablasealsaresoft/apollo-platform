"""
Criminal Behavior AI - Cryptocurrency Criminal Pattern Model
Apollo Platform v0.1.0

Train model to detect cryptocurrency criminal patterns including:
- Money laundering
- Exchange fraud
- Mixing service abuse
- Structured transactions
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Optional, Tuple
import logging
from pathlib import Path
import yaml

# Model imports
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from models.pattern_recognition.lstm_model import CryptoCriminalLSTM
from models.pattern_recognition.ensemble_model import CriminalBehaviorEnsemble

logger = logging.getLogger(__name__)


class CryptoCriminalPatternModel:
    """
    Train model to detect cryptocurrency criminal patterns.

    Features:
    - Transaction frequency patterns
    - Amount distributions
    - Wallet diversity
    - Mixing service usage
    - Exchange interaction patterns
    - Withdrawal timing
    - Geographic dispersion
    - Counterparty risk assessment
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize crypto criminal pattern model.

        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)

        self.features = [
            'transaction_frequency',
            'transaction_amounts',
            'wallet_diversity',
            'mixing_service_usage',
            'exchange_patterns',
            'withdrawal_timing',
            'geographic_dispersion',
            'counterparty_risk'
        ]

        self.scaler = StandardScaler()
        self.model = None

        logger.info("Initialized CryptoCriminalPatternModel")

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / 'config' / 'model-config.yaml'

        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        return config['models']['crypto_criminal']

    def load_training_data(self, data_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load and preprocess training data.

        Args:
            data_path: Path to training data

        Returns:
            (X, y): Features and labels
        """
        logger.info(f"Loading training data from {data_path}")

        # Load data (assuming parquet format)
        df = pd.read_parquet(data_path)

        logger.info(f"Loaded {len(df)} samples")

        # Extract features
        X = df[self.features].values
        y = df['is_criminal'].values

        # Handle class imbalance
        criminal_count = np.sum(y == 1)
        legitimate_count = np.sum(y == 0)
        imbalance_ratio = legitimate_count / criminal_count

        logger.info(
            f"Class distribution: "
            f"Criminal={criminal_count}, "
            f"Legitimate={legitimate_count}, "
            f"Ratio={imbalance_ratio:.2f}"
        )

        if imbalance_ratio > 3:
            logger.warning(f"Class imbalance detected (ratio: {imbalance_ratio:.2f})")

        return X, y

    def prepare_sequences(
        self,
        X: np.ndarray,
        sequence_length: int = 30
    ) -> np.ndarray:
        """
        Prepare sequential data for LSTM training.

        Args:
            X: Feature matrix
            sequence_length: Length of sequences

        Returns:
            Sequential data (samples, sequence_length, features)
        """
        logger.info(f"Preparing sequences of length {sequence_length}")

        num_samples = X.shape[0] - sequence_length + 1
        num_features = X.shape[1]

        sequences = np.zeros((num_samples, sequence_length, num_features))

        for i in range(num_samples):
            sequences[i] = X[i:i+sequence_length]

        logger.info(f"Created {num_samples} sequences")

        return sequences

    def train(
        self,
        training_data_path: str,
        model_type: str = 'ensemble',
        use_cross_validation: bool = True,
        save_model: bool = True
    ) -> Dict:
        """
        Train cryptocurrency criminal detection model.

        Args:
            training_data_path: Path to training data
            model_type: 'lstm' or 'ensemble'
            use_cross_validation: Use k-fold cross-validation
            save_model: Save trained model

        Returns:
            Training metrics
        """
        logger.info(f"Training {model_type} model for crypto crime detection")

        # Load data
        X, y = self.load_training_data(training_data_path)

        # Prepare sequences
        sequence_length = self.config.get('sequence_length', 30)
        X_seq = self.prepare_sequences(X, sequence_length)
        y_seq = y[sequence_length-1:]  # Align labels with sequences

        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_seq, y_seq,
            test_size=0.2,
            random_state=42,
            stratify=y_seq
        )

        # Further split for validation
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train,
            test_size=0.2,
            random_state=42,
            stratify=y_train
        )

        logger.info(
            f"Data split: "
            f"Train={len(X_train)}, "
            f"Val={len(X_val)}, "
            f"Test={len(X_test)}"
        )

        # Initialize model
        if model_type == 'lstm':
            self.model = CryptoCriminalLSTM()
        else:
            self.model = CriminalBehaviorEnsemble(
                sequence_length=sequence_length,
                num_features=len(self.features)
            )

        # Train model
        if use_cross_validation:
            cv_metrics = self._cross_validate(X_train, y_train)
            logger.info(f"Cross-validation results: {cv_metrics}")

        # Final training
        history = self.model.train(
            X_train, y_train,
            X_val, y_val,
            epochs=self.config.get('epochs', 100),
            batch_size=32
        )

        # Evaluate on test set
        test_metrics = self.model.evaluate(X_test, y_test)

        logger.info(f"Test set performance: {test_metrics}")

        # Save model
        if save_model:
            model_dir = Path(__file__).parent.parent.parent / 'models' / 'trained'
            model_dir.mkdir(parents=True, exist_ok=True)
            model_path = model_dir / f'crypto_criminal_{model_type}'
            self.model.save(str(model_path))
            logger.info(f"Model saved to {model_path}")

        return {
            'training_history': history,
            'test_metrics': test_metrics,
            'model_type': model_type
        }

    def _cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        k_folds: int = 5
    ) -> Dict:
        """
        Perform k-fold cross-validation.

        Args:
            X: Features
            y: Labels
            k_folds: Number of folds

        Returns:
            Cross-validation metrics
        """
        logger.info(f"Performing {k_folds}-fold cross-validation")

        skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)

        fold_metrics = []

        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            logger.info(f"Training fold {fold + 1}/{k_folds}")

            X_train_fold = X[train_idx]
            y_train_fold = y[train_idx]
            X_val_fold = X[val_idx]
            y_val_fold = y[val_idx]

            # Create temporary model for this fold
            temp_model = CryptoCriminalLSTM()
            temp_model.train(
                X_train_fold, y_train_fold,
                X_val_fold, y_val_fold,
                epochs=20  # Fewer epochs for CV
            )

            # Evaluate
            metrics = temp_model.evaluate(X_val_fold, y_val_fold)
            fold_metrics.append(metrics)

        # Aggregate metrics
        cv_results = {
            'mean_accuracy': np.mean([m['accuracy'] for m in fold_metrics]),
            'std_accuracy': np.std([m['accuracy'] for m in fold_metrics]),
            'mean_precision': np.mean([m['precision'] for m in fold_metrics]),
            'mean_recall': np.mean([m['recall'] for m in fold_metrics]),
            'mean_f1': np.mean([m.get('f1_score', 0) for m in fold_metrics])
        }

        return cv_results

    def detect_money_laundering(
        self,
        wallet_behavior: Dict
    ) -> Dict:
        """
        Detect money laundering patterns in wallet behavior.

        Args:
            wallet_behavior: Dictionary containing wallet behavioral features

        Returns:
            Detection result with confidence and patterns
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")

        # Extract features
        features = np.array([
            wallet_behavior.get(f, 0.0) for f in self.features
        ])

        # Prepare sequence (assuming single time step for now)
        sequence = features.reshape(1, -1)

        # Pad to sequence length if needed
        sequence_length = self.config.get('sequence_length', 30)
        if sequence.shape[1] < sequence_length * len(self.features):
            # Repeat last observation
            padding_needed = sequence_length - 1
            sequence = np.repeat(features.reshape(1, 1, -1), sequence_length, axis=1)

        # Predict
        prediction = self.model.predict_criminal_behavior(sequence)

        # Identify specific patterns
        patterns = self._identify_patterns(wallet_behavior)

        # Recommend action
        action = self._recommend_action(prediction['probability'], patterns)

        return {
            'is_laundering': prediction['is_criminal'],
            'confidence': prediction['confidence'],
            'probability': prediction['probability'],
            'risk_level': prediction['risk_level'],
            'patterns_detected': patterns,
            'recommended_action': action,
            'threshold': 0.85  # High threshold for money laundering
        }

    def _identify_patterns(self, wallet_behavior: Dict) -> List[str]:
        """
        Identify specific criminal patterns in wallet behavior.

        Args:
            wallet_behavior: Wallet behavioral features

        Returns:
            List of detected patterns
        """
        patterns = []

        # Check for structuring
        if wallet_behavior.get('transaction_amounts', 0) < 10000 and \
           wallet_behavior.get('transaction_frequency', 0) > 10:
            patterns.append('STRUCTURING')

        # Check for mixing service usage
        if wallet_behavior.get('mixing_service_usage', 0) > 0:
            patterns.append('MIXING_SERVICES')

        # Check for rapid movement
        if wallet_behavior.get('exchange_patterns', 0) > 5:
            patterns.append('RAPID_EXCHANGE_MOVEMENT')

        # Check for geographic dispersion
        if wallet_behavior.get('geographic_dispersion', 0) > 0.7:
            patterns.append('GEOGRAPHIC_LAYERING')

        # Check for high-risk counterparties
        if wallet_behavior.get('counterparty_risk', 0) > 0.6:
            patterns.append('HIGH_RISK_COUNTERPARTIES')

        # Check for unusual withdrawal timing
        if wallet_behavior.get('withdrawal_timing', 0) > 0.8:
            patterns.append('COORDINATED_WITHDRAWALS')

        return patterns

    def _recommend_action(
        self,
        probability: float,
        patterns: List[str]
    ) -> str:
        """
        Recommend investigation action based on detection.

        Args:
            probability: Money laundering probability
            patterns: Detected patterns

        Returns:
            Recommended action
        """
        critical_patterns = ['MIXING_SERVICES', 'STRUCTURING']
        has_critical = any(p in patterns for p in critical_patterns)

        if probability > 0.95 or (probability > 0.85 and has_critical):
            return "IMMEDIATE_INVESTIGATION"
        elif probability > 0.75:
            return "ENHANCED_MONITORING"
        elif probability > 0.60:
            return "INCREASED_SCRUTINY"
        else:
            return "ROUTINE_MONITORING"


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    # Initialize model
    model = CryptoCriminalPatternModel()

    # Train (with synthetic data path)
    # results = model.train(
    #     'training/datasets/crypto-criminal-patterns/training_data.parquet',
    #     model_type='ensemble'
    # )

    # Detect money laundering
    wallet_behavior = {
        'transaction_frequency': 15,
        'transaction_amounts': 9500,
        'wallet_diversity': 25,
        'mixing_service_usage': 1,
        'exchange_patterns': 8,
        'withdrawal_timing': 0.9,
        'geographic_dispersion': 0.8,
        'counterparty_risk': 0.7
    }

    # result = model.detect_money_laundering(wallet_behavior)
    # print(f"Money laundering detection: {result}")
