"""
Criminal Behavior AI - LSTM Pattern Recognition Model
Apollo Platform v0.1.0

LSTM-based sequence modeling for criminal behavior pattern detection.
Specializes in temporal behavioral sequences and progression analysis.
"""

import tensorflow as tf
from tensorflow.keras import layers, models, callbacks
import numpy as np
from typing import Dict, List, Tuple, Optional
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class CriminalBehaviorLSTM:
    """
    LSTM model for behavioral sequence modeling and criminal pattern detection.

    Optimized for:
    - Temporal behavior sequences
    - Progressive pattern detection
    - Multi-step behavior forecasting
    - Real-time inference
    """

    def __init__(
        self,
        sequence_length: int = 30,
        features: int = 8,
        hidden_layers: List[int] = [128, 64, 32],
        dropout_rate: float = 0.3,
        learning_rate: float = 0.001
    ):
        """
        Initialize LSTM model.

        Args:
            sequence_length: Length of input sequences
            features: Number of input features
            hidden_layers: List of hidden layer sizes
            dropout_rate: Dropout rate for regularization
            learning_rate: Learning rate for optimizer
        """
        self.sequence_length = sequence_length
        self.features = features
        self.hidden_layers = hidden_layers
        self.dropout_rate = dropout_rate
        self.learning_rate = learning_rate

        self.model = self.build_model()
        self.history = None

        logger.info(
            f"Initialized CriminalBehaviorLSTM: "
            f"seq_len={sequence_length}, features={features}, "
            f"layers={hidden_layers}"
        )

    def build_model(self) -> models.Sequential:
        """
        Build LSTM model architecture for behavioral sequence modeling.

        Returns:
            Compiled Keras Sequential model
        """
        model = models.Sequential(name="CriminalBehaviorLSTM")

        # Input layer
        model.add(layers.Input(shape=(self.sequence_length, self.features)))

        # LSTM layers with dropout
        for i, units in enumerate(self.hidden_layers[:-1]):
            model.add(layers.LSTM(
                units,
                return_sequences=True,
                name=f"lstm_{i+1}"
            ))
            model.add(layers.Dropout(self.dropout_rate, name=f"dropout_{i+1}"))

        # Final LSTM layer (no sequence return)
        model.add(layers.LSTM(
            self.hidden_layers[-1],
            return_sequences=False,
            name=f"lstm_{len(self.hidden_layers)}"
        ))
        model.add(layers.Dropout(
            self.dropout_rate,
            name=f"dropout_{len(self.hidden_layers)}"
        ))

        # Dense layers
        model.add(layers.Dense(16, activation='relu', name='dense_1'))
        model.add(layers.Dropout(0.2, name='dropout_final'))

        # Output layer (binary classification)
        model.add(layers.Dense(1, activation='sigmoid', name='output'))

        # Compile model
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss='binary_crossentropy',
            metrics=[
                'accuracy',
                tf.keras.metrics.Precision(name='precision'),
                tf.keras.metrics.Recall(name='recall'),
                tf.keras.metrics.AUC(name='auc')
            ]
        )

        logger.info(f"Built LSTM model with {model.count_params():,} parameters")

        return model

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        epochs: int = 100,
        batch_size: int = 32,
        early_stopping_patience: int = 10
    ) -> Dict:
        """
        Train the LSTM model on behavioral sequences.

        Args:
            X_train: Training sequences (samples, sequence_length, features)
            y_train: Training labels (samples,)
            X_val: Validation sequences
            y_val: Validation labels
            epochs: Number of training epochs
            batch_size: Batch size for training
            early_stopping_patience: Patience for early stopping

        Returns:
            Training history dictionary
        """
        logger.info(f"Training LSTM model: {X_train.shape[0]} samples, {epochs} epochs")

        # Callbacks
        callback_list = [
            callbacks.EarlyStopping(
                monitor='val_loss' if X_val is not None else 'loss',
                patience=early_stopping_patience,
                restore_best_weights=True,
                verbose=1
            ),
            callbacks.ReduceLROnPlateau(
                monitor='val_loss' if X_val is not None else 'loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7,
                verbose=1
            ),
            callbacks.TensorBoard(
                log_dir='logs/lstm',
                histogram_freq=1
            )
        ]

        # Train model
        validation_data = (X_val, y_val) if X_val is not None else None

        self.history = self.model.fit(
            X_train,
            y_train,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callback_list,
            verbose=1
        )

        logger.info("Training completed")

        return self.history.history

    def predict_criminal_behavior(
        self,
        behavior_sequence: np.ndarray,
        return_probabilities: bool = False
    ) -> Dict:
        """
        Predict if behavior sequence indicates criminal activity.

        Args:
            behavior_sequence: Input sequence (sequence_length, features)
            return_probabilities: Whether to return probability distribution

        Returns:
            Prediction dictionary with:
            - is_criminal: Binary prediction
            - confidence: Prediction confidence (0-1)
            - risk_level: Risk categorization
            - probabilities: Class probabilities (if requested)
        """
        # Ensure correct shape
        if behavior_sequence.ndim == 2:
            behavior_sequence = np.expand_dims(behavior_sequence, axis=0)

        # Get prediction
        prediction = self.model.predict(behavior_sequence, verbose=0)
        probability = float(prediction[0][0])

        # Calculate risk level
        risk_level = self.calculate_risk_level(probability)

        result = {
            'is_criminal': probability > 0.5,
            'confidence': probability if probability > 0.5 else 1 - probability,
            'probability': probability,
            'risk_level': risk_level,
            'threshold_used': 0.5
        }

        if return_probabilities:
            result['probabilities'] = {
                'criminal': probability,
                'legitimate': 1 - probability
            }

        return result

    def calculate_risk_level(self, probability: float) -> str:
        """
        Calculate risk level based on prediction probability.

        Args:
            probability: Prediction probability (0-1)

        Returns:
            Risk level: LOW, MEDIUM, HIGH, CRITICAL
        """
        if probability < 0.3:
            return "LOW"
        elif probability < 0.6:
            return "MEDIUM"
        elif probability < 0.85:
            return "HIGH"
        else:
            return "CRITICAL"

    def predict_batch(
        self,
        sequences: np.ndarray,
        batch_size: int = 64
    ) -> List[Dict]:
        """
        Batch prediction for multiple sequences.

        Args:
            sequences: Array of sequences (samples, sequence_length, features)
            batch_size: Batch size for prediction

        Returns:
            List of prediction dictionaries
        """
        predictions = self.model.predict(sequences, batch_size=batch_size, verbose=0)

        results = []
        for pred in predictions:
            probability = float(pred[0])
            results.append({
                'is_criminal': probability > 0.5,
                'confidence': probability if probability > 0.5 else 1 - probability,
                'probability': probability,
                'risk_level': self.calculate_risk_level(probability)
            })

        return results

    def save(self, path: str) -> None:
        """Save model to disk."""
        save_path = Path(path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save(path)
        logger.info(f"Model saved to {path}")

    def load(self, path: str) -> None:
        """Load model from disk."""
        self.model = tf.keras.models.load_model(path)
        logger.info(f"Model loaded from {path}")

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray
    ) -> Dict:
        """
        Evaluate model performance.

        Args:
            X_test: Test sequences
            y_test: Test labels

        Returns:
            Evaluation metrics dictionary
        """
        results = self.model.evaluate(X_test, y_test, verbose=0)

        metrics = {
            'loss': results[0],
            'accuracy': results[1],
            'precision': results[2],
            'recall': results[3],
            'auc': results[4]
        }

        # Calculate F1 score
        if metrics['precision'] > 0 and metrics['recall'] > 0:
            metrics['f1_score'] = 2 * (
                (metrics['precision'] * metrics['recall']) /
                (metrics['precision'] + metrics['recall'])
            )
        else:
            metrics['f1_score'] = 0.0

        logger.info(f"Evaluation results: {metrics}")

        return metrics

    def get_sequence_attention(
        self,
        sequence: np.ndarray
    ) -> np.ndarray:
        """
        Get attention weights for sequence (for explainability).

        Args:
            sequence: Input sequence

        Returns:
            Attention weights array
        """
        # Create model that outputs intermediate layer activations
        layer_outputs = [layer.output for layer in self.model.layers[:-2]]
        activation_model = models.Model(
            inputs=self.model.input,
            outputs=layer_outputs
        )

        # Get activations
        if sequence.ndim == 2:
            sequence = np.expand_dims(sequence, axis=0)

        activations = activation_model.predict(sequence, verbose=0)

        # Return attention from last LSTM layer
        return activations[-3]  # Last LSTM output


class CryptoCriminalLSTM(CriminalBehaviorLSTM):
    """
    Specialized LSTM for cryptocurrency criminal pattern detection.
    """

    def __init__(self):
        super().__init__(
            sequence_length=30,
            features=8,
            hidden_layers=[128, 64, 32],
            dropout_rate=0.3
        )

        self.feature_names = [
            'transaction_frequency',
            'transaction_amounts',
            'wallet_diversity',
            'mixing_service_usage',
            'exchange_patterns',
            'withdrawal_timing',
            'geographic_dispersion',
            'counterparty_risk'
        ]


class PredatorBehaviorLSTM(CriminalBehaviorLSTM):
    """
    Specialized LSTM for predator grooming pattern detection.
    High precision configuration for victim safety.
    """

    def __init__(self):
        super().__init__(
            sequence_length=50,  # Longer sequences for grooming progression
            features=10,
            hidden_layers=[256, 128, 64],  # Larger model for higher precision
            dropout_rate=0.2
        )

        self.feature_names = [
            'message_frequency',
            'message_content_embeddings',
            'progressive_intimacy_score',
            'gift_giving_patterns',
            'isolation_attempts',
            'secrecy_requests',
            'age_gap',
            'time_of_day_patterns',
            'platform_behavior',
            'social_engineering_indicators'
        ]

    def calculate_risk_level(self, probability: float) -> str:
        """
        Higher threshold for predator detection (safety priority).
        """
        if probability < 0.2:
            return "LOW"
        elif probability < 0.5:
            return "MEDIUM"
        elif probability < 0.80:
            return "HIGH"
        else:
            return "CRITICAL"


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    # Create sample data
    X_train = np.random.randn(1000, 30, 8)
    y_train = np.random.randint(0, 2, 1000)
    X_val = np.random.randn(200, 30, 8)
    y_val = np.random.randint(0, 2, 200)

    # Train crypto criminal model
    model = CryptoCriminalLSTM()
    model.train(X_train, y_train, X_val, y_val, epochs=10)

    # Predict
    test_sequence = np.random.randn(30, 8)
    result = model.predict_criminal_behavior(test_sequence)
    print(f"Prediction: {result}")
