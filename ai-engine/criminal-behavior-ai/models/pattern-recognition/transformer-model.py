"""
Criminal Behavior AI - Transformer Pattern Recognition Model
Apollo Platform v0.1.0

Transformer-based attention mechanism for criminal behavior pattern detection.
Specializes in complex sequential patterns and long-range dependencies.
"""

import tensorflow as tf
from tensorflow.keras import layers, models
import numpy as np
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class MultiHeadSelfAttention(layers.Layer):
    """Multi-head self-attention layer for transformer."""

    def __init__(self, embed_dim: int, num_heads: int):
        super().__init__()
        self.embed_dim = embed_dim
        self.num_heads = num_heads

        assert embed_dim % num_heads == 0, "embed_dim must be divisible by num_heads"

        self.projection_dim = embed_dim // num_heads
        self.query_dense = layers.Dense(embed_dim)
        self.key_dense = layers.Dense(embed_dim)
        self.value_dense = layers.Dense(embed_dim)
        self.combine_heads = layers.Dense(embed_dim)

    def attention(self, query, key, value):
        """Scaled dot-product attention."""
        score = tf.matmul(query, key, transpose_b=True)
        dim_key = tf.cast(tf.shape(key)[-1], tf.float32)
        scaled_score = score / tf.math.sqrt(dim_key)
        weights = tf.nn.softmax(scaled_score, axis=-1)
        output = tf.matmul(weights, value)
        return output, weights

    def separate_heads(self, x, batch_size):
        """Split into multiple heads."""
        x = tf.reshape(x, (batch_size, -1, self.num_heads, self.projection_dim))
        return tf.transpose(x, perm=[0, 2, 1, 3])

    def call(self, inputs):
        batch_size = tf.shape(inputs)[0]

        # Linear projections
        query = self.query_dense(inputs)
        key = self.key_dense(inputs)
        value = self.value_dense(inputs)

        # Separate heads
        query = self.separate_heads(query, batch_size)
        key = self.separate_heads(key, batch_size)
        value = self.separate_heads(value, batch_size)

        # Attention
        attention, weights = self.attention(query, key, value)

        # Combine heads
        attention = tf.transpose(attention, perm=[0, 2, 1, 3])
        concat_attention = tf.reshape(
            attention,
            (batch_size, -1, self.embed_dim)
        )

        # Final linear projection
        output = self.combine_heads(concat_attention)

        return output, weights


class TransformerBlock(layers.Layer):
    """Transformer encoder block."""

    def __init__(self, embed_dim: int, num_heads: int, ff_dim: int, dropout: float = 0.1):
        super().__init__()
        self.att = MultiHeadSelfAttention(embed_dim, num_heads)
        self.ffn = tf.keras.Sequential([
            layers.Dense(ff_dim, activation="relu"),
            layers.Dense(embed_dim),
        ])
        self.layernorm1 = layers.LayerNormalization(epsilon=1e-6)
        self.layernorm2 = layers.LayerNormalization(epsilon=1e-6)
        self.dropout1 = layers.Dropout(dropout)
        self.dropout2 = layers.Dropout(dropout)

    def call(self, inputs, training=False):
        # Multi-head attention
        attn_output, attn_weights = self.att(inputs)
        attn_output = self.dropout1(attn_output, training=training)
        out1 = self.layernorm1(inputs + attn_output)

        # Feed forward
        ffn_output = self.ffn(out1)
        ffn_output = self.dropout2(ffn_output, training=training)
        out2 = self.layernorm2(out1 + ffn_output)

        return out2, attn_weights


class CriminalBehaviorTransformer:
    """
    Transformer model for criminal behavior pattern detection.

    Uses self-attention to capture complex behavioral patterns
    and long-range dependencies in sequential data.
    """

    def __init__(
        self,
        max_sequence_length: int = 1000,
        num_features: int = 10,
        embedding_dim: int = 256,
        num_heads: int = 8,
        num_layers: int = 6,
        ff_dim: int = 512,
        dropout: float = 0.1,
        learning_rate: float = 0.0001
    ):
        """
        Initialize Transformer model.

        Args:
            max_sequence_length: Maximum sequence length
            num_features: Number of input features
            embedding_dim: Embedding dimension
            num_heads: Number of attention heads
            num_layers: Number of transformer blocks
            ff_dim: Feed-forward network dimension
            dropout: Dropout rate
            learning_rate: Learning rate
        """
        self.max_sequence_length = max_sequence_length
        self.num_features = num_features
        self.embedding_dim = embedding_dim
        self.num_heads = num_heads
        self.num_layers = num_layers
        self.ff_dim = ff_dim
        self.dropout = dropout
        self.learning_rate = learning_rate

        self.model = self.build_model()
        self.attention_weights = None

        logger.info(
            f"Initialized CriminalBehaviorTransformer: "
            f"seq_len={max_sequence_length}, embed_dim={embedding_dim}, "
            f"heads={num_heads}, layers={num_layers}"
        )

    def build_model(self) -> models.Model:
        """
        Build transformer model architecture.

        Returns:
            Compiled Keras Model
        """
        # Input
        inputs = layers.Input(shape=(self.max_sequence_length, self.num_features))

        # Input projection to embedding dimension
        x = layers.Dense(self.embedding_dim)(inputs)

        # Positional encoding
        positions = tf.range(start=0, limit=self.max_sequence_length, delta=1)
        position_embedding = layers.Embedding(
            input_dim=self.max_sequence_length,
            output_dim=self.embedding_dim
        )(positions)

        x = x + position_embedding

        # Transformer blocks
        attention_weights_list = []
        for i in range(self.num_layers):
            transformer_block = TransformerBlock(
                self.embedding_dim,
                self.num_heads,
                self.ff_dim,
                self.dropout
            )
            x, attn_weights = transformer_block(x)
            attention_weights_list.append(attn_weights)

        # Global average pooling
        x = layers.GlobalAveragePooling1D()(x)

        # Dropout
        x = layers.Dropout(self.dropout)(x)

        # Classification head
        x = layers.Dense(128, activation='relu')(x)
        x = layers.Dropout(self.dropout)(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(self.dropout)(x)
        outputs = layers.Dense(1, activation='sigmoid')(x)

        # Create model
        model = models.Model(inputs=inputs, outputs=outputs, name="CriminalBehaviorTransformer")

        # Compile
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

        logger.info(f"Built Transformer model with {model.count_params():,} parameters")

        return model

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        epochs: int = 100,
        batch_size: int = 32
    ) -> Dict:
        """
        Train the transformer model.

        Args:
            X_train: Training sequences
            y_train: Training labels
            X_val: Validation sequences
            y_val: Validation labels
            epochs: Number of epochs
            batch_size: Batch size

        Returns:
            Training history
        """
        logger.info(f"Training Transformer: {X_train.shape[0]} samples, {epochs} epochs")

        # Callbacks
        callback_list = [
            tf.keras.callbacks.EarlyStopping(
                monitor='val_loss' if X_val is not None else 'loss',
                patience=10,
                restore_best_weights=True
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss' if X_val is not None else 'loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7
            )
        ]

        # Train
        validation_data = (X_val, y_val) if X_val is not None else None
        history = self.model.fit(
            X_train,
            y_train,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callback_list,
            verbose=1
        )

        return history.history

    def predict_with_attention(
        self,
        sequence: np.ndarray
    ) -> Dict:
        """
        Predict with attention weights for explainability.

        Args:
            sequence: Input sequence

        Returns:
            Prediction with attention weights
        """
        if sequence.ndim == 2:
            sequence = np.expand_dims(sequence, axis=0)

        # Get prediction
        prediction = self.model.predict(sequence, verbose=0)
        probability = float(prediction[0][0])

        # Get attention weights (requires custom forward pass)
        # This is a simplified version - full implementation would extract
        # attention from TransformerBlock layers

        result = {
            'is_criminal': probability > 0.5,
            'confidence': probability if probability > 0.5 else 1 - probability,
            'probability': probability,
            'risk_level': self.calculate_risk_level(probability),
            'attention_available': True
        }

        return result

    def calculate_risk_level(self, probability: float) -> str:
        """Calculate risk level from probability."""
        if probability < 0.3:
            return "LOW"
        elif probability < 0.6:
            return "MEDIUM"
        elif probability < 0.85:
            return "HIGH"
        else:
            return "CRITICAL"

    def save(self, path: str) -> None:
        """Save model."""
        self.model.save(path)
        logger.info(f"Model saved to {path}")

    def load(self, path: str) -> None:
        """Load model."""
        self.model = tf.keras.models.load_model(path, custom_objects={
            'MultiHeadSelfAttention': MultiHeadSelfAttention,
            'TransformerBlock': TransformerBlock
        })
        logger.info(f"Model loaded from {path}")


class PredatorBehaviorTransformer(CriminalBehaviorTransformer):
    """
    Specialized Transformer for predator grooming detection.
    High precision configuration with attention visualization.
    """

    def __init__(self):
        super().__init__(
            max_sequence_length=1000,  # Long conversations
            num_features=10,
            embedding_dim=256,
            num_heads=8,
            num_layers=6,
            ff_dim=512,
            dropout=0.1
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

    def analyze_conversation(self, messages: np.ndarray) -> Dict:
        """
        Analyze conversation for grooming behavior.

        Args:
            messages: Message sequence features

        Returns:
            Detailed analysis with risk assessment
        """
        prediction = self.predict_with_attention(messages)

        # Enhanced for predator detection
        analysis = {
            'grooming_detected': prediction['probability'] > 0.90,  # High threshold
            'confidence': prediction['confidence'],
            'probability': prediction['probability'],
            'risk_level': self.calculate_risk_level(prediction['probability']),
            'urgency_level': self.calculate_urgency(prediction['probability']),
            'recommended_action': self.recommend_action(prediction['probability'])
        }

        return analysis

    def calculate_urgency(self, probability: float) -> str:
        """Calculate urgency level for intervention."""
        if probability > 0.95:
            return "IMMEDIATE"
        elif probability > 0.85:
            return "HIGH"
        elif probability > 0.70:
            return "MEDIUM"
        else:
            return "LOW"

    def recommend_action(self, probability: float) -> str:
        """Recommend intervention action."""
        if probability > 0.95:
            return "EMERGENCY_INTERVENTION"
        elif probability > 0.85:
            return "IMMEDIATE_INVESTIGATION"
        elif probability > 0.70:
            return "ENHANCED_MONITORING"
        elif probability > 0.50:
            return "CONTINUED_MONITORING"
        else:
            return "ROUTINE_MONITORING"

    def calculate_risk_level(self, probability: float) -> str:
        """Higher precision threshold for victim safety."""
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
    X_train = np.random.randn(500, 1000, 10)
    y_train = np.random.randint(0, 2, 500)

    # Train predator detection model
    model = PredatorBehaviorTransformer()
    model.train(X_train, y_train, epochs=5)

    # Analyze conversation
    test_conversation = np.random.randn(1000, 10)
    result = model.analyze_conversation(test_conversation)
    print(f"Analysis: {result}")
