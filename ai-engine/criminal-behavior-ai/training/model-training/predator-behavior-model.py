"""
Criminal Behavior AI - Predator Behavior Detection Model
Apollo Platform v0.1.0

Train high-precision model to recognize grooming patterns and predatory behavior.
Safety-first approach with very low false negative tolerance.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional
import logging
from pathlib import Path

# NLP imports
from sentence_transformers import SentenceTransformer
from transformers import pipeline

# Model imports
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from models.pattern_recognition.transformer_model import PredatorBehaviorTransformer

logger = logging.getLogger(__name__)


class PredatorBehaviorModel:
    """
    Train model to recognize grooming patterns with high precision.

    Features analyzed:
    - Message frequency and timing
    - Content progression (intimacy escalation)
    - Gift-giving and incentive patterns
    - Isolation attempts
    - Secrecy requests
    - Age-inappropriate content
    - Social engineering indicators
    """

    def __init__(self):
        """Initialize predator behavior detection model."""
        self.features = [
            'message_frequency',
            'message_content_analysis',
            'progressive_intimacy',
            'gift_giving_patterns',
            'isolation_attempts',
            'secrecy_requests',
            'age_gap',
            'time_of_day_patterns'
        ]

        # NLP model for message analysis
        self.nlp_model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')

        # Toxicity/safety classifier
        self.safety_classifier = pipeline(
            "text-classification",
            model="unitary/toxic-bert"
        )

        # Main detection model
        self.model = PredatorBehaviorTransformer()

        logger.info("Initialized PredatorBehaviorModel with high-precision configuration")

    def train_on_historical_cases(
        self,
        dataset_path: str,
        epochs: int = 100
    ) -> Dict:
        """
        Train on anonymized predator case data.

        Args:
            dataset_path: Path to historical case dataset
            epochs: Training epochs

        Returns:
            Training metrics
        """
        logger.info(f"Training on historical predator cases: {dataset_path}")

        # Load anonymized dataset
        df = pd.read_parquet(dataset_path)

        logger.info(f"Loaded {len(df)} anonymized cases")

        # Extract grooming features from messages
        X = self.extract_grooming_features(df)
        y = df['confirmed_grooming'].values

        # High precision requirement - prioritize recall
        # (better to flag non-grooming than miss actual grooming)
        from sklearn.model_selection import train_test_split

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )

        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train,
            test_size=0.2,
            random_state=42,
            stratify=y_train
        )

        # Train with high precision target
        history = self.model.train(
            X_train, y_train,
            X_val, y_val,
            epochs=epochs
        )

        # Evaluate with focus on recall
        from sklearn.metrics import classification_report, confusion_matrix

        predictions = []
        for seq in X_test:
            result = self.model.analyze_conversation(seq)
            predictions.append(int(result['grooming_detected']))

        predictions = np.array(predictions)

        # Detailed evaluation
        report = classification_report(y_test, predictions, output_dict=True)
        conf_matrix = confusion_matrix(y_test, predictions)

        logger.info(f"Classification Report:\n{report}")
        logger.info(f"Confusion Matrix:\n{conf_matrix}")

        # Check recall (critical for victim safety)
        recall = report['1']['recall']
        if recall < 0.90:
            logger.warning(
                f"Recall below target (0.90): {recall:.4f}. "
                "Consider retraining with adjusted threshold."
            )

        return {
            'history': history,
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist(),
            'recall': recall,
            'precision': report['1']['precision']
        }

    def extract_grooming_features(
        self,
        dataset: pd.DataFrame
    ) -> np.ndarray:
        """
        Extract grooming behavior features from conversation data.

        Args:
            dataset: DataFrame containing conversation data

        Returns:
            Feature matrix for model training
        """
        logger.info("Extracting grooming features from conversations")

        features_list = []

        for idx, row in dataset.iterrows():
            messages = row['messages']  # List of messages

            # Analyze message sequence
            features = self.analyze_message_sequence(messages)

            features_list.append(features)

        return np.array(features_list)

    def analyze_message_sequence(
        self,
        messages: List[Dict]
    ) -> np.ndarray:
        """
        Analyze sequence of messages for grooming patterns.

        Args:
            messages: List of message dictionaries

        Returns:
            Feature vector
        """
        # Extract temporal features
        message_frequency = self._calculate_frequency(messages)

        # Extract content features
        content_features = self._analyze_content_progression(messages)

        # Extract behavioral features
        behavioral_features = self._extract_behavioral_patterns(messages)

        # Combine features
        all_features = np.concatenate([
            [message_frequency],
            content_features,
            behavioral_features
        ])

        return all_features

    def _calculate_frequency(self, messages: List[Dict]) -> float:
        """Calculate message frequency score."""
        if len(messages) < 2:
            return 0.0

        # Calculate messages per day
        timestamps = [msg['timestamp'] for msg in messages]
        time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 86400  # days

        if time_span == 0:
            return len(messages)

        return len(messages) / time_span

    def _analyze_content_progression(
        self,
        messages: List[Dict]
    ) -> np.ndarray:
        """
        Analyze content for progressive intimacy and inappropriate material.

        Returns:
            Content feature vector
        """
        # Get message embeddings
        texts = [msg['content'] for msg in messages]
        embeddings = self.nlp_model.encode(texts)

        # Calculate intimacy progression
        intimacy_scores = self._calculate_intimacy_scores(texts)
        intimacy_trend = np.polyfit(range(len(intimacy_scores)), intimacy_scores, 1)[0]

        # Detect inappropriate content
        inappropriate_count = sum(1 for text in texts if self._is_inappropriate(text))

        # Gift/incentive mentions
        gift_pattern_count = sum(1 for text in texts if self._contains_gift_pattern(text))

        features = np.array([
            intimacy_trend,
            np.mean(intimacy_scores),
            inappropriate_count / len(texts),
            gift_pattern_count / len(texts)
        ])

        return features

    def _calculate_intimacy_scores(self, texts: List[str]) -> List[float]:
        """Calculate intimacy level for each message."""
        intimacy_keywords = [
            'love', 'special', 'secret', 'alone', 'together',
            'meet', 'beautiful', 'handsome', 'private'
        ]

        scores = []
        for text in texts:
            text_lower = text.lower()
            score = sum(1 for keyword in intimacy_keywords if keyword in text_lower)
            scores.append(score / len(text.split()))

        return scores

    def _is_inappropriate(self, text: str) -> bool:
        """Check if text contains age-inappropriate content."""
        try:
            result = self.safety_classifier(text[:512])[0]
            return result['label'] == 'toxic' and result['score'] > 0.7
        except:
            return False

    def _contains_gift_pattern(self, text: str) -> bool:
        """Detect gift-giving or incentive patterns."""
        gift_keywords = ['buy you', 'give you', 'send you', 'money', 'gift', 'present']
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in gift_keywords)

    def _extract_behavioral_patterns(
        self,
        messages: List[Dict]
    ) -> np.ndarray:
        """Extract behavioral manipulation patterns."""

        # Isolation attempts
        isolation_keywords = ['don\'t tell', 'secret', 'between us', 'alone']
        isolation_count = sum(
            1 for msg in messages
            if any(kw in msg['content'].lower() for kw in isolation_keywords)
        )

        # Secrecy requests
        secrecy_keywords = ['secret', 'hide', 'delete', 'clear history']
        secrecy_count = sum(
            1 for msg in messages
            if any(kw in msg['content'].lower() for kw in secrecy_keywords)
        )

        # Time pattern analysis (late night messaging)
        late_night_count = sum(
            1 for msg in messages
            if msg['timestamp'].hour >= 22 or msg['timestamp'].hour <= 5
        )

        features = np.array([
            isolation_count / len(messages),
            secrecy_count / len(messages),
            late_night_count / len(messages)
        ])

        return features

    def analyze_conversation(
        self,
        messages: List[Dict],
        subject_age: Optional[int] = None,
        victim_age: Optional[int] = None
    ) -> Dict:
        """
        Analyze conversation for grooming behavior.

        Args:
            messages: List of message dictionaries
            subject_age: Age of potential predator
            victim_age: Age of potential victim

        Returns:
            Detailed analysis with risk assessment
        """
        logger.info(f"Analyzing conversation with {len(messages)} messages")

        # Extract features
        features = self.analyze_message_sequence(messages)
        features_seq = features.reshape(1, -1)

        # Pad to sequence length
        if features_seq.shape[1] < 1000:
            padding = np.zeros((1, 1000 - features_seq.shape[1]))
            features_seq = np.concatenate([features_seq, padding], axis=1)

        features_seq = features_seq.reshape(1, 1000, 1)

        # Get prediction from transformer model
        result = self.model.analyze_conversation(features_seq)

        # Identify grooming stage
        stage = self.identify_grooming_stage(messages, result['probability'])

        # Assess victim risk
        victim_risk = self.assess_victim_risk(
            messages,
            result['probability'],
            subject_age,
            victim_age
        )

        # Calculate urgency
        urgency = self.calculate_urgency_level(
            result['probability'],
            stage,
            victim_risk
        )

        # Recommend intervention
        intervention = self.recommend_intervention(
            result['probability'],
            stage,
            urgency
        )

        return {
            'grooming_detected': result['grooming_detected'],
            'confidence': result['confidence'],
            'probability': result['probability'],
            'grooming_stage': stage,
            'victim_at_risk': victim_risk,
            'urgency_level': urgency,
            'recommended_action': intervention,
            'patterns_detected': self._identify_specific_patterns(messages)
        }

    def identify_grooming_stage(
        self,
        messages: List[Dict],
        probability: float
    ) -> str:
        """
        Identify stage of grooming process.

        Stages:
        1. TARGETING - Initial contact
        2. FRIENDSHIP - Building trust
        3. RELATIONSHIP - Developing connection
        4. SEXUALIZATION - Introducing sexual content
        5. MAINTENANCE - Ensuring secrecy
        """
        num_messages = len(messages)

        if num_messages < 5:
            return "TARGETING"

        # Analyze content progression
        intimacy_scores = self._calculate_intimacy_scores(
            [msg['content'] for msg in messages]
        )
        avg_intimacy = np.mean(intimacy_scores)

        inappropriate_count = sum(
            1 for msg in messages
            if self._is_inappropriate(msg['content'])
        )

        if inappropriate_count > len(messages) * 0.2:
            return "SEXUALIZATION"
        elif avg_intimacy > 0.05 and num_messages > 20:
            return "RELATIONSHIP"
        elif num_messages > 10:
            return "FRIENDSHIP"
        else:
            return "TARGETING"

    def assess_victim_risk(
        self,
        messages: List[Dict],
        probability: float,
        subject_age: Optional[int],
        victim_age: Optional[int]
    ) -> str:
        """Assess victim risk level."""
        risk_score = probability

        # Age gap increases risk
        if subject_age and victim_age:
            age_gap = subject_age - victim_age
            if age_gap > 10:
                risk_score += 0.1
            if victim_age < 13:
                risk_score += 0.15

        # Rapid progression increases risk
        if len(messages) > 50:
            time_span = (messages[-1]['timestamp'] - messages[0]['timestamp']).days
            if time_span < 7:
                risk_score += 0.1

        if risk_score > 0.9:
            return "CRITICAL"
        elif risk_score > 0.75:
            return "HIGH"
        elif risk_score > 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def calculate_urgency_level(
        self,
        probability: float,
        stage: str,
        victim_risk: str
    ) -> str:
        """Calculate urgency for intervention."""
        if victim_risk == "CRITICAL" or stage == "SEXUALIZATION":
            return "IMMEDIATE"
        elif probability > 0.85 or stage == "RELATIONSHIP":
            return "HIGH"
        elif probability > 0.70:
            return "MEDIUM"
        else:
            return "LOW"

    def recommend_intervention(
        self,
        probability: float,
        stage: str,
        urgency: str
    ) -> str:
        """Recommend intervention strategy."""
        if urgency == "IMMEDIATE":
            return "EMERGENCY_INTERVENTION_VICTIM_RESCUE"
        elif urgency == "HIGH":
            return "IMMEDIATE_INVESTIGATION_AND_MONITORING"
        elif urgency == "MEDIUM":
            return "ENHANCED_SURVEILLANCE"
        else:
            return "CONTINUED_MONITORING"

    def _identify_specific_patterns(self, messages: List[Dict]) -> List[str]:
        """Identify specific grooming patterns present."""
        patterns = []

        texts = [msg['content'].lower() for msg in messages]
        all_text = ' '.join(texts)

        if any('secret' in text or 'don\'t tell' in text for text in texts):
            patterns.append('SECRECY_REQUESTS')

        if any(self._contains_gift_pattern(text) for text in texts):
            patterns.append('GIFT_GIVING')

        if 'meet' in all_text or 'in person' in all_text:
            patterns.append('MEETING_ATTEMPTS')

        if any(self._is_inappropriate(msg['content']) for msg in messages):
            patterns.append('INAPPROPRIATE_CONTENT')

        return patterns


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    model = PredatorBehaviorModel()
    logger.info("Predator behavior model initialized")
