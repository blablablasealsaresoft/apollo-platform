"""
Predictive Analytics - Cash-Out Prediction
Apollo Platform v0.1.0

Predict when and where criminals will attempt to cash out cryptocurrency.
Uses time series forecasting to anticipate withdrawal attempts.
"""

import pandas as pd
import numpy as np
from prophet import Prophet
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class CashOutPredictor:
    """
    Predict when criminals will attempt to cash out cryptocurrency.

    Uses Prophet for time series forecasting with:
    - Weekly seasonality (day-of-week patterns)
    - Monthly seasonality (end-of-month patterns)
    - Holiday effects
    - Trend changes (sudden behavior shifts)
    """

    def __init__(
        self,
        changepoint_prior_scale: float = 0.05,
        seasonality_mode: str = 'multiplicative',
        include_holidays: bool = True
    ):
        """
        Initialize cash-out predictor.

        Args:
            changepoint_prior_scale: Trend flexibility
            seasonality_mode: 'additive' or 'multiplicative'
            include_holidays: Include holiday effects
        """
        self.model = Prophet(
            changepoint_prior_scale=changepoint_prior_scale,
            seasonality_mode=seasonality_mode,
            daily_seasonality=False,
            weekly_seasonality=True,
            yearly_seasonality=False
        )

        # Add custom seasonality
        self.model.add_seasonality(
            name='monthly',
            period=30.5,
            fourier_order=5
        )

        # Exchange selection model
        self.exchange_model = None

        self.trained = False

        logger.info("Initialized CashOutPredictor")

    def train(
        self,
        historical_data: pd.DataFrame,
        train_exchange_model: bool = True
    ) -> Dict:
        """
        Train on historical cash-out patterns.

        Args:
            historical_data: DataFrame with columns:
                - timestamp: datetime
                - cash_out_amount: float
                - wallet_address: str
                - exchange: str (optional)
            train_exchange_model: Also train exchange selection model

        Returns:
            Training metrics
        """
        logger.info(f"Training on {len(historical_data)} historical cash-outs")

        # Prepare data for Prophet
        df = pd.DataFrame({
            'ds': historical_data['timestamp'],
            'y': historical_data['cash_out_amount']
        })

        # Remove outliers (optional)
        df = self._remove_outliers(df)

        # Fit model
        self.model.fit(df)

        self.trained = True

        logger.info("Cash-out prediction model trained")

        # Train exchange selection model
        if train_exchange_model and 'exchange' in historical_data.columns:
            self._train_exchange_model(historical_data)

        return {
            'training_samples': len(df),
            'date_range': (df['ds'].min(), df['ds'].max()),
            'mean_cash_out': df['y'].mean(),
            'std_cash_out': df['y'].std()
        }

    def _remove_outliers(
        self,
        df: pd.DataFrame,
        std_threshold: float = 3.0
    ) -> pd.DataFrame:
        """Remove statistical outliers."""
        mean = df['y'].mean()
        std = df['y'].std()

        df_filtered = df[
            (df['y'] >= mean - std_threshold * std) &
            (df['y'] <= mean + std_threshold * std)
        ]

        removed = len(df) - len(df_filtered)
        if removed > 0:
            logger.info(f"Removed {removed} outliers")

        return df_filtered

    def _train_exchange_model(self, historical_data: pd.DataFrame) -> None:
        """Train exchange selection prediction model."""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder

        logger.info("Training exchange selection model")

        # Extract features
        features = self._extract_exchange_features(historical_data)

        # Encode exchanges
        self.exchange_encoder = LabelEncoder()
        y = self.exchange_encoder.fit_transform(historical_data['exchange'])

        # Train classifier
        self.exchange_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.exchange_model.fit(features, y)

        logger.info("Exchange selection model trained")

    def _extract_exchange_features(
        self,
        data: pd.DataFrame
    ) -> pd.DataFrame:
        """Extract features for exchange selection."""
        features = pd.DataFrame()

        # Temporal features
        features['hour'] = data['timestamp'].dt.hour
        features['day_of_week'] = data['timestamp'].dt.dayofweek
        features['day_of_month'] = data['timestamp'].dt.day

        # Amount features
        features['amount'] = data['cash_out_amount']
        features['amount_log'] = np.log1p(data['cash_out_amount'])

        # Wallet history features (if available)
        if 'wallet_address' in data.columns:
            wallet_counts = data.groupby('wallet_address').size()
            features['wallet_frequency'] = data['wallet_address'].map(wallet_counts)

        return features

    def predict_cash_out(
        self,
        wallet_address: str,
        days_ahead: int = 30,
        historical_behavior: Optional[pd.DataFrame] = None
    ) -> Dict:
        """
        Predict when and where criminal will cash out.

        Args:
            wallet_address: Cryptocurrency wallet address
            days_ahead: Prediction horizon in days
            historical_behavior: Historical behavior data for this wallet

        Returns:
            Prediction dictionary with:
            - predicted_dates: High-probability dates
            - likely_exchanges: Ranked exchange list
            - predicted_amounts: Amount forecasts
            - confidence: Prediction confidence
            - monitoring_strategy: Recommended monitoring
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")

        logger.info(
            f"Predicting cash-out for wallet {wallet_address[:10]}... "
            f"({days_ahead} days ahead)"
        )

        # Generate future dates
        future = self.model.make_future_dataframe(periods=days_ahead)
        forecast = self.model.predict(future)

        # Extract future predictions
        future_forecast = forecast.tail(days_ahead)

        # Identify high-probability dates
        high_prob_dates = self._extract_high_probability_dates(future_forecast)

        # Predict likely exchanges
        likely_exchanges = []
        if self.exchange_model is not None and historical_behavior is not None:
            likely_exchanges = self._predict_exchange_selection(
                wallet_address,
                high_prob_dates,
                historical_behavior
            )

        # Calculate confidence
        confidence = self._calculate_forecast_confidence(future_forecast)

        # Recommend monitoring strategy
        monitoring = self._recommend_monitoring_strategy(
            high_prob_dates,
            likely_exchanges,
            confidence
        )

        result = {
            'wallet_address': wallet_address,
            'prediction_horizon_days': days_ahead,
            'predicted_dates': high_prob_dates,
            'likely_exchanges': likely_exchanges,
            'predicted_amounts': future_forecast['yhat'].tolist(),
            'confidence': confidence,
            'recommended_monitoring': monitoring,
            'forecast_dataframe': future_forecast
        }

        logger.info(
            f"Prediction complete: {len(high_prob_dates)} high-probability dates, "
            f"confidence={confidence:.3f}"
        )

        return result

    def _extract_high_probability_dates(
        self,
        forecast: pd.DataFrame,
        percentile_threshold: float = 0.75
    ) -> List[Dict]:
        """
        Extract dates with high cash-out probability.

        Args:
            forecast: Prophet forecast dataframe
            percentile_threshold: Percentile threshold for "high"

        Returns:
            List of date dictionaries
        """
        # Calculate threshold
        threshold = forecast['yhat'].quantile(percentile_threshold)

        # Filter high-probability dates
        high_prob = forecast[forecast['yhat'] >= threshold]

        dates = []
        for _, row in high_prob.iterrows():
            dates.append({
                'date': row['ds'].strftime('%Y-%m-%d'),
                'predicted_amount': float(row['yhat']),
                'lower_bound': float(row['yhat_lower']),
                'upper_bound': float(row['yhat_upper']),
                'confidence_interval': float(row['yhat_upper'] - row['yhat_lower'])
            })

        return dates

    def _predict_exchange_selection(
        self,
        wallet_address: str,
        predicted_dates: List[Dict],
        historical_behavior: pd.DataFrame
    ) -> List[Dict]:
        """
        Predict which exchanges criminal will use.

        Args:
            wallet_address: Wallet address
            predicted_dates: Predicted cash-out dates
            historical_behavior: Historical behavior data

        Returns:
            Ranked list of exchanges with probabilities
        """
        if self.exchange_model is None:
            return []

        # Use features from most recent date
        if len(predicted_dates) == 0:
            return []

        # Create feature vector for prediction
        features = pd.DataFrame({
            'hour': [12],  # Assume midday
            'day_of_week': [pd.to_datetime(predicted_dates[0]['date']).dayofweek],
            'day_of_month': [pd.to_datetime(predicted_dates[0]['date']).day],
            'amount': [predicted_dates[0]['predicted_amount']],
            'amount_log': [np.log1p(predicted_dates[0]['predicted_amount'])],
            'wallet_frequency': [len(historical_behavior)]
        })

        # Predict probabilities
        proba = self.exchange_model.predict_proba(features)[0]
        exchanges = self.exchange_encoder.classes_

        # Rank exchanges
        exchange_probs = sorted(
            zip(exchanges, proba),
            key=lambda x: x[1],
            reverse=True
        )

        # Return top 5
        return [
            {
                'exchange': exchange,
                'probability': float(prob),
                'confidence': 'HIGH' if prob > 0.3 else 'MEDIUM' if prob > 0.1 else 'LOW'
            }
            for exchange, prob in exchange_probs[:5]
        ]

    def _calculate_forecast_confidence(
        self,
        forecast: pd.DataFrame
    ) -> float:
        """
        Calculate overall forecast confidence.

        Based on:
        - Prediction interval width
        - Model uncertainty
        - Trend stability
        """
        # Average relative uncertainty
        avg_uncertainty = np.mean(
            (forecast['yhat_upper'] - forecast['yhat_lower']) / forecast['yhat']
        )

        # Convert to confidence (inverse of uncertainty)
        confidence = 1.0 / (1.0 + avg_uncertainty)

        # Clamp to [0, 1]
        confidence = np.clip(confidence, 0.0, 1.0)

        return float(confidence)

    def _recommend_monitoring_strategy(
        self,
        predicted_dates: List[Dict],
        likely_exchanges: List[Dict],
        confidence: float
    ) -> Dict:
        """
        Recommend monitoring strategy based on predictions.

        Args:
            predicted_dates: Predicted cash-out dates
            likely_exchanges: Likely exchanges
            confidence: Forecast confidence

        Returns:
            Monitoring recommendation
        """
        # Determine intensity
        if confidence > 0.8 and len(predicted_dates) > 0:
            intensity = "INTENSIVE"
        elif confidence > 0.6:
            intensity = "ENHANCED"
        else:
            intensity = "ROUTINE"

        # Focus areas
        focus_exchanges = [ex['exchange'] for ex in likely_exchanges[:3]]

        # Timeline
        if len(predicted_dates) > 0:
            start_date = predicted_dates[0]['date']
            end_date = predicted_dates[-1]['date']
        else:
            start_date = datetime.now().strftime('%Y-%m-%d')
            end_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')

        return {
            'intensity': intensity,
            'focus_exchanges': focus_exchanges,
            'monitoring_start': start_date,
            'monitoring_end': end_date,
            'check_frequency': 'HOURLY' if intensity == 'INTENSIVE' else 'DAILY',
            'alert_threshold': 0.8 if intensity == 'INTENSIVE' else 0.9,
            'recommended_actions': self._get_monitoring_actions(intensity)
        }

    def _get_monitoring_actions(self, intensity: str) -> List[str]:
        """Get recommended monitoring actions."""
        if intensity == "INTENSIVE":
            return [
                "Real-time exchange monitoring",
                "Coordinate with exchange security teams",
                "Deploy automated alerts",
                "Prepare for immediate action",
                "24/7 monitoring"
            ]
        elif intensity == "ENHANCED":
            return [
                "Increased check frequency",
                "Exchange coordination",
                "Automated alerts",
                "Regular status reviews"
            ]
        else:
            return [
                "Routine monitoring",
                "Daily status checks",
                "Standard alerts"
            ]

    def get_forecast_visualization_data(self, forecast: pd.DataFrame) -> Dict:
        """Get data for visualization."""
        return {
            'dates': forecast['ds'].dt.strftime('%Y-%m-%d').tolist(),
            'predictions': forecast['yhat'].tolist(),
            'lower_bound': forecast['yhat_lower'].tolist(),
            'upper_bound': forecast['yhat_upper'].tolist()
        }


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    # Create sample historical data
    dates = pd.date_range(start='2025-01-01', end='2025-12-31', freq='D')
    amounts = np.random.lognormal(10, 1, len(dates))

    historical_data = pd.DataFrame({
        'timestamp': dates,
        'cash_out_amount': amounts,
        'wallet_address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        'exchange': np.random.choice(['Binance', 'Coinbase', 'Kraken'], len(dates))
    })

    # Train predictor
    predictor = CashOutPredictor()
    predictor.train(historical_data)

    # Predict cash-out
    prediction = predictor.predict_cash_out(
        '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        days_ahead=30,
        historical_behavior=historical_data
    )

    print(f"Prediction: {prediction['predicted_dates'][:3]}")
    print(f"Likely exchanges: {prediction['likely_exchanges']}")
    print(f"Monitoring strategy: {prediction['recommended_monitoring']}")
