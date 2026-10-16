# backend/core/ai_models/anomaly_detection/model.py
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Any, Optional, Tuple # Added Tuple
import os

# Assuming QueryProcessor is in the same directory or accessible via PYTHONPATH
# This try-except block helps if running scripts directly vs. as part of a package.
try:
    from .processor import QueryProcessor # Relative import for package structure
except ImportError:
    # Fallback for cases where the script might be run directly (e.g., for testing)
    # or the environment setup for PYTHONPATH is different.
    print("INFO: Attempting fallback import for QueryProcessor due to ImportError. Ensure PYTHONPATH is set for package use.")
    from processor import QueryProcessor # Direct import, assumes processor.py is in the same dir or PYTHONPATH


class AnomalyDetectionModel:
    """
    A wrapper for an anomaly detection model (e.g., Isolation Forest)
    to detect anomalous SQL queries.
    """
    def __init__(self,
                 model_path: Optional[str] = None,
                 processor_scaler_path: Optional[str] = None,
                 model_params: Optional[dict] = None):
        """
        Initializes the AnomalyDetectionModel.

        Args:
            model_path (str, optional): Path to load a pre-trained model.
                                        If None, a new model will be created.
            processor_scaler_path (str, optional): Path to the fitted scaler for the QueryProcessor.
                                                   This is crucial for consistent feature processing.
            model_params (dict, optional): Parameters for the Isolation Forest model if creating a new one.
                                           Example: {'n_estimators': 100, 'contamination': 'auto', 'random_state': 42}
        """
        self.model_path = model_path
        self.processor = QueryProcessor(scaler_path=processor_scaler_path) # Initialize processor
        self.model: Optional[IsolationForest] = None # Type hint for the model

        # Default parameters for Isolation Forest, can be overridden by model_params
        default_params = {'n_estimators': 100, 'contamination': 0.05, 'random_state': 42, 'n_jobs': -1}
        self.model_params = {**default_params, **(model_params if model_params else {})}

        # Attempt to load the model if model_path is provided and the file exists
        if self.model_path and self._model_exists(self.model_path):
            try:
                self.load_model(self.model_path)
                print(f"INFO: Anomaly detection model loaded successfully from {self.model_path}")
            except Exception as e:
                print(f"WARNING: Could not load model from {self.model_path}. A new one will be created. Error: {e}")
                self.model = IsolationForest(**self.model_params) # Initialize new model on failure
        else:
            self.model = IsolationForest(**self.model_params) # Initialize a new model
            if self.model_path: # If path was given but file doesn't exist
                 print(f"INFO: Model file not found at {self.model_path}. A new model will be initialized.")
        
        # Ensure processor's feature names are ready if its scaler was loaded
        if self.processor._fitted: # Check if the processor's scaler was successfully loaded
            _ = self.processor.get_feature_names() # This populates feature names in the processor

    def _model_exists(self, path: str) -> bool:
        """Checks if a model file exists at the given path."""
        return os.path.exists(path)

    def train(self, queries: List[str],
              processor_scaler_save_path: Optional[str] = None,
              model_save_path: Optional[str] = None) -> None:
        """
        Trains the anomaly detection model on the given SQL queries.
        Typically, these should be examples of normal, non-anomalous queries.

        Args:
            queries (List[str]): A list of SQL query strings for training.
            processor_scaler_save_path (str, optional): Path to save the fitted QueryProcessor's scaler.
                                                       If None, uses processor.scaler_path if set.
            model_save_path (str, optional): Path to save the trained model.
                                             If None, uses self.model_path if set during init.
        """
        if not queries:
            print("ERROR: No queries provided for training.")
            return
        if self.model is None: # Should not happen with current __init__
            print("ERROR: Model is not initialized. Cannot train.")
            return

        print("INFO: Fitting query processor and transforming queries for training...")
        # The processor's fit_transform will fit its scaler and transform data.
        # It will also save the scaler if processor_scaler_save_path is provided or if
        # processor.scaler_path was set at initialization.
        _scaler_save_path_for_processor = processor_scaler_save_path or self.processor.scaler_path
        features = self.processor.fit_transform(queries, scaler_save_path=_scaler_save_path_for_processor)

        if features.size == 0:
            print("ERROR: No features extracted after processing. Training aborted.")
            return

        print(f"INFO: Training anomaly detection model with {features.shape[0]} samples and {features.shape[1]} features...")
        self.model.fit(features)
        print("INFO: Model training completed.")

        # Determine save path for the model
        _model_save_path_to_use = model_save_path if model_save_path else self.model_path
        if _model_save_path_to_use:
            self.save_model(_model_save_path_to_use)
        else:
            print("WARNING: model_save_path not provided, and no default model_path set. Trained model not saved.")

    def predict_and_score(self, queries: List[str]) -> List[Tuple[int, float]]:
        """
        Predicts if queries are anomalous and provides their anomaly scores.

        Args:
            queries (List[str]): A list of SQL query strings to predict.

        Returns:
            List[Tuple[int, float]]: A list of tuples, where each tuple is (prediction, score).
                                     Prediction: 1 for inliers (normal), -1 for outliers (anomalous) for IsolationForest.
                                     Score: Anomaly score from the model (lower is more anomalous for IsolationForest).
                                     Returns an empty list if the model or processor is not ready or no queries.
        """
        if self.model is None:
            print("ERROR: Model is not trained or loaded. Cannot predict.")
            return []
        if not self.processor._fitted: # Check if processor's scaler is fitted/loaded
            print("ERROR: QueryProcessor's scaler is not fitted/loaded. Cannot transform queries for prediction.")
            return []
        if not queries:
            return [] # Return empty list if no queries are provided

        features = self.processor.transform(queries)
        if features.size == 0 and queries: # Queries provided, but no features extracted (e.g., all failed processing)
            print("WARNING: No features extracted from provided queries for prediction.")
            return []
        if features.size == 0: # No queries or no features extracted
             return []

        # Preserve feature names when possible to avoid sklearn/lightgbm feature-name warnings.
        X: Any = features
        try:
            import pandas as pd  # type: ignore

            names = self.processor.get_feature_names()
            if isinstance(names, list) and names and len(names) == int(features.shape[1]):
                X = pd.DataFrame(features, columns=names)
        except Exception:
            X = features

        try:
            predictions = self.model.predict(X)
            # For Isolation Forest, decision_function returns average anomaly scores.
            # Negative scores are outliers, positive are inliers. Lower scores = more anomalous.
            scores = self.model.decision_function(X)
            return list(zip(predictions.tolist(), scores.tolist()))
        except Exception as e:
            print(f"ERROR: Error during model prediction or scoring: {e}")
            return []


    def save_model(self, path: str) -> None:
        """
        Saves the trained model to a file.

        Args:
            path (str): The path to save the model.
        """
        if self.model is None:
            print("ERROR: No model to save (model is None).")
            return
        try:
            # Ensure directory exists before saving
            dir_name = os.path.dirname(path)
            if dir_name: # Check if path includes a directory
                os.makedirs(dir_name, exist_ok=True)
            joblib.dump(self.model, path)
            print(f"INFO: Model saved successfully to {path}")
            self.model_path = path # Update internal path to the new save location
        except Exception as e:
            print(f"ERROR: Error saving model to {path}: {e}")

    def load_model(self, path: str) -> None:
        """
        Loads a pre-trained model from a file.

        Args:
            path (str): The path to the saved model.
        """
        if not self._model_exists(path):
            print(f"ERROR: Model file not found at {path}. Cannot load.")
            raise FileNotFoundError(f"Model file not found at {path}")
        try:
            self.model = joblib.load(path)
            self.model_path = path # Update internal path
            print(f"INFO: Model loaded successfully from {path}")
        except Exception as e:
            print(f"ERROR: Error loading model from {path}: {e}")
            # Optionally re-raise or handle (e.g. self.model = None)
            raise # Re-raise the exception to signal failure to the caller

if __name__ == '__main__':
    # Example Usage
    # Define paths for saving/loading artifacts
    # It's good practice to store these in a config or manage them centrally.
    TEMP_ARTIFACTS_DIR_MODEL = "./temp_model_class_artifacts" # Unique name for this test
    SCALER_FILENAME_FOR_TEST = "test_anomaly_query_scaler.joblib"
    MODEL_FILENAME_FOR_TEST = "test_anomaly_detection_model.joblib"

    # Create directory if it doesn't exist for storing test artifacts
    os.makedirs(TEMP_ARTIFACTS_DIR_MODEL, exist_ok=True)

    # Define full paths for the scaler and model for this test run
    test_scaler_path = os.path.join(TEMP_ARTIFACTS_DIR_MODEL, SCALER_FILENAME_FOR_TEST)
    test_model_path = os.path.join(TEMP_ARTIFACTS_DIR_MODEL, MODEL_FILENAME_FOR_TEST)


    # --- Training Example ---
    print("\n--- Training Anomaly Detection Model ---")
    # Initialize a new model. The paths provided here will be used for saving after training.
    # The processor_scaler_path is passed to the QueryProcessor inside AnomalyDetectionModel.
    anomaly_model_trainer = AnomalyDetectionModel(
        model_path=test_model_path, # Will save model here after training
        processor_scaler_path=test_scaler_path, # Processor will save scaler here
        model_params={'n_estimators': 50, 'contamination': 0.1, 'random_state': 123} # Example params
    )

    # Sample queries for training (ideally, train on a large dataset of NORMAL queries)
    training_queries = [
        "SELECT id, name FROM users WHERE status = 'active' AND registration_date > '2023-01-01'",
        "INSERT INTO logs (level, message, timestamp) VALUES ('INFO', 'User logged in', NOW())",
        "UPDATE products SET price = price * 1.05 WHERE category_id = 2",
        "SELECT user_id FROM sessions WHERE last_activity < NOW() - INTERVAL '1 hour'",
        "DELETE FROM temp_uploads WHERE created_at < '2024-01-01'"
    ] * 20 # Multiply to have a bit more data for Isolation Forest to work reasonably

    # Train the model. This will also fit and save the processor's scaler.
    anomaly_model_trainer.train(
        training_queries,
        # These paths are now passed during __init__ to the model and its processor
        # but can be overridden here if needed for a specific training run.
        # For this example, we rely on paths set during __init__.
        # processor_scaler_save_path=test_scaler_path, # Redundant if set in __init__
        # model_save_path=test_model_path # Redundant if set in __init__
    )

    # --- Prediction Example (using a newly loaded instance) ---
    print("\n--- Predicting with a Loaded Anomaly Detection Model ---")
    # Simulate loading the model and processor (scaler) as it would be in a prediction service
    # Ensure the paths point to where the artifacts were saved during training.
    anomaly_model_predictor = AnomalyDetectionModel(
        model_path=test_model_path,
        processor_scaler_path=test_scaler_path
    )

    if anomaly_model_predictor.model and anomaly_model_predictor.processor._fitted:
        test_queries_for_prediction = [
            "SELECT id, name FROM users WHERE status = 'active'", # Normal-looking
            "1' OR '1'='1'; -- comment", # Clearly malicious
            "SELECT card_number FROM credit_cards WHERE user_id = 1 UNION SELECT password FROM users WHERE user_id = 1", # Malicious
            "INSERT INTO audit (action, user_id, details) VALUES ('login_attempt_failed', 100, '{\"ip\": \"1.2.3.4\"}')", # Normal
            "DROP TABLE important_data; SELECT SLEEP(10);", # Malicious
            "SELECT version()" # Benign but sometimes flagged by simple rules
        ]

        prediction_results = anomaly_model_predictor.predict_and_score(test_queries_for_prediction)

        print("\nQuery Predictions (1: normal, -1: anomalous) and Scores (lower is more anomalous):")
        if prediction_results:
            for i, query_text in enumerate(test_queries_for_prediction):
                prediction, score = prediction_results[i]
                pred_label = "Normal" if prediction == 1 else "Anomalous"
                print(f"Query: \"{query_text}\"")
                print(f"  Prediction: {prediction} ({pred_label})")
                print(f"  Anomaly Score: {score:.4f}")
                print("-" * 20)
        else:
            print("No prediction results were returned.")
    else:
        print("ERROR: Failed to load model or processor for prediction example. Check paths and training.")

    # Clean up temporary artifacts directory (optional)
    import shutil
    if os.path.exists(TEMP_ARTIFACTS_DIR_MODEL):
        shutil.rmtree(TEMP_ARTIFACTS_DIR_MODEL)
        print(f"\nCleaned up temporary artifacts directory: {TEMP_ARTIFACTS_DIR_MODEL}")
