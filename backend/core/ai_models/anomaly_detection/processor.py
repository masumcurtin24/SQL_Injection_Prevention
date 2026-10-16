# backend/core/ai_models/anomaly_detection/processor.py
import re
import numpy as np
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Any, Union, Optional # Added Optional
import joblib # For saving/loading the scaler
import os # For checking file existence

class QueryProcessor:
    """
    Processes SQL queries to extract features suitable for anomaly detection models.
    """
    def __init__(self, scaler_path: Optional[str] = None): # Added Optional type hint
        """
        Initializes the QueryProcessor.

        Args:
            scaler_path (str, optional): Path to load a pre-fitted scaler.
                                         If None, a new scaler will be created during fit.
        """
        self.sql_keywords = [
            'select', 'from', 'where', 'insert', 'into', 'values', 'update', 'set',
            'delete', 'drop', 'table', 'database', 'create', 'alter', 'union',
            'and', 'or', 'not', 'exec', 'execute', 'char', 'varchar', 'nvarchar',
            'declare', 'cast', 'convert', 'sleep', 'waitfor', 'delay', 'benchmark',
            'like', 'join', 'left', 'right', 'inner', 'outer', 'on', 'group', 'by',
            'order', 'asc', 'desc', 'limit', 'offset', 'having', 'as', 'distinct',
            'count', 'sum', 'avg', 'min', 'max', 'abs', 'sqrt', 'power', 'rand',
            'substring', 'concat', 'replace', 'length', 'upper', 'lower', 'trim',
            'case', 'when', 'then', 'else', 'end', 'exists', 'in', 'between', 'is', 'null'
        ]
        # Pattern to find characters not typically part of standard SQL syntax or common data
        # This aims to catch unusual symbols often used in obfuscation or attacks.
        self.special_chars_pattern = re.compile(r"[^a-zA-Z0-9\s.,;()_=<>!+\-/*%&|~^'\"`#@\[\]{}:?]")
        self.comment_patterns = [
            re.compile(r"--.*"),  # SQL single line comment (to end of line)
            re.compile(r"#.*"),   # MySQL single line comment (to end of line)
            re.compile(r"/\*.*?\*/", re.DOTALL)  # SQL multi-line comment
        ]
        self.scaler = StandardScaler()
        self.scaler_path = scaler_path
        self._fitted = False
        self._feature_names_cache: List[str] = [] # Initialize as empty list

        if self.scaler_path and self._model_exists(self.scaler_path):
            try:
                self.scaler = joblib.load(self.scaler_path)
                # We need a reliable way to get feature names if scaler is loaded.
                # Best practice: save feature names with the scaler, or ensure get_feature_names()
                # is called in a way that populates it (e.g., by processing a dummy query if needed).
                self._fitted = True
                print(f"INFO: Scaler loaded successfully from {self.scaler_path}")
            except Exception as e:
                print(f"WARNING: Could not load scaler from {self.scaler_path}. A new one will be created. Error: {e}")
                self.scaler = StandardScaler() # Reset to a new scaler
        elif self.scaler_path: # Path provided but file doesn't exist
            print(f"WARNING: Scaler path '{self.scaler_path}' provided, but file does not exist. New scaler will be created.")

    def _model_exists(self, path: str) -> bool:
        """Checks if a model file exists at the given path."""
        return os.path.exists(path)

    def _extract_features(self, query: str) -> Dict[str, Union[int, float]]:
        """
        Extracts a set of features from a single SQL query.

        Args:
            query (str): The SQL query string.

        Returns:
            Dict[str, Union[int, float]]: A dictionary of extracted features.
        """
        original_query_length = len(query)
        cleaned_query_for_keywords = query.lower() # For keyword matching, case-insensitive
        
        # Remove comments for some feature calculations
        query_no_comments = query
        for pattern in self.comment_patterns:
            query_no_comments = pattern.sub("", query_no_comments)
        query_no_comments = query_no_comments.strip()
        
        # Use a specific version for keyword counting after comment removal and lowercasing
        cleaned_query_for_keywords_no_comments = query_no_comments.lower()


        features = {}
        # Length features
        features['length_original'] = original_query_length
        features['length_no_comments'] = len(query_no_comments)

        # Character type counts (on query with no comments)
        features['special_chars_count'] = len(self.special_chars_pattern.findall(query_no_comments))
        features['whitespace_count'] = query_no_comments.count(' ')
        features['digit_count'] = sum(c.isdigit() for c in query_no_comments)
        features['uppercase_count'] = sum(c.isupper() for c in query_no_comments) # Count uppercase in no_comments version
        features['lowercase_count'] = sum(c.islower() for c in query_no_comments) # Count lowercase

        # Specific character counts (on query with no comments)
        features['equals_count'] = query_no_comments.count('=')
        features['parentheses_count'] = query_no_comments.count('(') + query_no_comments.count(')')
        features['semicolon_count'] = query_no_comments.count(';')
        features['single_quote_count'] = query_no_comments.count("'")
        features['double_quote_count'] = query_no_comments.count('"')
        features['comma_count'] = query_no_comments.count(',')
        features['hyphen_count'] = query_no_comments.count('-') # Often in comments or string literals
        features['double_hyphen_count'] = query_no_comments.count('--') # SQL comment start
        features['slash_star_count'] = query_no_comments.count('/*') # SQL comment start
        features['star_slash_count'] = query_no_comments.count('*/') # SQL comment end
        features['hash_count'] = query_no_comments.count('#') # MySQL comment start
        features['asterisk_count'] = query_no_comments.count('*')
        features['percent_count'] = query_no_comments.count('%')
        features['pipe_count'] = query_no_comments.count('|')
        features['ampersand_count'] = query_no_comments.count('&')
        features['at_count'] = query_no_comments.count('@') # SQL variables

        # Keyword counts (on lowercased query with no comments)
        # Using regex to find whole words to avoid matching parts of other words
        words = re.findall(r'\b\w+\b', cleaned_query_for_keywords_no_comments)
        for keyword in self.sql_keywords:
            features[f'keyword_{keyword}_count'] = words.count(keyword)

        # Ratio features (based on length_no_comments)
        len_no_comments_for_ratio = features['length_no_comments'] if features['length_no_comments'] > 0 else 1.0
        features['special_chars_ratio'] = features['special_chars_count'] / len_no_comments_for_ratio
        features['digit_ratio'] = features['digit_count'] / len_no_comments_for_ratio
        features['whitespace_ratio'] = features['whitespace_count'] / len_no_comments_for_ratio
        features['uppercase_ratio'] = features['uppercase_count'] / len_no_comments_for_ratio

        # Word-based features
        features['word_count'] = len(words)
        features['distinct_word_count'] = len(set(words))
        features['max_word_length'] = max(len(word) for word in words) if words else 0
        features['avg_word_length'] = sum(len(word) for word in words) / len(words) if words else 0
        
        # Entropy (Shannon entropy of character distribution in query_no_comments)
        if query_no_comments:
            prob = [float(query_no_comments.count(c)) / len(query_no_comments) for c in dict.fromkeys(list(query_no_comments))]
            features['entropy'] = -sum([p * np.log2(p) for p in prob])
        else:
            features['entropy'] = 0.0

        # Number of logical operators
        logical_ops = ['and', 'or', 'not'] # These are already counted as keywords
        features['logical_op_count_explicit'] = sum(features[f'keyword_{op}_count'] for op in logical_ops)

        # Number of comparison operators
        comparison_ops_pattern = re.compile(r"(=|<>|!=|>|<|>=|<=|like\b|between\b|in\b|is\s+null\b|is\s+not\s+null\b)")
        features['comparison_op_count'] = len(comparison_ops_pattern.findall(cleaned_query_for_keywords_no_comments))
        
        # Count of hex patterns (e.g., 0xdeadbeef) - basic check
        features['hex_pattern_count'] = len(re.findall(r'0x[0-9a-fA-F]+', query_no_comments))

        # Count of SQL function calls (very basic: word followed by parenthesis)
        features['function_call_count'] = len(re.findall(r'\b\w+\s*\(', query_no_comments))

        # Cache feature names if not already done (based on the first processed query)
        if not self._feature_names_cache:
             self._feature_names_cache = sorted(features.keys())

        return features

    def get_feature_names(self) -> List[str]:
        """
        Returns the names of the features that this processor extracts, in order.
        Ensures features are extracted at least once to populate the cache.
        """
        if not self._feature_names_cache:
            # Process a dummy query to populate feature names if cache is empty
            # This ensures that even if fit/transform hasn't been called yet (e.g. loading a scaler),
            # we can still get the expected feature names.
            _ = self._extract_features("SELECT 1") # The result is discarded, only populates cache
        return self._feature_names_cache

    def transform(self, queries: List[str]) -> np.ndarray:
        """
        Transforms a list of SQL queries into a numerical feature matrix.

        Args:
            queries (List[str]): A list of SQL query strings.

        Returns:
            np.ndarray: A NumPy array where rows are queries and columns are features.
                        Returns an empty array if the scaler is not fitted or no queries.
        """
        if not self._fitted:
            print("ERROR: Scaler is not fitted and could not be loaded. Call fit() or provide a valid scaler_path.")
            return np.array([])
        if not queries:
            return np.array([])

        # Ensure feature names are populated and consistent
        feature_names = self.get_feature_names()
        
        numerical_features_list = []
        for q_idx, q_text in enumerate(queries):
            try:
                raw_features = self._extract_features(q_text)
                # Ensure all features are present and in the correct order, defaulting to 0 if a feature is unexpectedly missing
                ordered_features = [raw_features.get(name, 0.0) for name in feature_names]
                numerical_features_list.append(ordered_features)
            except Exception as e:
                print(f"ERROR: Failed to extract features for query at index {q_idx}: '{q_text[:100]}...'. Error: {e}")
                # Append a vector of zeros or handle as per strategy (e.g., skip query)
                numerical_features_list.append([0.0] * len(feature_names))


        if not numerical_features_list: # Should not happen if queries list was not empty
            return np.array([])

        feature_matrix = np.array(numerical_features_list, dtype=float)
        # Replace NaN or Inf that might have crept in from divisions by zero or other issues
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=np.finfo(np.float64).max, neginf=np.finfo(np.float64).min)

        return self.scaler.transform(feature_matrix)

    def fit(self, queries: List[str], scaler_save_path: Optional[str] = None) -> 'QueryProcessor':
        """
        Fits the processor on a list of SQL queries. This typically involves
        fitting the feature scaler.

        Args:
            queries (List[str]): A list of SQL query strings (typically normal queries).
            scaler_save_path (str, optional): Path to save the fitted scaler.
                                              If None, the scaler is not saved automatically after fitting.

        Returns:
            QueryProcessor: The fitted QueryProcessor instance.
        """
        if not queries:
            print("WARNING: No queries provided to fit the processor.")
            return self

        # Populate feature names using the first query, then use these names consistently for all.
        # This ensures self._feature_names_cache is set based on the first query in the training set.
        _ = self._extract_features(queries[0])
        feature_names = self.get_feature_names()

        numerical_features_list = []
        for q_idx, q_text in enumerate(queries):
            try:
                raw_features = self._extract_features(q_text)
                ordered_features = [raw_features.get(name, 0.0) for name in feature_names]
                numerical_features_list.append(ordered_features)
            except Exception as e:
                print(f"ERROR: Failed to extract features during fit for query at index {q_idx}: '{q_text[:100]}...'. Error: {e}")
                # Skip this query or append zeros
                numerical_features_list.append([0.0] * len(feature_names))
        
        if not numerical_features_list:
            print("WARNING: No features could be extracted from the provided queries for fitting.")
            return self

        feature_matrix = np.array(numerical_features_list, dtype=float)
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=np.finfo(np.float64).max, neginf=np.finfo(np.float64).min)


        if feature_matrix.size == 0:
            print("WARNING: Feature matrix is empty after processing queries for fitting.")
            return self

        self.scaler.fit(feature_matrix)
        self._fitted = True
        print("INFO: QueryProcessor (Scaler) fitted successfully.")

        # Determine save path
        _save_path = scaler_save_path if scaler_save_path else self.scaler_path
        if _save_path:
            self.save_scaler(_save_path)
        
        return self

    def fit_transform(self, queries: List[str], scaler_save_path: Optional[str] = None) -> np.ndarray:
        """
        Fits the processor and then transforms the queries.

        Args:
            queries (List[str]): A list of SQL query strings.
            scaler_save_path (str, optional): Path to save the fitted scaler.

        Returns:
            np.ndarray: The transformed feature matrix.
        """
        self.fit(queries, scaler_save_path)
        return self.transform(queries)

    def save_scaler(self, path: str) -> None:
        """
        Saves the fitted scaler to a file.

        Args:
            path (str): The path to save the scaler.
        """
        if not self._fitted:
            print("WARNING: Scaler is not fitted. Cannot save.")
            return
        try:
            # Ensure directory exists before saving
            dir_name = os.path.dirname(path)
            if dir_name: # Check if path includes a directory
                os.makedirs(dir_name, exist_ok=True)
            joblib.dump(self.scaler, path)
            print(f"INFO: Scaler saved successfully to {path}")
            self.scaler_path = path # Update internal path if saved to a new location
        except Exception as e:
            print(f"ERROR: Error saving scaler to {path}: {e}")

if __name__ == '__main__':
    # Example Usage
    temp_artifacts_dir = "./temp_processor_artifacts" # Changed name to avoid conflict
    os.makedirs(temp_artifacts_dir, exist_ok=True)
    scaler_file = os.path.join(temp_artifacts_dir, "test_query_scaler.joblib")

    processor = QueryProcessor() # Initialize without a path, will create new scaler

    sample_normal_queries = [
        "SELECT id, name, email FROM users WHERE id = 1;",
        "INSERT INTO products (name, price, category) VALUES ('Laptop', 1200.00, 'Electronics');",
        "UPDATE customers SET address = '123 New St' WHERE customer_id = 101 AND name LIKE '%Smith%';" ,
        "SELECT COUNT(*) FROM orders WHERE order_date > '2024-01-01' AND status = 'completed';"
    ]
    sample_malicious_queries = [
        "SELECT * FROM users WHERE username = 'admin' --' AND password = 'password123';",
        "1' OR '1'='1", # Classic SQLi
        "SELECT name FROM users WHERE id = 1 UNION SELECT credit_card, cc_expiry FROM user_data WHERE user_id = 1; --",
        "DROP TABLE users; --",
        "SELECT /* evil comment */ name FROM users WHERE id = 0xDEADBEEF"
    ]
    all_queries_for_test = sample_normal_queries + sample_malicious_queries

    print("\n--- Fitting Processor ---")
    processor.fit(sample_normal_queries, scaler_save_path=scaler_file) # Fit on normal queries
    
    # Print feature names after fitting
    feature_names_from_processor = processor.get_feature_names()
    print(f"Feature names ({len(feature_names_from_processor)}): {feature_names_from_processor}")


    print("\n--- Transforming All Test Queries (using fitted scaler) ---")
    transformed_features = processor.transform(all_queries_for_test)
    if transformed_features.size > 0:
        print(f"Shape of transformed features: {transformed_features.shape}")
        print("\nFirst transformed normal query features (scaled):")
        print(transformed_features[0])
        print("\nFirst transformed malicious query features (scaled):")
        print(transformed_features[len(sample_normal_queries)])
    else:
        print("No features transformed.")


    print("\n--- Loading Processor with Pre-fitted Scaler ---")
    loaded_processor = QueryProcessor(scaler_path=scaler_file) # Load the saved scaler
    if loaded_processor._fitted:
        # Crucial: Call get_feature_names or process a dummy query if feature names are not persisted with scaler
        # In this implementation, get_feature_names() will work as it processes a dummy query if cache is empty.
        _ = loaded_processor.get_feature_names() # Ensure feature names are initialized for the loaded processor

        print("\nTransforming malicious queries with loaded processor:")
        transformed_features_loaded = loaded_processor.transform(sample_malicious_queries)
        if transformed_features_loaded.size > 0:
            print(f"Shape of transformed features (loaded scaler): {transformed_features_loaded.shape}")
            print("First transformed malicious query (loaded scaler):")
            print(transformed_features_loaded[0])
        else:
            print("No features transformed with loaded processor.")
    else:
        print("ERROR: Loaded processor's scaler is not fitted.")

    # Clean up
    import shutil
    if os.path.exists(temp_artifacts_dir):
        shutil.rmtree(temp_artifacts_dir)
        print(f"\nCleaned up temporary artifacts directory: {temp_artifacts_dir}")