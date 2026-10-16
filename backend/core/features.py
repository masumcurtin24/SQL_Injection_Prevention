# SQL_Injection_Prevention/backend/core/features.py
from sklearn.base import BaseEstimator, TransformerMixin
import numpy as np

# This class is now in a permanent file, allowing both the notebook and the
# main application to import and use it consistently.
class QuerySyntaxFeatures(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        features = []
        for query in X:
            query = str(query).lower()
            
            length = len(query)
            
            sql_keywords = ['select', 'from', 'where', 'union', 'insert', 'update', 'delete', 'drop', 'exec', 'order by', 'group by']
            keyword_count = sum(query.count(kw) for kw in sql_keywords)
            
            special_chars = ["'", "\"", ";", "--", "/*", "*/", "="]
            special_char_count = sum(query.count(sc) for sc in special_chars)
            
            if length > 0:
                keyword_ratio = keyword_count / length
                special_char_ratio = special_char_count / length
            else:
                keyword_ratio = 0
                special_char_ratio = 0
                
            has_or = 1 if ' or ' in query else 0
            has_and = 1 if ' and ' in query else 0
            has_comment = 1 if '--' in query or '/*' in query else 0
            
            features.append([
                length, keyword_count, special_char_count,
                keyword_ratio, special_char_ratio,
                has_or, has_and, has_comment
            ])
            
        return np.array(features)