# Confidence_Based_Hybrid_Model.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import time
import warnings
warnings.filterwarnings('ignore')

class ConfidenceBasedHybridModel:
    """
    Confidence-Based Hybrid Model for VANET Threat Detection
    
    Strategy:
    - Uses XGBoost for initial fast prediction
    - Delegates to SVM when prediction confidence is below threshold
    - Optimizes for both speed and accuracy
    """
    
    def __init__(self, confidence_threshold=0.7, verbose=True):
        """
        Initialize the hybrid model
        
        Parameters:
        -----------
        confidence_threshold : float (0-1)
            Threshold for determining when to use SVM
            Higher values = more SVM usage = higher accuracy but slower
            Lower values = more XGBoost usage = faster but potentially less accurate
        verbose : bool
            Whether to print training progress and statistics
        """
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose
        
        # Initialize models
        self.xgb = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.3,
            objective='multi:softprob',
            random_state=42,
            use_label_encoder=False,
            eval_metric='mlogloss',
            n_jobs=-1  # Use all CPU cores
        )
        
        self.svm = SVC(
            kernel="rbf",
            C=1.0,
            gamma="scale",
            probability=True,  # Need probabilities for confidence
            random_state=42,
            cache_size=500  # Increase cache for faster predictions
        )
        
        # Statistics tracking
        self.stats = {
            'xgb_predictions': 0,
            'svm_predictions': 0,
            'training_time': 0,
            'avg_confidence': 0
        }
        
        # For label encoding
        self.label_encoder = None
        self.classes_ = None
        
    def fit(self, X, y):
        """
        Train both XGBoost and SVM models
        """
        start_time = time.time()
        
        if self.verbose:
            print("Training Confidence-Based Hybrid Model...")
            print("-" * 50)
        
        # Store classes for later use
        self.classes_ = np.unique(y)
        
        # Train XGBoost
        if self.verbose:
            print("Training XGBoost model...")
        xgb_start = time.time()
        self.xgb.fit(X, y)
        xgb_time = time.time() - xgb_start
        
        # Train SVM
        if self.verbose:
            print("Training SVM model...")
        svm_start = time.time()
        self.svm.fit(X, y)
        svm_time = time.time() - svm_start
        
        self.stats['training_time'] = time.time() - start_time
        
        if self.verbose:
            print(f"\n✓ XGBoost training time: {xgb_time:.2f}s")
            print(f"✓ SVM training time: {svm_time:.2f}s")
            print(f"✓ Total training time: {self.stats['training_time']:.2f}s")
            print("-" * 50)
        
        return self
    
    def predict(self, X, return_stats=False):
        """
        Make predictions using the hybrid approach
        
        Parameters:
        -----------
        X : array-like
            Features to predict
        return_stats : bool
            Whether to return prediction statistics
        """
        n_samples = X.shape[0]
        
        # Get XGBoost predictions and probabilities
        xgb_proba = self.xgb.predict_proba(X)
        xgb_pred = self.xgb.predict(X)
        
        # Calculate confidence (max probability for each sample)
        confidence = np.max(xgb_proba, axis=1)
        self.stats['avg_confidence'] = np.mean(confidence)
        
        # Identify low confidence predictions
        low_conf_mask = confidence < self.confidence_threshold
        n_low_conf = np.sum(low_conf_mask)
        
        # Initialize predictions with XGBoost results
        predictions = xgb_pred.copy()
        
        # Use SVM for low confidence predictions
        if n_low_conf > 0:
            if self.verbose:
                print(f"\n🔍 Routing {n_low_conf}/{n_samples} low-confidence samples to SVM...")
            
            svm_pred = self.svm.predict(X[low_conf_mask])
            predictions[low_conf_mask] = svm_pred
        
        # Update statistics
        self.stats['xgb_predictions'] = np.sum(~low_conf_mask)
        self.stats['svm_predictions'] = n_low_conf
        
        if return_stats:
            return predictions, {
                'confidence': confidence,
                'used_svm': low_conf_mask,
                'stats': self.stats
            }
        
        return predictions
    
    def predict_proba(self, X):
        """
        Get probability predictions using the hybrid approach
        """
        n_samples = X.shape[0]
        
        # Get XGBoost probabilities
        xgb_proba = self.xgb.predict_proba(X)
        
        # Calculate confidence
        confidence = np.max(xgb_proba, axis=1)
        
        # Identify low confidence predictions
        low_conf_mask = confidence < self.confidence_threshold
        
        # Initialize with XGBoost probabilities
        probabilities = xgb_proba.copy()
        
        # Use SVM for low confidence predictions
        if np.any(low_conf_mask):
            svm_proba = self.svm.predict_proba(X[low_conf_mask])
            probabilities[low_conf_mask] = svm_proba
        
        return probabilities
    
    def get_model_usage_report(self):
        """
        Get detailed statistics about model usage
        """
        total = self.stats['xgb_predictions'] + self.stats['svm_predictions']
        if total == 0:
            return "No predictions made yet."
        
        report = f"""
        Model Usage Statistics:
        ----------------------
        Total Predictions: {total}
        XGBoost Used: {self.stats['xgb_predictions']} ({100*self.stats['xgb_predictions']/total:.1f}%)
        SVM Used: {self.stats['svm_predictions']} ({100*self.stats['svm_predictions']/total:.1f}%)
        Average Confidence: {self.stats['avg_confidence']:.3f}
        Confidence Threshold: {self.confidence_threshold}
        """
        return report
    
    def optimize_threshold(self, X_val, y_val, thresholds=None):
        """
        Find optimal confidence threshold using validation data
        """
        if thresholds is None:
            thresholds = np.arange(0.5, 0.95, 0.05)
        
        results = []
        
        for thresh in thresholds:
            self.confidence_threshold = thresh
            pred = self.predict(X_val, return_stats=False)
            acc = accuracy_score(y_val, pred)
            
            results.append({
                'threshold': thresh,
                'accuracy': acc,
                'xgb_usage': self.stats['xgb_predictions'],
                'svm_usage': self.stats['svm_predictions']
            })
        
        results_df = pd.DataFrame(results)
        best_idx = results_df['accuracy'].idxmax()
        best_threshold = results_df.loc[best_idx, 'threshold']
        
        # Set to optimal threshold
        self.confidence_threshold = best_threshold
        
        if self.verbose:
            print(f"\nOptimal Confidence Threshold: {best_threshold:.2f}")
            print(f"Best Accuracy: {results_df.loc[best_idx, 'accuracy']*100:.2f}%")
        
        return results_df
    
    def save_model(self, filepath='hybrid_model.pkl'):
        """Save the trained model"""
        joblib.dump(self, filepath)
        if self.verbose:
            print(f"Model saved to {filepath}")
    
    @staticmethod
    def load_model(filepath='hybrid_model.pkl'):
        """Load a trained model"""
        return joblib.load(filepath)


# === MAIN EXECUTION ===
if __name__ == "__main__":
    
    print("="*60)
    print("CONFIDENCE-BASED HYBRID MODEL FOR VANET THREAT DETECTION")
    print("="*60)
    
    # === Load dataset ===
    df = pd.read_csv("vanet_threat_dataset.csv")
    
    # === Define features and label ===
    y = df["threat_type"]
    X = df.drop(columns=["threat_type", "timestamp", "vehicle_id"], errors="ignore")
    
    # === Encode target variable ===
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # === Separate numeric and categorical columns ===
    cat_cols = [c for c in X.columns if X[c].dtype == "object"]
    num_cols = [c for c in X.columns if c not in cat_cols]
    
    # === Preprocessing ===
    preprocessor = ColumnTransformer([
        ("num", StandardScaler(), num_cols),
        ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols)
    ])
    
    # === Train/Validation/Test Split ===
    # First split: separate test set
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y_encoded, test_size=0.2, stratify=y_encoded, random_state=42
    )
    
    # Second split: separate train and validation
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.2, stratify=y_temp, random_state=42
    )
    
    # Transform data
    X_train_transformed = preprocessor.fit_transform(X_train)
    X_val_transformed = preprocessor.transform(X_val)
    X_test_transformed = preprocessor.transform(X_test)
    
    # === Initialize and train the hybrid model ===
    hybrid_model = ConfidenceBasedHybridModel(
        confidence_threshold=0.7,  # Initial threshold
        verbose=True
    )
    
    # Train the model
    hybrid_model.fit(X_train_transformed, y_train)
    
    # === Optimize confidence threshold using validation set ===
    print("\n" + "="*60)
    print("OPTIMIZING CONFIDENCE THRESHOLD")
    print("="*60)
    
    threshold_results = hybrid_model.optimize_threshold(
        X_val_transformed, y_val,
        thresholds=np.arange(0.5, 0.91, 0.1)
    )
    
    print("\nThreshold Optimization Results:")
    print(threshold_results.to_string(index=False))
    
    # === Make predictions on test set ===
    print("\n" + "="*60)
    print("FINAL EVALUATION ON TEST SET")
    print("="*60)
    
    # Predict with statistics
    predictions, pred_info = hybrid_model.predict(
        X_test_transformed, 
        return_stats=True
    )
    
    # Calculate accuracy
    accuracy = accuracy_score(y_test, predictions)
    
    print(f"\n🎯 Test Set Accuracy: {accuracy * 100:.2f}%")
    
    # Model usage report
    print(hybrid_model.get_model_usage_report())
    
    # === Detailed Classification Report ===
    print("\n" + "="*60)
    print("CLASSIFICATION REPORT")
    print("="*60)
    
    # Convert back to original labels
    pred_labels = label_encoder.inverse_transform(predictions)
    test_labels = label_encoder.inverse_transform(y_test)
    
    print(classification_report(test_labels, pred_labels))
    
    # === Performance Analysis ===
    print("\n" + "="*60)
    print("PERFORMANCE ANALYSIS")
    print("="*60)
    
    # Estimate inference time
    start_time = time.time()
    _ = hybrid_model.predict(X_test_transformed)
    inference_time = time.time() - start_time
    
    print(f"Total inference time for {len(X_test)} samples: {inference_time:.3f}s")
    print(f"Average inference time per sample: {1000*inference_time/len(X_test):.2f}ms")
    
    # Compare with pure models
    print("\n--- Comparison with Individual Models ---")
    
    # Pure XGBoost
    start_time = time.time()
    xgb_only_pred = hybrid_model.xgb.predict(X_test_transformed)
    xgb_time = time.time() - start_time
    xgb_acc = accuracy_score(y_test, xgb_only_pred)
    
    # Pure SVM
    start_time = time.time()
    svm_only_pred = hybrid_model.svm.predict(X_test_transformed)
    svm_time = time.time() - start_time
    svm_acc = accuracy_score(y_test, svm_only_pred)
    
    print(f"\nXGBoost Only - Accuracy: {xgb_acc*100:.2f}%, Time: {xgb_time:.3f}s")
    print(f"SVM Only - Accuracy: {svm_acc*100:.2f}%, Time: {svm_time:.3f}s")
    print(f"Hybrid Model - Accuracy: {accuracy*100:.2f}%, Time: {inference_time:.3f}s")
    
    # Speed improvement
    speed_improvement = (svm_time - inference_time) / svm_time * 100
    print(f"\n✨ Speed Improvement over pure SVM: {speed_improvement:.1f}%")
    
    # === Save the model ===
    print("\n" + "="*60)
    print("SAVING MODEL")
    print("="*60)
    
    hybrid_model.save_model('vanet_hybrid_model.pkl')
    
    # Save preprocessor and label encoder
    joblib.dump(preprocessor, 'vanet_preprocessor.pkl')
    joblib.dump(label_encoder, 'vanet_label_encoder.pkl')
    print("✓ Preprocessor saved to vanet_preprocessor.pkl")
    print("✓ Label encoder saved to vanet_label_encoder.pkl")
    
    print("\n" + "="*60)
    print("MODEL TRAINING COMPLETE!")
    print("="*60)
