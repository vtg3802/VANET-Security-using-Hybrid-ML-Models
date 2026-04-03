# XGBoost_Model.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score, 
    classification_report,
    confusion_matrix
)
import seaborn as sns
import matplotlib.pyplot as plt

# === Load dataset ===
df = pd.read_csv("vanet_threat_dataset.csv")

# === Define features and label ===
y = df["threat_type"]
X = df.drop(columns=["threat_type", "timestamp", "vehicle_id"], errors="ignore")

# === Encode target variable for XGBoost (needs numeric labels) ===
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# === Separate numeric and categorical columns ===
cat_cols = [c for c in X.columns if X[c].dtype == "object"]
num_cols = [c for c in X.columns if c not in cat_cols]

# === Preprocessing ===
pre = ColumnTransformer([
    ("num", StandardScaler(), num_cols),
    ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols)
])

# === Train/Test Split ===
Xtr, Xte, ytr, yte = train_test_split(
    X, y_encoded, test_size=0.25, stratify=y_encoded, random_state=42
)

# === XGBoost Model ===
model = Pipeline([
    ("pre", pre),
    ("clf", XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.3,
        objective='multi:softprob',
        random_state=42,
        use_label_encoder=False,
        eval_metric='mlogloss'
    ))
])

# === Train and Evaluate ===
print("="*60)
print("XGBOOST MODEL - VANET THREAT DETECTION")
print("="*60)

model.fit(Xtr, ytr)
yp = model.predict(Xte)

# === Calculate Metrics ===
accuracy = accuracy_score(yte, yp)

# For multi-class classification, calculate metrics with different averaging strategies
precision_macro = precision_score(yte, yp, average='macro', zero_division=0)
precision_weighted = precision_score(yte, yp, average='weighted', zero_division=0)

recall_macro = recall_score(yte, yp, average='macro', zero_division=0)
recall_weighted = recall_score(yte, yp, average='weighted', zero_division=0)

f1_macro = f1_score(yte, yp, average='macro', zero_division=0)
f1_weighted = f1_score(yte, yp, average='weighted', zero_division=0)

# === Display Overall Metrics ===
print("\n" + "="*60)
print("OVERALL PERFORMANCE METRICS")
print("="*60)

print(f"\n📊 Accuracy: {accuracy * 100:.2f}%")
print(f"\n📈 Precision:")
print(f"   - Macro Average: {precision_macro * 100:.2f}%")
print(f"   - Weighted Average: {precision_weighted * 100:.2f}%")
print(f"\n📉 Recall:")
print(f"   - Macro Average: {recall_macro * 100:.2f}%")
print(f"   - Weighted Average: {recall_weighted * 100:.2f}%")
print(f"\n⚖️ F1-Score:")
print(f"   - Macro Average: {f1_macro * 100:.2f}%")
print(f"   - Weighted Average: {f1_weighted * 100:.2f}%")

# === Per-Class Metrics ===
print("\n" + "="*60)
print("PER-CLASS PERFORMANCE METRICS")
print("="*60)

# Get class names
class_names = label_encoder.classes_

# Calculate per-class metrics
precision_per_class = precision_score(yte, yp, average=None, zero_division=0)
recall_per_class = recall_score(yte, yp, average=None, zero_division=0)
f1_per_class = f1_score(yte, yp, average=None, zero_division=0)

# Create a DataFrame for better visualization
metrics_df = pd.DataFrame({
    'Threat Type': class_names,
    'Precision (%)': precision_per_class * 100,
    'Recall (%)': recall_per_class * 100,
    'F1-Score (%)': f1_per_class * 100
})

print("\n" + metrics_df.to_string(index=False, float_format='%.2f'))

# === Detailed Classification Report ===
print("\n" + "="*60)
print("DETAILED CLASSIFICATION REPORT")
print("="*60)

# Convert predictions back to original labels
yp_labels = label_encoder.inverse_transform(yp)
yte_labels = label_encoder.inverse_transform(yte)

print("\n" + classification_report(yte_labels, yp_labels, digits=3))

# === Confusion Matrix ===
print("\n" + "="*60)
print("CONFUSION MATRIX")
print("="*60)

cm = confusion_matrix(yte, yp)
cm_df = pd.DataFrame(cm, index=class_names, columns=class_names)

print("\nConfusion Matrix (Actual vs Predicted):")
print(cm_df.to_string())

# === Feature Importance ===
print("\n" + "="*60)
print("TOP 10 MOST IMPORTANT FEATURES")
print("="*60)

# Get feature names after preprocessing
feature_names = []
if num_cols:
    feature_names.extend(num_cols)
if cat_cols:
    # Get one-hot encoded feature names
    cat_features = model.named_steps['pre'].transformers_[1][1].get_feature_names_out(cat_cols)
    feature_names.extend(cat_features)

# Get feature importance
importance = model.named_steps['clf'].feature_importances_

# Create importance dataframe
importance_df = pd.DataFrame({
    'Feature': feature_names,
    'Importance Score': importance
}).sort_values('Importance Score', ascending=False).head(10)

print("\n" + importance_df.to_string(index=False))

# === Model Performance Summary ===
print("\n" + "="*60)
print("MODEL PERFORMANCE SUMMARY")
print("="*60)

# Calculate support for each class
support = np.bincount(yte)

# Find best and worst performing classes
best_class_idx = np.argmax(f1_per_class)
worst_class_idx = np.argmin(f1_per_class)

print(f"\n✅ Best Performing Threat Type: {class_names[best_class_idx]}")
print(f"   - F1-Score: {f1_per_class[best_class_idx]*100:.2f}%")
print(f"   - Precision: {precision_per_class[best_class_idx]*100:.2f}%")
print(f"   - Recall: {recall_per_class[best_class_idx]*100:.2f}%")

print(f"\n⚠️ Worst Performing Threat Type: {class_names[worst_class_idx]}")
print(f"   - F1-Score: {f1_per_class[worst_class_idx]*100:.2f}%")
print(f"   - Precision: {precision_per_class[worst_class_idx]*100:.2f}%")
print(f"   - Recall: {recall_per_class[worst_class_idx]*100:.2f}%")

# === Recommendations ===
print("\n" + "="*60)
print("RECOMMENDATIONS FOR IMPROVEMENT")
print("="*60)

recommendations = []

# Check for class imbalance issues
if recall_per_class[worst_class_idx] < 0.5:
    recommendations.append(f"• Consider addressing class imbalance for '{class_names[worst_class_idx]}' threat type")

# Check overall performance
if f1_weighted < 0.8:
    recommendations.append("• Consider hyperparameter tuning using GridSearchCV or RandomizedSearchCV")
    recommendations.append("• Try increasing n_estimators to 200-300 for potentially better performance")

# Check for overfitting indicators
if accuracy > 0.95:
    recommendations.append("• High accuracy may indicate overfitting - consider cross-validation")
    recommendations.append("• Add regularization by adjusting 'reg_alpha' and 'reg_lambda' parameters")

if not recommendations:
    recommendations.append("• Model is performing well! Consider ensemble methods for further improvement")

for rec in recommendations:
    print(rec)

# === Quick Hyperparameter Suggestions ===
print("\n" + "="*60)
print("SUGGESTED HYPERPARAMETERS FOR OPTIMIZATION")
print("="*60)

print("""
param_grid = {
    'clf__n_estimators': [100, 200, 300],
    'clf__max_depth': [4, 6, 8, 10],
    'clf__learning_rate': [0.01, 0.1, 0.3],
    'clf__subsample': [0.8, 1.0],
    'clf__colsample_bytree': [0.8, 1.0],
    'clf__reg_alpha': [0, 0.1, 1],
    'clf__reg_lambda': [1, 1.5, 2]
}

# Use with GridSearchCV or RandomizedSearchCV for optimization
""")

print("\n" + "="*60)
print("MODEL TRAINING COMPLETE!")
print("="*60)
