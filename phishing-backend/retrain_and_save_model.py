import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
import joblib

# Load dataset (phishing.csv must be in the same folder)
data = pd.read_csv("phishing.csv")

# Drop columns not used in training
X = data.drop(columns=["class", "Index"])  # Drop 'Index' only if it's not a feature
y = data["class"]

# Split dataset
X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = GradientBoostingClassifier(max_depth=4, learning_rate=0.7)
model.fit(X_train, y_train)

# Save model using joblib
joblib.dump(model, "phishing_model.pkl")

print("✅ Model retrained and saved as phishing_model.pkl")
