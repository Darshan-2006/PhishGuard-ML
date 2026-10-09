import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
import pickle
import os

print("Loading dataset...")
df = pd.read_csv('data/dataset.csv')

# Drop the index column
X = df.drop(columns=['index', 'Target'])
y = df['Target']

print(f"Training on {X.shape[0]} samples with {X.shape[1]} features...")

# Train Gradient Boosting Classifier
gbc = GradientBoostingClassifier(random_state=42)
gbc.fit(X, y)

print("Saving model...")
os.makedirs("models", exist_ok=True)
with open('models/model.pkl', 'wb') as f:
    pickle.dump(gbc, f)

print("Model successfully retrained and saved to models/model.pkl!")
