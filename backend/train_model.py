import os
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix


print("🚀 Starting PhishGuard model training (SNN baseline)...")


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "URL dataset_features.csv"
LABEL_COL = "phishing"

if not DATASET_PATH.exists():
    raise FileNotFoundError(
        f"Dataset '{DATASET_PATH.name}' not found in backend directory. "
        f"Place your processed CSV here (same schema as in the notebook)."
    )

df = pd.read_csv(str(DATASET_PATH))
print(f"Dataset loaded with shape: {df.shape}")

feature_cols = [c for c in df.columns if c not in ["URL", LABEL_COL]]
X = df[feature_cols].values.astype(float)
y = df[LABEL_COL].values.astype(int)

X_train_full, X_test, y_train_full, y_test = train_test_split(
    X, y, test_size=0.20, stratify=y, random_state=42
)

X_train, X_val, y_train, y_val = train_test_split(
    X_train_full, y_train_full, test_size=0.20, stratify=y_train_full, random_state=42
)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_val = scaler.transform(X_val)
X_test = scaler.transform(X_test)

print("Data prepared:")
print("  Train:", X_train.shape)
print("  Val  :", X_val.shape)
print("  Test :", X_test.shape)


def build_snn(input_dim: int) -> tf.keras.Model:
    inp = tf.keras.layers.Input(shape=(input_dim,))
    x = tf.keras.layers.Dense(28, activation="relu")(inp)
    out = tf.keras.layers.Dense(2, activation="softmax")(x)
    model = tf.keras.Model(inp, out)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(1e-3),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


model = build_snn(X_train.shape[1])

history = model.fit(
    X_train,
    y_train,
    validation_data=(X_val, y_val),
    epochs=50,
    batch_size=128,
    callbacks=[tf.keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)],
    verbose=2,
)

val_loss, val_acc = model.evaluate(X_val, y_val, verbose=0)
test_loss, test_acc = model.evaluate(X_test, y_test, verbose=0)

print(f"\nValidation Accuracy: {val_acc*100:.2f}%")
print(f"Test Accuracy: {test_acc*100:.2f}%")

y_pred_probs = model.predict(X_test, verbose=0)
y_pred = y_pred_probs.argmax(axis=1)

print("\nClassification report:")
print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

print("💾 Saving trained model & scaler...")
model.save(os.path.join(MODEL_DIR, "phishguard_model.keras"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.save"))

print("✅ Model & scaler saved in backend/model/")
print("🎉 Training complete — run this again only when retraining.")
