# ML Models

This directory stores trained machine-learning models used by NetScan's
detection engine.

## Files

| File                    | Description                                              |
|-------------------------|----------------------------------------------------------|
| `isolation_forest.pkl`  | Serialised `IsolationForest` model (scikit-learn / joblib)|
| `ml_config.yaml`        | Hyperparameters and feature list used during training     |
| `train_notebook.ipynb`  | Jupyter notebook for training / evaluation                |

## Training workflow

1. Capture several hours of **known-normal** network traffic using
   `scripts/run_capture.py --mode live`.
2. Export `network_features` rows from the database (CSV or direct query).
3. Open `train_notebook.ipynb` and run all cells.
4. The notebook saves `isolation_forest.pkl` in this directory.
5. Restart the detection pipeline — `ml_model.py` will load the new model
   automatically.

## Notes

- Models are **not** committed to Git (add `*.pkl` to `.gitignore`).
- Re-train periodically as "normal" traffic patterns evolve.
