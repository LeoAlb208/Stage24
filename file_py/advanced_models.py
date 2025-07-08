from .lib import xgb, accuracy_score, roc_auc_score, classification_report

class AdvancedModels:
    """
    This class provides methods for training and evaluating advanced machine learning models.
    """

    def train_xgboost(X_train, y_train, X_test, y_test):
        """
        Trains an XGBoost classifier and evaluates its performance on the test data.

        Parameters:
        - X_train: array-like, shape (n_samples, n_features), training input data
        - y_train: array-like, shape (n_samples,), training target labels
        - X_test: array-like, shape (n_samples, n_features), testing input data
        - y_test: array-like, shape (n_samples,), testing target labels

        Returns:
        - bst: trained XGBoost model
        """
        dtrain = xgb.DMatrix(X_train, label=y_train)
        dtest = xgb.DMatrix(X_test, label=y_test)

        val_pos = y_train[y_train == 1].count()
        val_neg = y_train[y_train == 0].count()
        scale_pos_weight = val_neg / val_pos

        params = {
            'objective': 'binary:logistic',
            'scale_pos_weight': scale_pos_weight,
            'max_depth': 5,
            'eta': 0.1,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'min_child_weight': 5,
            'eval_metric': 'auc'
        }
        num_round = 200

        evals = [(dtrain, 'train'), (dtest, 'eval')]
        bst = xgb.train(params, dtrain, num_round, evals, early_stopping_rounds=10)

        y_pred_prob = bst.predict(dtest)
        y_pred = (y_pred_prob > 0.5).astype(int)

        accuracy = accuracy_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_pred_prob)
        print(f'Accuracy: {accuracy * 100:.2f}%')
        print(f'ROC AUC: {roc_auc:.2f}')
        print(classification_report(y_test, y_pred))
        return bst