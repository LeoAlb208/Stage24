from .lib import DecisionTreeClassifier, AdaBoostClassifier, XGBClassifier, CatBoostClassifier, MLPClassifier, QuadraticDiscriminantAnalysis, ExtraTreesClassifier, classification_report

class InitialTraining:
    """
    This class provides methods for training and evaluating initial machine learning models.
    """

    def train_and_evaluate_initial_models(X_train, y_train, X_test, y_test):
        """
        Trains and evaluates a set of initial machine learning models on the provided training and testing data.

        Parameters:
        - X_train: array-like, shape (n_samples, n_features), training input data
        - y_train: array-like, shape (n_samples,), training target labels
        - X_test: array-like, shape (n_samples, n_features), testing input data
        - y_test: array-like, shape (n_samples,), testing target labels

        Returns:
        - results: dict, classification reports for each model
        """
        algorithms = {
            'Decision Tree': DecisionTreeClassifier(),
            'AdaBoost': AdaBoostClassifier(),
            'XGBoost': XGBClassifier(use_label_encoder=False, eval_metric='logloss'),
            'CatBoost': CatBoostClassifier(verbose=0),
            'MLP': MLPClassifier(max_iter=1000),
            'Quadratic Discriminant Analysis': QuadraticDiscriminantAnalysis(reg_param=0.1),
            'Extra Trees': ExtraTreesClassifier()
        }

        results = {}
        for name, model in algorithms.items():
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            results[name] = classification_report(y_test, y_pred, output_dict=True)
            print(f"\n{name} Classification Report:")
            print(classification_report(y_test, y_pred))
        return results