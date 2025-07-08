from .lib import RandomForestClassifier, GradientBoostingClassifier, GaussianNB, Pipeline, KNeighborsClassifier, StandardScaler, LogisticRegression, make_scorer, f1_score, GridSearchCV

class HyperparameterTuning:
    """
    This class provides methods for tuning hyperparameters of machine learning models using grid search.
    """

    def tune_hyperparameters(X_train, y_train):
        """
        Performs hyperparameter tuning for various machine learning algorithms using grid search.

        Parameters:
        - X_train: array-like, shape (n_samples, n_features), training input data
        - y_train: array-like, shape (n_samples,), training target labels

        Returns:
        - best_models: dict, best estimator for each algorithm after hyperparameter tuning
        """
        algorithms = {
            'Random Forest': (RandomForestClassifier(), {
                'n_estimators': [100, 200, 300],
                'max_depth': [None, 10, 20],
                'min_samples_split': [2, 5, 10]
            }),
            'Gradient Boosting': (GradientBoostingClassifier(), {
                'n_estimators': [100, 200, 300],
                'learning_rate': [0.01, 0.1, 0.3],
                'max_depth': [3, 5, 7]
            }),
            'Naive Bayes': (GaussianNB(), {}),
            'KNN': (Pipeline([
                ('knn', KNeighborsClassifier())
            ]), {
                'knn__n_neighbors': [3, 5, 7, 9],
                'knn__weights': ['uniform', 'distance'],
                'knn__metric': ['euclidean', 'manhattan', 'minkowski']
            }),
            'Logistic Regression': (Pipeline([
                ('scaler', StandardScaler()),
                ('logreg', LogisticRegression(max_iter=1000))
            ]), {
                'logreg__C': [0.01, 0.1, 1, 10, 100],
                'logreg__solver': ['lbfgs', 'liblinear']
            })
        }

        scorer = make_scorer(f1_score)
        best_models = {}
        for name, (model, params) in algorithms.items():
            grid_search = GridSearchCV(model, params, scoring=scorer, cv=5, n_jobs=-1)
            grid_search.fit(X_train, y_train)
            best_models[name] = grid_search.best_estimator_
            print(f'Best parameters for {name}: {grid_search.best_params_}')
            print(f'Best F1-score: {grid_search.best_score_}')
        return best_models