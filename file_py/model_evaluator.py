from .lib import classification_report

class ModelEvaluator:
    """
    This class provides methods for evaluating machine learning models using classification reports.
    """

    def __init__(self, models):
        """
        Initializes the ModelEvaluator with a dictionary of models.

        Parameters:
        - models: dict, a dictionary containing names of models as keys and their corresponding trained models as values
        """
        self.models = models
        self.evaluation_results = {}

    def evaluate_models(self, X_test, y_test):
        """
        Evaluates the performance of each model in the provided dictionary on the test data.

        Parameters:
        - X_test: array-like, shape (n_samples, n_features), testing input data
        - y_test: array-like, shape (n_samples,), testing target labels

        Returns:
        - evaluation_results: dict, classification reports for each model
        """
        for name, model in self.models.items():
            y_pred = model.predict(X_test)
            report = classification_report(y_test, y_pred, output_dict=True)
            self.evaluation_results[name] = report
            print(f'\n{name} Classification Report:')
            print(classification_report(y_test, y_pred))
        return self.evaluation_results

    def print_best_model(self, codifica):
        """
        Prints the model with the highest average F1-score.

        Returns:
        - best_model: str, name of the best model
        - best_f1_score: float, F1-score of the best model
        """
        if not self.evaluation_results:
            print("No evaluation results found. Please run evaluate_models() first.")
            return None, None

        best_model = None
        best_f1_score = 0
        
        for name, report in self.evaluation_results.items():
            # Calculate the average F1-score
            avg_f1_score = report['macro avg']['f1-score']
            
            if avg_f1_score > best_f1_score:
                best_f1_score = avg_f1_score
                best_model = name

        # Print the best model and its score
        if best_model:
            print(f'\nDopo la codifica con {codifica} il modello migliore è stato {best_model} con lo score di {best_f1_score:.4f}')