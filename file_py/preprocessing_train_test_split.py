from .lib import np, train_test_split

class PreprocessingTrainTestSplit:
    """
    This class provides methods for preprocessing data and splitting it into training and testing sets.
    """

    def preprocess_data(df):
        """
        Preprocesses the input DataFrame by converting the '_time' column to integer timestamps.
        
        Parameters:
        - df: DataFrame, input data
        
        Returns:
        - df: DataFrame, preprocessed data
        """
        df['_time'] = (df['_time'].astype(np.int64) // 10**9).astype(int)
        return df

    def split_data(df, target_column, test_size=0.25, random_state=42):
        """
        Splits the preprocessed DataFrame into features (X) and target (y) and then into training and testing sets.

        Parameters:
        - df: DataFrame, preprocessed data
        - target_column: str, name of the target column
        - test_size: float, optional (default=0.25), proportion of the dataset to include in the test split
        - random_state: int, optional (default=42), random state for reproducibility
        
        Returns:
        - X_train, X_test, y_train, y_test: arrays, training and testing data
        """
        df = PreprocessingTrainTestSplit.preprocess_data(df)
        X = df.drop(target_column, axis=1)
        y = df[target_column]
        return train_test_split(X, y, test_size=test_size, random_state=random_state)