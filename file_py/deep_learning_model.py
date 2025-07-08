from .lib import Sequential, Dense, classification_report

class DeepLearningModel:
    """
    This class provides methods for training and evaluating a deep learning model using Keras.
    """

    def train_deep_learning_model(X_train, y_train, X_test, y_test):
        """
        Trains a deep learning model and evaluates its performance on the test data.

        Parameters:
        - X_train: array-like, shape (n_samples, n_features), training input data
        - y_train: array-like, shape (n_samples,), training target labels
        - X_test: array-like, shape (n_samples, n_features), testing input data
        - y_test: array-like, shape (n_samples,), testing target labels

        Returns:
        - model: trained deep learning model
        """
        model = Sequential([
            Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')
        ])

        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

        model.fit(X_train, y_train, epochs=10, batch_size=32, verbose=1)

        loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
        print(f'Test Accuracy: {accuracy}')

        y_pred_prob = model.predict(X_test)
        y_pred = (y_pred_prob > 0.5).astype(int)

        print("Classification Report for Deep Learning Model:")
        print(classification_report(y_test, y_pred))
        return model