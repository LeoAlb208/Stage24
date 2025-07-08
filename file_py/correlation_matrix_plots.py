from .lib import plt, sns

class CorrelationMatrixPlots:
    """A utility class for plotting correlation matrices.

    This class provides static methods to plot correlation matrices using matplotlib and seaborn.

    Attributes:
        None

    Methods:
        plot_correlation_matrix(df, title): Plots a correlation matrix for a DataFrame with a specified title.
        plot_correlation_matrix_big(df, title): Plots a larger correlation matrix for a DataFrame with a specified title.
    """
    
    @staticmethod
    def plot_correlation_matrix(df, title):
        """Plots a correlation matrix for a DataFrame with a specified title.

        Args:
            df (pandas.DataFrame): The DataFrame containing the data.
            title (str): The title for the plot.

        Returns:
            None
        """
        correlation_matrix = df.corr()
        plt.figure(figsize=(10, 8))
        sns.heatmap(correlation_matrix, annot=True, fmt=".2f", cmap='coolwarm', linewidths=0.5)
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.title(title)
        plt.show()

    @staticmethod
    def plot_correlation_matrix_big(df, title):
        """Plots a larger correlation matrix for a DataFrame with a specified title.

        Args:
            df (pandas.DataFrame): The DataFrame containing the data.
            title (str): The title for the plot.

        Returns:
            None
        """
        correlation_matrix = df.corr()

        # Filter columns with at least three values > 0.30 or < -0.30
        cols_to_keep = correlation_matrix.columns[
            (correlation_matrix.abs() > 0.30).sum(axis=0) >= 3
        ].tolist()

        # Add 'corrisponde_ad_attacco' if not already included
        if 'corrisponde_ad_attacco' not in cols_to_keep:
            cols_to_keep.append('corrisponde_ad_attacco')

        # Filter the correlation matrix to keep only the desired columns and rows
        filtered_corr_matrix = correlation_matrix.loc[cols_to_keep, cols_to_keep]

        plt.figure(figsize=(15, 10))
        sns.heatmap(filtered_corr_matrix, annot=False, fmt=".2f", cmap='coolwarm', linewidths=0.5)
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.title(title)
        plt.show()