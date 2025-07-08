from .lib import pd, StandardScaler, LabelEncoder

class CsvPreprocessingScaler:
    """A utility class for preprocessing CSV data and applying scaling.

    This class provides static methods for reading CSV files, preprocessing data,
    and applying various preprocessing techniques like dropping unnecessary columns,
    converting data types, and scaling features.

    Attributes:
        None

    Methods:
        read_csv_file(file_path): Reads a CSV file and returns a DataFrame.
        drop_unnecessary_columns(df, columns_to_drop): Drops specified columns from a DataFrame.
        convert_to_datetime(df, column): Converts a column in a DataFrame to datetime format.
        categorize_and_count_paths(df): Categorizes paths in a DataFrame and counts occurrences.
        RawPreprocessing(df): Performs raw preprocessing steps on a DataFrame.
        RawPreprocessingWSig(df): Performs raw preprocessing steps on a DataFrame, keeping 'signature'.
        LEPreprocessing(df): Performs label encoding preprocessing on a DataFrame.
        OhePreprocessing(df): Performs one-hot encoding preprocessing on a DataFrame.
        stdScaler(df): Applies standard scaling to the features of a DataFrame.
    """

    @staticmethod
    def read_csv_file(file_path):
        """Reads a CSV file and returns a DataFrame.

        Args:
            file_path (str): The path to the CSV file.

        Returns:
            pandas.DataFrame: The DataFrame containing the CSV data.
        """
        try:
            df = pd.read_csv(file_path, low_memory=False)
            return df
        except FileNotFoundError:
            print(f"File {file_path} not found.")
            return pd.DataFrame()
        except pd.errors.EmptyDataError:
            print(f"File {file_path} is empty.")
            return pd.DataFrame()
        except Exception as e:
            print(f"An error occurred while reading {file_path}: {e}")
            return pd.DataFrame()

    @staticmethod
    def drop_unnecessary_columns(df, columns_to_drop):
        """Drops specified columns from a DataFrame.

        Args:
            df (pandas.DataFrame): The DataFrame to modify.
            columns_to_drop (list): A list of column names to drop.

        Returns:
            pandas.DataFrame: The DataFrame with specified columns dropped.
        """
        return df.drop(columns=columns_to_drop, errors='ignore')

    @staticmethod
    def convert_to_datetime(df, column):
        """Converts a column in a DataFrame to datetime format.

        Args:
            df (pandas.DataFrame): The DataFrame containing the column to convert.
            column (str): The name of the column to convert.

        Returns:
            None
        """
        try:
            df[column] = pd.to_datetime(df[column])
        except Exception as e:
            print(f"An error occurred while converting {column} to datetime: {e}")

    @staticmethod
    def categorize_and_count_paths(df):
        """Categorizes paths in a DataFrame and counts occurrences.

        Args:
            df (pandas.DataFrame): The DataFrame containing the 'process_path' column.

        Returns:
            pandas.DataFrame: The DataFrame with the 'path_category_detailed' column added.
        """
        data = pd.DataFrame()
        data["process_path"] = df["process_path"]

        def categorize_path_detailed(path):
            path_lower = path.lower()
            if '\\temp\\' in path_lower or '\\tmp\\' in path_lower or '\\appdata\\local\\temp\\' in path_lower:
                return 'Temporary'
            elif path_lower.startswith('c:\\windows\\system32\\') or path_lower.startswith('c:\\windows\\syswow64\\'):
                return 'System Files'
            elif path_lower.startswith('c:\\program files\\') or path_lower.startswith('c:\\program files (x86)\\'):
                return 'Program Files'
            elif path_lower.startswith('c:\\users\\'):
                return 'User Files'
            elif path_lower.startswith('\\\\'):
                return 'Network Locations'
            else:
                return 'Other'

        # Apply the detailed categorization function to the 'process_path' column
        data['path_category_detailed'] = data['process_path'].apply(categorize_path_detailed)
        
        return data

    @staticmethod
    def RawPreprocessing(df):
        """Performs raw preprocessing steps on a DataFrame.

        Args:
            df (pandas.DataFrame): The DataFrame to preprocess.

        Returns:
            pandas.DataFrame: The preprocessed DataFrame.
        """
        # Keep only the relevant rows
        df = df.dropna(subset=["RuleAnnotation.mitre_attack.id", "signature"])

        # Drop columns with more than 2000 missing values
        df = df.drop(columns=df.columns[df.isnull().sum() > 2000])
        
        # Drop specific unnecessary columns
        columns_to_drop = ["_raw", "date", "date_hour", "date_mday", "date_minute", "date_month", "date_second", 
                           "date_wday", "date_year", "date_zone", "RuleAnnotation", "Timestamp", 
                           "tag::eventtype", "AppVersion"]
        df = CsvPreprocessingScaler.drop_unnecessary_columns(df, columns_to_drop)
        
        # Convert '_time' column to datetime
        CsvPreprocessingScaler.convert_to_datetime(df, '_time')
        
        # Split 'RuleAnnotation.mitre_attack.id' column values by newline characters
        df['RuleAnnotation.mitre_attack.id'] = df['RuleAnnotation.mitre_attack.id'].str.split('\n')
        
        # Explode rows with lists of values into multiple separate rows
        df = df.explode('RuleAnnotation.mitre_attack.id')

        categorized_paths_df = CsvPreprocessingScaler.categorize_and_count_paths(df)
        df = df.join(categorized_paths_df.set_index(df.index), rsuffix='_detailed')

        df = df[["signature", "RuleAnnotation.mitre_attack.id", "_time", "parent_process_id", "process_id", 'path_category_detailed', "severity_id", "EventType", "tag"]]

        return df

    @staticmethod
    def RawPreprocessingWSig(df):
        """Performs raw preprocessing steps on a DataFrame, keeping 'signature'.

        Args:
            df (pandas.DataFrame): The DataFrame to preprocess.

        Returns:
            pandas.DataFrame: The preprocessed DataFrame.
        """
        df = CsvPreprocessingScaler.RawPreprocessing(df)
        return df

    @staticmethod
    def LEPreprocessing(df):
        """Performs label encoding preprocessing on a DataFrame.

        Args:
            df (pandas.DataFrame): The DataFrame to preprocess.

        Returns:
            pandas.DataFrame: The preprocessed DataFrame.
        """
        df = CsvPreprocessingScaler.RawPreprocessing(df)
        columns_to_encode_for_LE = ["signature", "RuleAnnotation.mitre_attack.id", "parent_process_id", "process_id", 'path_category_detailed', "severity_id", "EventType", "tag"]
        label_encoder = LabelEncoder()

        for column in columns_to_encode_for_LE:
            try:
                df[column] = label_encoder.fit_transform(df[column])
            except Exception as e:
                print(f"An error occurred while encoding {column}: {e}")
        
        return df

    @staticmethod
    def OhePreprocessing(df):
        """Performs one-hot encoding preprocessing on a DataFrame.

        Args:
            df (pandas.DataFrame): The DataFrame to preprocess.

        Returns:
            pandas.DataFrame: The preprocessed DataFrame.
        """
        df = CsvPreprocessingScaler.RawPreprocessing(df)
        columns_to_encode_for_OH = ["signature", "RuleAnnotation.mitre_attack.id", 'path_category_detailed', "severity_id", "EventType", "tag"]

        # Replace newlines in 'tag' column
        df['tag'] = df['tag'].str.replace('\n', '_')

        try:
            df = pd.get_dummies(df, columns=columns_to_encode_for_OH)
        except Exception as e:
            print(f"An error occurred during OneHotEncoding: {e}")
        
        return df
    
    @staticmethod
    def stdScaler(df):
        """Applies standard scaling to the features of a DataFrame.

        Args:
            df (pandas.DataFrame): The DataFrame to scale.

        Returns:
            pandas.DataFrame: The scaled DataFrame.
        """
        scaler = StandardScaler()
        try:
            df_scaled = scaler.fit_transform(df.drop(columns="_time"))
            return pd.merge(pd.DataFrame(df_scaled, columns=df.drop(columns="_time").columns), df["_time"], left_index=True, right_index=True)
        except Exception as e:
            print(f"An error occurred during standard scaling: {e}")
            return df