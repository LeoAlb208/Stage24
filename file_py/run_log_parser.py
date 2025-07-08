from .lib import csv, pd, timedelta

class RunLogParser:
    """A utility class for parsing run logs, processing attacks and creating specific datasets.

    This class provides static methods to parse a run log CSV file,
    process attacks based on the log data and create the event_df based off of it.

    Attributes:
        None

    Methods:
        parse_run_log(file_path): Parses a run log CSV file and returns a list of attacks.
        process_attacks(file_path, df): Processes attacks and updates a DataFrame accordingly.
        create_event_df(file_path, df): Creates a DataFrame of events based on the attack log.
    """

    @staticmethod
    def parse_run_log(file_path):
        """Parses a run log CSV file and returns a list of attacks.

        Args:
            file_path (str): The path to the run log CSV file.

        Returns:
            list: A list of dictionaries containing attack information.
        """
        attacks = []
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=[field.lower().replace(' ', '_') for field in csvfile.readline().strip().split(',')])
            for row in reader:
                attack = {
                    'codice_attacco': row['codice_attacco'],
                    'data_inizio': row['data_inizio_attacco'],
                    'data_fine': row['data_fine_attacco'],
                }
                attack['data_inizio'] = pd.to_datetime(attack['data_inizio'])
                attack['data_fine'] = pd.to_datetime(attack['data_fine'])
                attacks.append(attack)
        return attacks

    @staticmethod
    def process_attacks(file_path, df):
        """Processes attacks and updates a DataFrame accordingly.

        Args:
            file_path (str): The path to the run log CSV file.
            df (pandas.DataFrame): The DataFrame to be updated.

        Returns:
            pandas.DataFrame: The updated DataFrame.
        """
        attacks = RunLogParser.parse_run_log(file_path)
        df_result = df.copy()
        df_result['corrisponde_ad_attacco'] = 0
        
        for attack in attacks:
            codice_attacco = attack['codice_attacco']
            data_inizio = attack['data_inizio']
            data_fine = attack['data_fine']
            
            mask = (df_result['_time'] >= data_inizio) & (df_result['_time'] < data_fine + timedelta(seconds=1))
            df_result.loc[mask, 'corrisponde_ad_attacco'] = 1
            df_result.loc[mask, 'codice_attacco'] = codice_attacco
        
        df_result.drop(columns=['codice_attacco'], inplace=True)
        
        return df_result

    @staticmethod
    def create_event_df(file_path, df):
        """Creates a DataFrame of events based on the attack log.

        Args:
            file_path (str): The path to the attack log CSV file.
            df (pandas.DataFrame): The raw DataFrame to filter events from.

        Returns:
            pandas.DataFrame: The DataFrame containing event information.
        """
        # Read the attack log
        df_attack_log = pd.read_csv(file_path)
        df_attack_log['Data inizio attacco'] = pd.to_datetime(df_attack_log['Data inizio attacco'])
        df_attack_log['Data fine attacco'] = pd.to_datetime(df_attack_log['Data fine attacco'])

        # Initialize the list of events
        events = []
        single_attack = {'RuleAnnotation.mitre_attack.id': [], 'severity_id': [], 'EventType': [], 'tag': [], 'signature': [], 'path_category_detailed': []}

        for _, attack in df_attack_log.iterrows():
            # Filter results that fall within the attack time window
            mask = (df['_time'] >= attack['Data inizio attacco']) & (df['_time'] <= attack['Data fine attacco'])
            df_filtered = df.loc[mask].copy()

            for _, row in df_filtered.iterrows():
                single_attack['RuleAnnotation.mitre_attack.id'].append(row['RuleAnnotation.mitre_attack.id'])
                single_attack['severity_id'].append(row['severity_id'])
                single_attack['EventType'].append(row['EventType'])
                single_attack['tag'].append(row['tag'])
                single_attack['signature'].append(row['signature'])
                single_attack['path_category_detailed'].append(row['path_category_detailed'])

            if single_attack['RuleAnnotation.mitre_attack.id']:
                events.append(single_attack)
            single_attack = {'RuleAnnotation.mitre_attack.id': [], 'severity_id': [], 'EventType': [], 'tag': [], 'signature': [], 'path_category_detailed': []}

        if events:
            event_df = pd.DataFrame(events)
            event_df["severity_max"] = event_df["severity_id"].apply(max)
            event_df["severity_mean"] = event_df["severity_id"].apply(lambda x: sum(x) / len(x))
            event_df["severity_min"] = event_df["severity_id"].apply(min)
            return event_df
        else:
            print("Non ci sono attacchi.")
            return pd.DataFrame()