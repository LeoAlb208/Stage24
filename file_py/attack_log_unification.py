from .lib import pd

class AttackLogUnification:

    @staticmethod
    def attack_log_together(files_csv, output_file):
        # Lista per conservare i DataFrame
        dataframes = []

        # Leggi tutti i file CSV e aggiungi i DataFrame alla lista
        for file_csv in files_csv:
            df = pd.read_csv(file_csv)
            dataframes.append(df)

        # Unisci tutti i DataFrame nella lista
        combined_df = pd.concat(dataframes)

        # Ordina il DataFrame risultante per 'Data inizio attacco'
        combined_df = combined_df.sort_values(by='Data inizio attacco')

        # Salva il DataFrame combinato in un nuovo file CSV
        combined_df.to_csv(output_file, index=False)

        return output_file