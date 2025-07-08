from .lib import np, pd

class SignatureStatsCalculator:

    @staticmethod
    def get_sig_stats(df1, sig_to_rem=None):
        # Funzioni di aggregazione ottimizzate
        def max_sev(x):
            return max(x, default=0)
        
        def mean_sev(x):
            return np.mean(x) if x else 0
        
        def min_sev(x):
            return min(x, default=0)
        
        def list_difference(list1, list2):
            set1, set2 = set(list1), set(list2)
            return len(set1.symmetric_difference(set2)) / (len(set1) + len(set2))
        
        def calculate_difference(row1, row2):
            numeric_columns = ['severity_max', 'severity_mean', 'severity_min']
            differences = [abs(row1[col] - row2[col]) / max(row1[col], row2[col], 1) for col in numeric_columns]
            
            categorical_columns = ['RuleAnnotation.mitre_attack.id', 'severity_id', 'EventType', 'tag', 'signature']
            differences.extend([list_difference(row1[col], row2[col]) for col in categorical_columns])
            
            return np.mean(differences)
        
        # Creare una copia del dataframe e rimuovere le signature
        df1_wo_sig = df1.copy()
        
        # Utilizzare mask e numpy per operazioni più efficienti
        mask = df1_wo_sig['signature'].apply(lambda x: sig_to_rem in x)
        indices_to_rem = np.where(mask)[0]
        
        for idx in indices_to_rem:
            indices_to_keep = [i for i, sig in enumerate(df1_wo_sig.at[idx, 'signature']) if sig != sig_to_rem]
            
            for col in ['RuleAnnotation.mitre_attack.id', 'severity_id', 'EventType', 'tag', 'signature']:
                df1_wo_sig.at[idx, col] = [df1_wo_sig.at[idx, col][i] for i in indices_to_keep]
        
        # Calcolare severity_max, severity_mean e severity_min usando funzioni di pandas
        df1_wo_sig["severity_max"] = df1_wo_sig["severity_id"].apply(max_sev)
        df1_wo_sig["severity_mean"] = df1_wo_sig["severity_id"].apply(mean_sev)
        df1_wo_sig["severity_min"] = df1_wo_sig["severity_id"].apply(min_sev)
        
        # Filtrare righe con severity_id vuoto
        non_empty_mask = df1_wo_sig["severity_id"].apply(bool)
        df_wosig_filtrato = df1_wo_sig[non_empty_mask].copy()
        df1_filtrato = df1[non_empty_mask].copy()
        
        # Calcolare la differenza per ogni coppia di record corrispondenti
        distances = df1_filtrato.apply(lambda row: calculate_difference(row, df_wosig_filtrato.loc[row.name]), axis=1)
        
        # Calcolare le differenze delle statistiche di severity
        sev_diff_min = df1_filtrato["severity_min"] - df_wosig_filtrato["severity_min"]
        sev_diff_mean = df1_filtrato["severity_mean"] - df_wosig_filtrato["severity_mean"]
        sev_diff_max = df1_filtrato["severity_max"] - df_wosig_filtrato["severity_max"]
        
        # Conteggio record con diminuzione di severity_max >= 15
        count_max = (sev_diff_max >= 15).sum()
        
        differences = [sig_to_rem, distances.mean(), sev_diff_min.mean(), sev_diff_mean.mean(), sev_diff_max.mean(), count_max, len(non_empty_mask) - non_empty_mask.sum()]

        return differences

    def create_signature_stats(df1, df2):

        if df1.empty | df2.empty:
            print("Non ci sono attacchi.")
            return

        signature_stats=pd.DataFrame(columns=(["signature","Indice_Diff","Media_Differenza_Severity_min","Media_Differenza_Severity_mean","Media_Differenza_Severity_max","N_Max_Sev_Diff_15","N_Attacchi_Non_rilevati"]))
        for e in df2["signature"].unique():
            signature_stats.loc[len(signature_stats)]=SignatureStatsCalculator.get_sig_stats(df1,e)

        return signature_stats