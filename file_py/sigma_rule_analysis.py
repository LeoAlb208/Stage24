from .lib import plt, sns

class SigmaRuleAnalysis:
    def __init__(self, df):
        self.df = df
    
    def scatter_plot(self, y_column, title):
        if self.df is None or self.df.empty:
            print("Non ci sono attacchi.")
            return
        
        plt.figure(figsize=(10, 6))
        sns.scatterplot(x='Indice_Diff', y=y_column, hue='N_Attacchi_Non_rilevati', data=self.df, palette='coolwarm')
        plt.title(title)
        plt.xlabel('Indice_Diff')
        plt.ylabel(y_column)
        plt.axhline(0, color='red', linestyle='--')
        plt.show()
        
    def scatter_plot_severity_mean(self):
        self.scatter_plot('Media_Differenza_Severity_mean', 'Indice_Diff vs Media_Differenza_Severity_mean')
        
    def scatter_plot_severity_min(self):
        self.scatter_plot('Media_Differenza_Severity_min', 'Indice_Diff vs Media_Differenza_Severity_min')
        
    def scatter_plot_severity_max(self):
        self.scatter_plot('Media_Differenza_Severity_max', 'Indice_Diff vs Media_Differenza_Severity_max')
        
    def heatmap_correlations(self):
        if self.df is None or self.df.empty:
            print("Non ci sono attacchi.")
            return
        
        # Exclude non-numeric columns
        numeric_cols = self.df.select_dtypes(include=['float64', 'int64']).columns
        corr_matrix = self.df[numeric_cols].corr()

        plt.figure(figsize=(12, 8))
        sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', linewidths=0.5)
        plt.xticks(rotation=45, ha='right')
        plt.title('Correlazioni tra le metriche')
        plt.show()
        
    def box_plot_non_detected_attacks(self):
        if self.df is None or self.df.empty:
            print("Non ci sono attacchi.")
            return
        
        plt.figure(figsize=(10, 10))
        sns.boxplot(y='N_Attacchi_Non_rilevati', data=self.df)
        plt.grid(True)
        plt.title('Distribuzione di N_Attacchi_Non_rilevati')
        plt.show()
    
    def plots_sigma_rule_analysis(self):
        if self.df is None or self.df.empty:
            print("Non ci sono attacchi.")
            return
        
        self.scatter_plot_severity_mean()
        self.scatter_plot_severity_min()
        self.scatter_plot_severity_max()
        self.heatmap_correlations()
        self.box_plot_non_detected_attacks()