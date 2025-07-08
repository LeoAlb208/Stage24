from .lib import plt

class StatSeverity:
    """
    Classe StatSeverity per l'analisi della severità.

    Metodi
    ------
    plot_stat_severity(df)
        Genera e visualizza istogrammi per le statistiche di severità massima, minima e media.
    """
    @staticmethod
    def plot_stat_severity(df):
        """
        Genera e visualizza istogrammi per le statistiche di severità massima, minima e media.

        Parametri
        ----------
        df : pandas.DataFrame
            DataFrame contenente una colonna 'severity_id' con valori numerici.

        Il metodo crea tre sottotrame (subplots) per visualizzare gli istogrammi delle distribuzioni di queste nuove colonne.
        """
        if df.empty:
            print("Non ci sono attacchi.")
            return
        
        fig, axs = plt.subplots(1, 3, figsize=(18, 8), sharey=True)
        fig.suptitle('Statistiche di Criticità per ogni attacco', fontsize=16)

        # Istogramma per 'severity_max' nel primo subplot
        n, bins, patches = axs[0].hist(df['severity_max'], bins=10, edgecolor='black')
        axs[0].set_title('Criticità Massima')
        axs[0].set_ylabel('Frequenza')

        # Aggiungi i valori sopra le barre dell'istogramma 'severity_max'
        for i in range(len(patches)):
            if patches[i].get_height() > 0:  # Mostra il valore solo se è maggiore di zero
                axs[0].text(patches[i].get_x() + patches[i].get_width() / 2, patches[i].get_height() + 0.5, int(patches[i].get_height()), ha='center')
            axs[0].text(bins[i], -0.02, f'{bins[i]:.1f}', transform=axs[0].get_xaxis_transform(), ha='center', color='black', fontsize=10)

        # Aggiungi manualmente il valore finale (100) spostato a sinistra di 0.2 unità sull'asse x
        axs[0].text(bins[-1] - 0.2, -0.02, f'{bins[-1]:.1f}', transform=axs[0].get_xaxis_transform(), ha='center', color='black', fontsize=10)

        axs[0].set_xticks([])  # Rimuovi le xticks dopo aver aggiunto le etichette manualmente

        # Istogramma per 'severity_min' nel secondo subplot
        n, bins, patches = axs[1].hist(df['severity_min'], bins=10, edgecolor='black')
        axs[1].set_title('Criticità Minima')

        # Aggiungi i valori sopra le barre dell'istogramma 'severity_min'
        for i in range(len(patches)):
            if patches[i].get_height() > 0:  # Mostra il valore solo se è maggiore di zero
                axs[1].text(patches[i].get_x() + patches[i].get_width() / 2, patches[i].get_height() + 0.5, int(patches[i].get_height()), ha='center')
            axs[1].text(bins[i], -0.02, f'{bins[i]:.1f}', transform=axs[1].get_xaxis_transform(), ha='center', color='black', fontsize=10)

        # Aggiungi manualmente il valore finale (100) spostato a sinistra di 0.2 unità sull'asse x
        axs[1].text(bins[-1] - 0.2, -0.02, f'{bins[-1]:.1f}', transform=axs[1].get_xaxis_transform(), ha='center', color='black', fontsize=10)

        axs[1].set_xticks([])  # Rimuovi le xticks dopo aver aggiunto le etichette manualmente

        # Istogramma per 'severity_mean' nel terzo subplot
        n, bins, patches = axs[2].hist(df['severity_mean'], bins=10, edgecolor='black')
        axs[2].set_title('Criticità Media')

        # Aggiungi i valori sopra le barre dell'istogramma 'severity_mean'
        for i in range(len(patches)):
            if patches[i].get_height() > 0:  # Mostra il valore solo se è maggiore di zero
                axs[2].text(patches[i].get_x() + patches[i].get_width() / 2, patches[i].get_height() + 0.5, int(patches[i].get_height()), ha='center')
            axs[2].text(bins[i], -0.02, f'{bins[i]:.1f}', transform=axs[2].get_xaxis_transform(), ha='center', color='black', fontsize=10)
        
        # Aggiungi manualmente il valore finale (100) spostato a sinistra di 0.2 unità sull'asse x
        axs[2].text(bins[-1] - 0.2, -0.02, f'{bins[-1]:.1f}', transform=axs[2].get_xaxis_transform(), ha='center', color='black', fontsize=10)

        axs[2].set_xticks([])  # Rimuovi le xticks dopo aver aggiunto le etichette manualmente

        plt.tight_layout()
        plt.show()