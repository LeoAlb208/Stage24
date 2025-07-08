from .lib import plt, alt, math, pd

class Plots:
    """
    The Plots class provides various methods to visualize data related to attack events using Matplotlib.
    It includes methods to plot pie charts, bar distributions, top MITRE ATT&CK IDs, and value counts 
    for unique values in specified columns of a DataFrame. The class is designed to help analyze and 
    display data in a clear and meaningful way, facilitating the understanding of attack patterns and distributions.

    Methods:
        plot_cake_attack(df):
            Generates and displays a pie chart showing the percentage of events that correspond to attacks.
        
        plot_distributions(df):
            Generates and displays subplots of distributions for attack and non-attack events based on specified columns.
        
        plot_top_10_mitre_id(df):
            Generates and displays subplots of the top 10 MITRE ATT&CK IDs in overall frequency and for attacks.
        
        plot_value_counts_per_unique(df):
            Plots the count of values for each unique value in a specified column of the DataFrame.

        plot_precision_recall(df):
            Plots precision and recall for every rule
    """

    def plot_cake_attack(df):
        """
        Method to generate and display the pie chart of the percentage of events that correspond to attacks.

        Args:
            df (DataFrame): The DataFrame containing the event data.

        Returns:
            None
        """
        is_attack = df['corrisponde_ad_attacco'] == 1  # Filter attacks
        attack_percentage = is_attack.mean() * 100
        plt.figure(figsize=(6, 6))
        plt.pie([attack_percentage, 100 - attack_percentage], labels=['Attacks', 'Non-Attacks'], autopct='%1.1f%%', startangle=140)
        plt.title('Percentage of Events that Correspond to Attacks')
        plt.show()

    def plot_distributions(df):
        """
        Method to generate and display subplots of distributions for attack and non-attack events.

        Args:
            df (DataFrame): The DataFrame containing the event data.

        Returns:
            None
        """
        is_attack = df['corrisponde_ad_attacco'] == 1
        fig, axes = plt.subplots(4, 2, figsize=(12, 15))  # 4 rows, 2 columns
        ylim = []
        for i, column in enumerate(['path_category_detailed', 'severity_id', 'tag', 'EventType']):

            # Attack distribution
            attack_values = df[is_attack][column].value_counts(sort=False)

            # Non-Attack Distribution
            non_attack_values = df[~is_attack][column].value_counts(sort=False)

            # Combine unique values and reindex
            all_values = attack_values.index.union(non_attack_values.index)
            attack_values = attack_values.reindex(all_values, fill_value=0)
            non_attack_values = non_attack_values.reindex(all_values, fill_value=0)

            attack_values.plot(kind='bar', ax=axes[i, 0], color='red')
            axes[i, 0].set_title(f'Distribution of {column} (Attacks)')
            axes[i, 0].tick_params(axis='x', rotation=0)

            # Add values on top of the bars for attack distribution
            for p in axes[i, 0].patches:
                height = p.get_height()
                if height > 0:
                    axes[i, 0].annotate(
                        str(height), 
                        (p.get_x() + p.get_width() / 2., height + height * 0.01), 
                        ha='center', va='bottom', color='black'
                    )

            non_attack_values.plot(kind='bar', ax=axes[i, 1], color='blue')  # Same column, different row
            axes[i, 1].set_title(f'Distribution of {column} (Non-Attacks)')
            axes[i, 1].tick_params(axis='x', rotation=0)

            # Add values on top of the bars for non-attack distribution
            for p in axes[i, 1].patches:
                height = p.get_height()
                if height > 0:
                    axes[i, 1].annotate(
                        str(height), 
                        (p.get_x() + p.get_width() / 2., height + height * 0.01), 
                        ha='center', va='bottom', color='black'
                    )

            max_value = max(attack_values.max(), non_attack_values.max())
            ylim.append(max_value + max_value * 0.15)  # Add 15% margin to the highest value
            axes[i, 0].set_ylim(0, ylim[i])
            axes[i, 1].set_ylim(0, ylim[i])

        plt.tight_layout()
        plt.show()

    def plot_top_10_signatures(df):
        """
        Method to generate and display interactive bar charts of the top 10 signatures in overall frequency and for attacks.

        Args:
            df (DataFrame): The DataFrame containing the event data.

        Returns:
            alt.vconcat: The concatenated Altair charts.
        """
        # Calculate top 10 signatures overall, for attacks, and for non-attacks
        top_10_signatures_overall = df['signature'].value_counts().head(10).reset_index()
        top_10_signatures_attack = df[df['corrisponde_ad_attacco'] == 1]['signature'].value_counts().head(10).reset_index()
        top_10_signatures_non_attack = df[df['corrisponde_ad_attacco'] == 0]['signature'].value_counts().head(10).reset_index()

        # Rename columns for clarity
        top_10_signatures_overall.columns = ['Signature', 'Frequency']
        top_10_signatures_attack.columns = ['Signature', 'Frequency']
        top_10_signatures_non_attack.columns = ['Signature', 'Frequency']

        # Create the base selection for hovering
        selection = alt.selection_single(fields=['Signature'], on='mouseover', clear='mouseout')

        # Overall chart
        overall_chart = alt.Chart(top_10_signatures_overall).mark_bar().encode(
            x=alt.X('Signature', sort='-y', axis=None),  # Remove x-axis labels
            y=alt.Y('Frequency', title='Frequency', axis=alt.Axis(grid=True)),
            color=alt.condition(selection, alt.value('lightblue'), alt.value('steelblue')),  # Conditional color change
            tooltip=['Signature', 'Frequency']
        ).add_selection(
            selection
        ).properties(
            title='Top 10 Signatures (Overall)',
            width=400,
            height=500
        )

        # Attack chart
        attack_chart = alt.Chart(top_10_signatures_attack).mark_bar().encode(
            x=alt.X('Signature', sort='-y', axis=None),  # Remove x-axis labels
            y=alt.Y('Frequency', title=None, axis=alt.Axis(grid=True)),
            color=alt.condition(selection, alt.value('lightcoral'), alt.value('firebrick')),  # Conditional color change
            tooltip=['Signature', 'Frequency']
        ).add_selection(
            selection
        ).properties(
            title='Top 10 Signatures (Attacks)',
            width=400,
            height=500
        )

        # Non-attack chart
        non_attack_chart = alt.Chart(top_10_signatures_non_attack).mark_bar().encode(
            x=alt.X('Signature', sort='-y', axis=None),  # Remove x-axis labels
            y=alt.Y('Frequency', title=None, axis=alt.Axis(grid=True)),
            color=alt.condition(selection, alt.value('lightgreen'), alt.value('seagreen')),  # Conditional color change
            tooltip=['Signature', 'Frequency']
        ).add_selection(
            selection
        ).properties(
            title='Top 10 Signatures (Non-Attacks)',
            width=400,
            height=500
        )

        # Concatenate the charts horizontally
        combined_chart = alt.hconcat(overall_chart, attack_chart, non_attack_chart).resolve_scale(y='shared')

        # Create a shared x-axis label
        x_axis_label = alt.Chart(pd.DataFrame({'Signature': ['']})).mark_text(
            text='Signature',
            align='center',
            baseline='top'
        ).encode(
            x=alt.value(660),  # position in the middle
            y=alt.value(15)    # position a bit below the charts
        )

        # Concatenate vertically with the x-axis label
        final_chart = alt.vconcat(
            combined_chart,
            x_axis_label
        ).configure_concat(
            spacing=5
        )

        return final_chart

    def plot_value_counts_per_unique(df):
        """
        Plot the count of values for each unique value in a specified column of the DataFrame.

        Parameters:
        - df: DataFrame: The DataFrame containing the data to be plotted.
        """

        unique_col = 'signature'
        count_col = 'corrisponde_ad_attacco'
        cols = 5  # Numero di colonne desiderato nella griglia dei subplot
        color = ['#5cabbf', '#a15cbf']  # Colori per le barre
        xlabel = ''  # Etichetta per l'asse x
        ylabel = 'N. record'  # Etichetta per l'asse y
        xtick_labels = ['Non attacco', 'Attacco']  # Etichette per i tick dell'asse x
        figsize_multiplier = (6, 4)  # Multiplicatore per la dimensione della figura (larghezza, altezza)

        # Troviamo i valori unici della colonna unique_col
        unique_values = df[unique_col].unique()

        # Impostiamo il numero di subplot (una per ciascun valore unico di unique_col)
        num_plots = len(unique_values)

        # Determiniamo il numero di righe e colonne per la griglia
        rows = math.ceil(num_plots / cols)  # Calcola il numero di righe necessario

        # Creiamo i subplot
        fig, axes = plt.subplots(rows, cols, figsize=(figsize_multiplier[0] * cols, figsize_multiplier[1] * rows))

        # Se c'è solo un valore unico, axes non è un array bidimensionale, quindi lo convertiamo
        if num_plots == 1:
            axes = [[axes]]
        elif rows == 1:
            axes = [axes]

        # Cicliamo su ciascun valore unico di unique_col e plottiamo i dati
        for ax, value in zip(axes.flat, unique_values):
            # Filtriamo il DataFrame per il valore corrente di unique_col
            filtered_df = df[df[unique_col] == value]

            # Contiamo i valori di count_col (0 e 1)
            count_values = filtered_df[count_col].value_counts().sort_index()

            # Assicuriamoci che entrambi i valori (0 e 1) siano presenti
            count_values = count_values.reindex([0, 1], fill_value=0)

            # Creiamo il grafico sul subplot corrente
            count_values.plot(kind='bar', ax=ax, color=color)

            # Aggiungiamo etichette e titolo
            ax.set_xlabel(xlabel)
            ax.set_ylabel(ylabel)
            ax.set_title(value)
            ax.set_xticks([0, 1])
            ax.set_xticklabels(xtick_labels, rotation='horizontal')

            # Aggiungiamo i valori sopra ogni barra
            for p in ax.patches:
                ax.annotate(str(p.get_height()), (p.get_x() + p.get_width() / 2., p.get_height()), ha='center', va='center', xytext=(0, 5), textcoords='offset points')

            # Aggiungiamo un margine sopra alle colonne più alte
            ax.set_ylim(0, ax.get_ylim()[1] * 1.1)  # Modifica il fattore moltiplicativo a tuo piacimento (es. * 1.1)

        # Rimuoviamo gli assi vuoti
        for i in range(num_plots, rows * cols):
            fig.delaxes(axes.flat[i])

        # Aggiustiamo il layout
        plt.tight_layout()
        plt.show()

    def plot_precision_recall(df):
        """
        Calcola e plotta la precisione e il recall per ciascuna regola utilizzando Altair.
        
        Args:
        df: DataFrame contenente i dati da analizzare.
        """
        
        # Calcolo delle metriche per ciascuna regola
        rule_stats = df.groupby('signature')['corrisponde_ad_attacco'].agg(
            total='count',
            true_positives='sum'
        ).reset_index()
        
        rule_stats['false_positives'] = rule_stats['total'] - rule_stats['true_positives']
        rule_stats['precision'] = rule_stats['true_positives'] / rule_stats['total']
        rule_stats['recall'] = rule_stats['true_positives'] / rule_stats['true_positives'].sum()
        
        # Plotting con Altair
        precision_chart = alt.Chart(rule_stats).mark_bar(color='blue', opacity=0.7).encode(
            x=alt.X('signature:N', title='Regola', axis=None),
            y=alt.Y('precision:Q', title='Precisione', axis=alt.Axis(format='%', title='Precisione')),
            tooltip=[
                alt.Tooltip('signature:N', title='Regola'),
                alt.Tooltip('precision:Q', title='Precisione', format='.2f'),
            ],
        ).properties(
            title='Precisione e Recall delle Regole',
            width=1400,
            height=700
        )

        recall_chart = alt.Chart(rule_stats).mark_bar(color='#FFD700', opacity=0.7).encode(
            x=alt.X('signature:N', title='Regola', axis=None),
            y=alt.Y('recall:Q', title='Recall', axis=alt.Axis(format='%', title='Recall')),
            tooltip=[
                alt.Tooltip('signature:N', title='Regola'),
                alt.Tooltip('recall:Q', title='Recall', format='.2f'),
            ],
        )

        # Sovrapponi i grafici
        combined_chart = alt.layer(
            precision_chart,
            recall_chart
        ).properties(
            title='Precisione e Recall delle Regole',
            width=1200,
            height=600
        )
        
        # Create a shared x-axis label
        x_axis_label = alt.Chart(pd.DataFrame({'signature': ['']})).mark_text(
            text='Signature',
            align='center',
            baseline='top'
        ).encode(
            x=alt.value(600),  # position in the middle
            y=alt.value(10)    # position a bit below the charts
        )

        # Concatenate vertically with the x-axis label
        final_chart = alt.vconcat(
            combined_chart,
            x_axis_label
        ).configure_concat(
            spacing=5
        )

        # Visualizza il grafico combinato
        final_chart.display()