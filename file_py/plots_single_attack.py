from .lib import pd, go, plt, alt

class PlotsSingleAttack:
    """
    La classe PlotsSingleAttack contiene metodi per analizzare le attivazioni di regole specifiche 
    all'interno di un dataframe, separando gli attacchi reali dai falsi positivi e generando vari grafici 
    di supporto. Inoltre, permette di analizzare i pattern degli eventi che precedono l'attivazione di una 
    regola specifica.

    Metodi:
        analyze_rule_activations(df, rule):
            Analizza le attivazioni di una regola specificata e genera vari plot per visualizzare la frequenza
            delle attivazioni, il tipo di evento, il parent process, il process, la severità e i tag.
        
        patterns_before_activation(df, rule, elements_to_consider):
            Analizza i pattern degli eventi che precedono l'attivazione di una regola specifica e genera plot
            per visualizzare le regole, il tipo di evento, i tag, il parent process, il process e la severità 
            degli eventi precedenti.
    """
    
    @staticmethod
    def analyze_rule_activations(df, rule, rule_col='signature', mitre_attack_col='RuleAnnotation.mitre_attack.id', path_col='path_category_detailed', time_col='_time', eventtype_col='EventType', parent_col='parent_process_id', process_col='process_id', severity_col='severity_id', tag_col='tag', attack_col='corrisponde_ad_attacco'):
        """
        Analizza le attivazioni di una regola specificata in un dataframe, 
        separando gli attacchi reali dai falsi positivi e generando vari grafici di supporto.
        
        Args:
        df: DataFrame contenente i dati da analizzare.
        rule: La regola specifica da analizzare.
        rule_col: Nome della colonna che contiene l'ID della regola.
        mitre_attack_col: Nome della colonna che contiene l'ID dell'attacco registrato.
        path_col: Nome della colonna che contiene il path dell'evento.
        time_col: Nome della colonna che contiene il timestamp.
        eventtype_col: Nome della colonna che contiene il tipo di evento.
        parent_col: Nome della colonna che contiene l'ID del processo padre.
        process_col: Nome della colonna che contiene l'ID del processo.
        severity_col: Nome della colonna che contiene il livello di severità.
        tag_col: Nome della colonna che contiene i tag.
        attack_col: Nome della colonna che indica se l'attivazione corrisponde a un attacco reale.
        """ 
        
        # Verifica se la regola specificata è presente nel dataframe
        if rule not in df[rule_col].values:
            print("La regola ricercata non è presente")
            return
        
        # Filtra il dataframe per la regola specificata
        df_rule = df[df[rule_col] == rule]
        
        # Separa le attivazioni in attacchi reali e falsi positivi
        df_attack = df_rule[df_rule[attack_col] == 1]
        df_non_attack = df_rule[df_rule[attack_col] == 0]
        
        # Funzioni per i grafici

        # Funzione di supporto per la frequenza di attivazione
        def plot_activation_frequency(df_attack, df_non_attack, title):
            """
            Plotta la frequenza delle attivazioni degli attacchi e dei falsi positivi in modo interattivo con Plotly.
            
            Args:
            df_attack: DataFrame contenente solo attacchi reali.
            df_non_attack: DataFrame contenente solo falsi positivi.
            title: Titolo del grafico.
            """
            
            # Crea nuove DataFrame con la colonna 'date' aggiunta
            df_attack = df_attack.assign(date=df_attack['_time'].dt.date)
            df_non_attack = df_non_attack.assign(date=df_non_attack['_time'].dt.date)
            
            # Prendi l'elenco dei giorni unici da entrambi i DataFrame
            unique_days = pd.concat([df_attack['date'], df_non_attack['date']]).unique()
            
            for day in unique_days:
                # Filtra i dati per il giorno specifico
                daily_attack = df_attack[df_attack['date'] == day]
                daily_non_attack = df_non_attack[df_non_attack['date'] == day]
                
                if daily_attack.empty and daily_non_attack.empty:
                    continue  # Se non ci sono dati per quel giorno, salta al prossimo giorno
                
                frequency_attack = daily_attack['_time'].dt.floor('5T').value_counts().sort_index()
                frequency_non_attack = daily_non_attack['_time'].dt.floor('5T').value_counts().sort_index()
                
                fig = go.Figure()
                fig.add_trace(go.Bar(x=frequency_non_attack.index, y=frequency_non_attack.values, name='Non Attacchi', marker_color='blue'))
                fig.add_trace(go.Bar(x=frequency_attack.index, y=frequency_attack.values, name='Attacchi', marker_color='red'))
                
                fig.update_layout(
                    title=f"{title} - {day}",
                    xaxis_title='Tempo',
                    yaxis_title='Numero di Attivazioni',
                    xaxis_tickangle=-0,
                    barmode='stack',
                    xaxis=dict(
                        tickvals=frequency_non_attack.index.union(frequency_attack.index),  # Imposta tickvals agli indici della frequenza
                        tickformat='%H:%M'  # Imposta il formato dell'ora/minuto
                    )
                )
                
                fig.update_traces(hovertemplate='Attivazioni: %{y}')  # Imposta il formato del tooltip
                
                fig.show()
        
        # Frequenza di Attivazione
        plot_activation_frequency(df_attack, df_non_attack, f'Frequenza di Attivazione - {rule}')

        def plot_parent_process_counts(df_attack, df_non_attack, title):
            """
            Plotta il numero di attacchi e falsi positivi per ID del processo padre.
            
            Args:
            df_attack: DataFrame contenente solo attacchi reali.
            df_non_attack: DataFrame contenente solo falsi positivi.
            title: Titolo del grafico.
            """
            
            parent_process_counts_attack = df_attack['parent_process_id'].value_counts().nlargest(10)
            parent_process_counts_non_attack = df_non_attack['parent_process_id'].value_counts().nlargest(10)
            
            combined = pd.DataFrame({'Attacchi': parent_process_counts_attack, 'Non Attacchi': parent_process_counts_non_attack})
            
            if not combined.empty:
                colors = {'Attacchi': 'red', 'Non Attacchi': 'blue'}
                ax = combined.plot(kind='bar', figsize=(20, 6), color=[colors[col] for col in combined.columns])
                plt.title(title)
                plt.xlabel('Parent Process Id')
                plt.xticks(rotation=55, ha='right')
                plt.ylabel('Numero di Attivazioni')
                
                for p in ax.patches:
                    ax.annotate(f'{int(p.get_height())}',
                                (p.get_x() + p.get_width() / 2, p.get_height()),
                                ha='center', va='bottom')
                
                plt.show()
            else:
                print(f"Nessun dato disponibile per il grafico {title}")

        plot_parent_process_counts(df_attack, df_non_attack, 'Attacchi e Non-Attacchi per Parent Process Id')

        def plot_process_counts(df_attack, df_non_attack, title):
            """
            Plotta il numero di attacchi e falsi positivi per ID del processo.
            
            Args:
            df_attack: DataFrame contenente solo attacchi reali.
            df_non_attack: DataFrame contenente solo falsi positivi.
            title: Titolo del grafico.
            """
            
            process_counts_attack = df_attack['process_id'].value_counts().nlargest(10)
            process_counts_non_attack = df_non_attack['process_id'].value_counts().nlargest(10)
            
            combined = pd.DataFrame({'Attacchi': process_counts_attack, 'Non Attacchi': process_counts_non_attack})
            
            if not combined.empty:
                colors = {'Attacchi': 'red', 'Non Attacchi': 'blue'}
                ax = combined.plot(kind='bar', figsize=(20, 6), color=[colors[col] for col in combined.columns])
                plt.title(title)
                plt.xlabel('Process Id')
                plt.xticks(rotation=55, ha='right')
                plt.ylabel('Numero di Attivazioni')
                
                for p in ax.patches:
                    ax.annotate(f'{int(p.get_height())}',
                                (p.get_x() + p.get_width() / 2, p.get_height()),
                                ha='center', va='bottom')
                
                plt.show()
            else:
                print(f"Nessun dato disponibile per il grafico {title}")

        plot_process_counts(df_attack, df_non_attack, 'Attacchi e Non-Attacchi per Process Id')

        def plot_path_category_detailed(df_attack, df_non_attack, title):
            """
            Plotta il numero di attacchi e falsi positivi per categoria del Path.
            
            Args:
            df_attack: DataFrame contenente solo attacchi reali.
            df_non_attack: DataFrame contenente solo falsi positivi.a
            title: Titolo del grafico.
            """
            
            path_category_detailed_attack = df_attack['path_category_detailed'].value_counts().nlargest(10)
            path_category_detailed_non_attack = df_non_attack['path_category_detailed'].value_counts().nlargest(10)
            
            combined = pd.DataFrame({'Attacchi': path_category_detailed_attack, 'Non Attacchi': path_category_detailed_non_attack})
            
            if not combined.empty:
                colors = {'Attacchi': 'red', 'Non Attacchi': 'blue'}
                ax = combined.plot(kind='bar', figsize=(20, 6), color=[colors[col] for col in combined.columns])
                plt.title(title)
                plt.xlabel('Path Category')
                plt.xticks(rotation=0)
                plt.ylabel('Numero di Attivazioni')
                
                for p in ax.patches:
                    ax.annotate(f'{int(p.get_height())}',
                                (p.get_x() + p.get_width() / 2, p.get_height()),
                                ha='center', va='bottom')
                
                plt.show()
            else:
                print(f"Nessun dato disponibile per il grafico {title}")

        plot_path_category_detailed(df_attack, df_non_attack, 'Attacchi e Non-Attacchi per Categoria del Path')

        def plot_mitre_attack_counts(df_attack, df_non_attack, title, ax):
            """
            Plotta il numero di attacchi e falsi positivi per tipo di evento.
            
            Args:
            df_attack: DataFrame contenente solo attacchi reali.
            df_non_attack: DataFrame contenente solo falsi positivi.
            title: Titolo del grafico.
            ax: Oggetto Axes su cui tracciare il grafico.
            """
            
            mitre_attack_counts_attack = df_attack[mitre_attack_col].value_counts()
            mitre_attack_counts_non_attack = df_non_attack[mitre_attack_col].value_counts()
                
            combined = pd.DataFrame({'Attacchi': mitre_attack_counts_attack, 'Non Attacchi': mitre_attack_counts_non_attack})
            
            # Colori per le colonne
            colors = {'Attacchi': 'red', 'Non Attacchi': 'blue'}

            combined.plot(kind='bar', ax=ax, figsize=(16, 8), color=[colors[col] for col in combined.columns])
            ax.set_title(title)
            ax.set_xlabel('Mitre Attack Id', labelpad=50)
            ax.set_ylabel('Numero di Attivazioni')
            ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
            
            for p in ax.patches:
                ax.annotate(f'{int(p.get_height())}',
                            (p.get_x() + p.get_width() / 2, p.get_height()),
                            ha='center', va='bottom')
            
            plt.tight_layout()
        
        def plot_event_type_counts(df_attack, df_non_attack, title, ax):
            """
            Plotta il numero di attacchi e falsi positivi per tipo di evento.
            
            Args:
            df_attack: DataFrame contenente solo attacchi reali.
            df_non_attack: DataFrame contenente solo falsi positivi.
            title: Titolo del grafico.
            ax: Oggetto Axes su cui tracciare il grafico.
            """
            
            event_type_counts_attack = df_attack[eventtype_col].value_counts()
            event_type_counts_non_attack = df_non_attack[eventtype_col].value_counts()
                
            combined = pd.DataFrame({'Attacchi': event_type_counts_attack, 'Non Attacchi': event_type_counts_non_attack})

            # Colori per le colonne
            colors = {'Attacchi': 'red', 'Non Attacchi': 'blue'}
                
            combined.plot(kind='bar', ax=ax, figsize=(16, 8), color=[colors[col] for col in combined.columns])
            ax.set_title(title)
            ax.set_xlabel('Tipo di Evento', labelpad=50)
            ax.set_ylabel('Numero di Attivazioni')
            ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
            
            for p in ax.patches:
                ax.annotate(f'{int(p.get_height())}',
                            (p.get_x() + p.get_width() / 2, p.get_height()),
                            ha='center', va='bottom')
            
            plt.tight_layout()
        
        def plot_severity_counts(df_attack, df_non_attack, title, ax):
            """
            Plotta il numero di attacchi e falsi positivi per livello di severità.
            
            Args:
            df_attack: DataFrame contenente solo attacchi reali.
            df_non_attack: DataFrame contenente solo falsi positivi.
            title: Titolo del grafico.
            ax: Oggetto Axes su cui tracciare il grafico.
            """
            
            severity_counts_attack = df_attack[severity_col].value_counts()
            severity_counts_non_attack = df_non_attack[severity_col].value_counts()
                
            combined = pd.DataFrame({'Attacchi': severity_counts_attack, 'Non Attacchi': severity_counts_non_attack})

            # Colori per le colonne
            colors = {'Attacchi': 'red', 'Non Attacchi': 'blue'}
                
            combined.plot(kind='bar', ax=ax, figsize=(16, 8), color=[colors[col] for col in combined.columns])
            ax.set_title(title)
            ax.set_xlabel('Severità', labelpad=50)
            ax.set_ylabel('Numero di Attivazioni')
            ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
            
            for p in ax.patches:
                ax.annotate(f'{int(p.get_height())}',
                            (p.get_x() + p.get_width() / 2, p.get_height()),
                            ha='center', va='bottom')
            
            plt.tight_layout()
        
        def plot_tag_counts(df_attack, df_non_attack, title, ax):
            """
            Plotta il numero di attacchi e falsi positivi per tag.
            
            Args:
            df_attack: DataFrame contenente solo attacchi reali.
            df_non_attack: DataFrame contenente solo falsi positivi.
            title: Titolo del grafico.
            ax: Oggetto Axes su cui tracciare il grafico.
            """
            
            tag_counts_attack = df_attack[tag_col].value_counts()
            tag_counts_non_attack = df_non_attack[tag_col].value_counts()
                
            combined = pd.DataFrame({'Attacchi': tag_counts_attack, 'Non Attacchi': tag_counts_non_attack})

            # Colori per le colonne
            colors = {'Attacchi': 'red', 'Non Attacchi': 'blue'}
                
            combined.plot(kind='bar', ax=ax, figsize=(16, 8), color=[colors[col] for col in combined.columns])
            ax.set_title(title)
            ax.set_xlabel('Tag', labelpad=15)
            ax.set_ylabel('Numero di Attivazioni')
            ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
            
            for p in ax.patches:
                ax.annotate(f'{int(p.get_height())}',
                            (p.get_x() + p.get_width() / 2, p.get_height()),
                            ha='center', va='bottom')
            
            plt.tight_layout()
        
        # Creazione dei subplot
        fig, axs = plt.subplots(1, 4, figsize=(25, 16))
        
        # Chiamata alle funzioni di plot con gli assi corrispondenti
        plot_mitre_attack_counts(df_attack, df_non_attack, f'Mitre Attack Id', ax=axs[0])
        plot_event_type_counts(df_attack, df_non_attack, f'Tipo di Evento', ax=axs[1])
        plot_severity_counts(df_attack, df_non_attack, f'Severità', ax=axs[2])
        plot_tag_counts(df_attack, df_non_attack, f'Tag', ax=axs[3])
        
        # Imposta il layout
        plt.tight_layout()
        plt.show()


    def patterns_before_activation(df, rule, elements_to_consider, rule_col='signature', mitre_attack_col='RuleAnnotation.mitre_attack.id', path_col='path_category_detailed', time_col='_time', eventtype_col='EventType', parent_col='parent_process_id', process_col='process_id', severity_col='severity_id', tag_col='tag', attack_col='corrisponde_ad_attacco'):
        """
        Analizza i pattern degli eventi che precedono l'attivazione di una regola specifica.

        Args:
        df: DataFrame contenente i dati da analizzare.
        rule: La regola specifica da analizzare.
        elements_to_consider: Numero di eventi precedenti da considerare.
        rule_col: Nome della colonna che contiene l'ID della regola.
        mitre_attack_col: Nome della colonna che contiene l'ID dell'attacco.
        path_col: Nome della colonna che contiene il path dell'evento.
        time_col: Nome della colonna che contiene il timestamp.
        eventtype_col: Nome della colonna che contiene il tipo di evento.
        parent_col: Nome della colonna che contiene l'ID del processo padre.
        process_col: Nome della colonna che contiene l'ID del processo.
        severity_col: Nome della colonna che contiene il livello di severità.
        tag_col: Nome della colonna che contiene i tag.
        attack_col: Nome della colonna che indica se l'attivazione corrisponde a un attacco reale.
        """

        # Verifica se la regola specificata è presente nel dataframe
        if rule not in df[rule_col].values:
            print("La regola ricercata non è presente")
            return
        
        # Verifica se ci sono attacchi corrispondenti
        if not df[attack_col].any():
            print("Non ci sono attacchi")
            return

        # Ordina il DataFrame per il tempo per garantire l'ordine cronologico
        df = df.sort_values(by=time_col)
        
        # Lista per memorizzare gli eventi precedenti
        previous_events = []

        # Scorri il DataFrame completo
        for i in range(1, len(df)):
            # Ottieni l'evento attuale e precedente
            current_event = df.iloc[i]
            previous_event = df.iloc[i - 1]

            # Verifica se l'evento attuale è la regola specificata
            if current_event[rule_col] == rule and current_event[attack_col] == True:
                # Controlla se l'evento attuale è un "primo avvio della serie"
                if (current_event[rule_col] != previous_event[rule_col] or
                    current_event[mitre_attack_col] != previous_event[mitre_attack_col] or
                    current_event[path_col] != previous_event[path_col] or
                    current_event[parent_col] != previous_event[parent_col] or
                    current_event[process_col] != previous_event[process_col] or
                    current_event[eventtype_col] != previous_event[eventtype_col] or
                    current_event[tag_col] != previous_event[tag_col] or
                    current_event[severity_col] != previous_event[severity_col]
                    ):
                    
                    # Aggiungi gli eventi precedenti al primo avvio della serie
                    start_idx = max(0, i - elements_to_consider)
                    previous_events.extend(df.iloc[start_idx:i].to_dict('records'))

        # Crea un DataFrame dagli eventi precedenti
        df_previous_events = pd.DataFrame(previous_events)

        def plot_rules_counts(df, column, title):
            # Calcola i conteggi
            counts = df.groupby([column, attack_col]).size().unstack(fill_value=0)
            counts = counts.loc[(counts.sum(axis=1) >= 10)]  # Filtra le righe con somma >= 10
            counts.columns = ['Non Attacco' if col == False else 'Attacco' for col in counts.columns]
            counts = counts.sort_values(by='Attacco', ascending=False)  # Ordina per conteggi di 'Attacco'

            # Trasforma il DataFrame in un formato adatto ad Altair
            counts = counts.reset_index().melt(id_vars=[column], var_name='tipo_attacco', value_name='conteggio')
            
            # Crea il grafico a barre usando Altair
            chart = alt.Chart(counts).mark_bar().encode(
                x=alt.X(column + ':O', title='Regole', sort='-y'),
                y=alt.Y('sum(conteggio):Q', title='Numero di occorrenze'),
                color=alt.Color('tipo_attacco:N', title=None, scale=alt.Scale(range=['red', 'blue'])),
                tooltip=[alt.Tooltip(column + ':O', title='Regole'), alt.Tooltip('sum(conteggio):Q', title='Numero di occorrenze')]
            ).properties(
                width=1400,
                height=700,
                title=alt.TitleParams(
                text=title,
                fontSize=18,
                anchor='start',
                offset=20  # Aggiungi un margine superiore di 20 punti tra il titolo e il grafico
                )
            ).configure_legend(
                strokeColor='black',  # Colore del bordo della legenda
                strokeWidth=3,  # Spessore del bordo della legenda
                orient='top-right',  # Posizione della legenda (in alto a destra)
                offset=50,  # Distanza della legenda dal bordo del grafico
                padding=20,
                labelFontSize=15,
                fillColor='lightgrey'
            ).configure_axisY(
                labelFontSize=12,
                titleFontSize=15,
            ).configure_axisX(
                titleFontSize=15,
                labels=False
            ).configure_title(
                fontSize=16,
                anchor='start'
            )

            chart.display()

        def plot_column_counts(df, column, title):
            # Divide il DataFrame in attacchi e non attacchi
            attacks = df[df[attack_col] == True]
            non_attacks = df[df[attack_col] == False]
            
            # Conta le occorrenze per attacchi e non attacchi
            counts_attacks = attacks[column].value_counts()
            counts_non_attacks = non_attacks[column].value_counts()

            counts_attacks = counts_attacks[counts_attacks > 3]
            counts_non_attacks = counts_non_attacks[counts_non_attacks > 3]

            # Trova il valore massimo di counts_attacks
            max_v_attacks = max(counts_attacks)
            
            # Prepara il plot
            plt.figure(figsize=(18, 8))
            
            # Plot per attacchi (rosso)
            counts_attacks.plot(kind='bar', color='red', alpha=1, label='Attacchi')
            
            # Plot per non attacchi (blu)
            counts_non_attacks.plot(kind='bar', color='blue', alpha=1, label='Non Attacchi')

            # Aggiungi testo sopra le barre
            for i, (v_attacks, v_non_attacks) in enumerate(zip(counts_attacks, counts_non_attacks)):
                offset = max_v_attacks / 75  # Usa il valore massimo per il calcolo dell'offset
                plt.text(i, v_attacks + offset, f"-", color='black', ha='center')
                plt.text(i, v_attacks + offset, f"{v_attacks} ", color='red', ha='right')
                plt.text(i, v_attacks + offset, f"  {v_non_attacks}", color='blue', ha='left')
            
            plt.xlabel(column)
            plt.ylabel('Numero di occorrenze')
            plt.title(title)
            plt.legend()
            plt.xticks(rotation=45, ha='right')

            # Aggiungi spazio extra a sinistra
            plt.xlim(left=-0.7)

            plt.show()

        # Plot per le regole attivate prima di quella scelta
        plot_rules_counts(df_previous_events, rule_col, f'{elements_to_consider} Regole attivate subito prima di {rule}')
        
        # Plot per gli attacchi registrati prima dell'attivazione della regola scelta
        plot_column_counts(df_previous_events, mitre_attack_col, f'{elements_to_consider} Mitre Id registrati subito prima di {rule}')

        # Plot per i parent process registrati prima dell'attivazione della regola scelta
        plot_column_counts(df_previous_events, path_col, f'{elements_to_consider} Categorie del Path registrate subito prima di {rule}')

        # Plot per i parent process registrati prima dell'attivazione della regola scelta
        plot_column_counts(df_previous_events, parent_col, f'{elements_to_consider} Parent Process registrati subito prima di {rule}')

        # Plot per i process registrati prima dell'attivazione della regola scelta
        plot_column_counts(df_previous_events, process_col, f'{elements_to_consider} Process registrati subito prima di {rule}')


        # Crea un subplot per eventtype_col, tag_col e severity_col
        fig, axes = plt.subplots(nrows=1, ncols=3, figsize=(18, 8))

        # Plot per gli eventtype registrati prima dell'attivazione della regola scelta (attacchi vs non attacchi)
        counts_eventtype_attacks = df_previous_events[df_previous_events[attack_col] == True][eventtype_col].value_counts()
        counts_eventtype_non_attacks = df_previous_events[df_previous_events[attack_col] == False][eventtype_col].value_counts()

        counts_eventtype_attacks.plot(kind='bar', ax=axes[0], color='red', alpha=1, label='Attacchi')
        counts_eventtype_non_attacks.plot(kind='bar', ax=axes[0], color='blue', alpha=1, label='Non Attacchi')

        # Trova il valore massimo di counts_eventtype_attacks
        max_v_eventtype_attacks = max(counts_eventtype_attacks)

        axes[0].set_xlabel(eventtype_col, labelpad=45)
        axes[0].set_ylabel('Numero di occorrenze')
        axes[0].set_title(f'{elements_to_consider} EventType prima di {rule}')
        axes[0].tick_params(axis='x', rotation=0)
        axes[0].legend()

        # Aggiungi testo sopra le barre
        for i, (v_attacks, v_non_attacks) in enumerate(zip(counts_eventtype_attacks, counts_eventtype_non_attacks)):
            offset = max_v_eventtype_attacks / 100  # Usa il valore massimo per il calcolo dell'offset
            axes[0].text(i, v_attacks + offset, f"-", color='black', ha='center')
            axes[0].text(i, v_attacks + offset, f"{v_attacks} ", color='red', ha='right')
            axes[0].text(i, v_attacks + offset, f"  {v_non_attacks}", color='blue', ha='left')

        # Plot per i tag registrati prima dell'attivazione della regola scelta (attacchi vs non attacchi)
        counts_tag_attacks = df_previous_events[df_previous_events[attack_col] == True][tag_col].value_counts()
        counts_tag_non_attacks = df_previous_events[df_previous_events[attack_col] == False][tag_col].value_counts()

        counts_tag_attacks.plot(kind='bar', ax=axes[1], color='red', alpha=1, label='Attacchi')
        counts_tag_non_attacks.plot(kind='bar', ax=axes[1], color='blue', alpha=1, label='Non Attacchi')

        # Trova il valore massimo di counts_tag_attacks
        max_v_tag_attacks = max(counts_tag_attacks)

        axes[1].set_xlabel(tag_col)
        axes[1].set_ylabel('Numero di occorrenze')
        axes[1].set_title(f'{elements_to_consider} Tag prima di {rule}')
        axes[1].tick_params(axis='x', rotation=0)
        axes[1].legend()

        # Aggiungi testo sopra le barre
        for i, (v_attacks, v_non_attacks) in enumerate(zip(counts_tag_attacks, counts_tag_non_attacks)):
            offset = max_v_tag_attacks / 100  # Usa il valore massimo per il calcolo dell'offset
            axes[1].text(i, v_attacks + offset, f"-", color='black', ha='center')
            axes[1].text(i, v_attacks + offset, f"{v_attacks} ", color='red', ha='right')
            axes[1].text(i, v_attacks + offset, f"  {v_non_attacks}", color='blue', ha='left')

        # Plot per i severity registrati prima dell'attivazione della regola scelta (attacchi vs non attacchi)
        counts_severity_attacks = df_previous_events[df_previous_events[attack_col] == True][severity_col].value_counts()
        counts_severity_non_attacks = df_previous_events[df_previous_events[attack_col] == False][severity_col].value_counts()

        counts_severity_attacks.plot(kind='bar', ax=axes[2], color='red', alpha=1, label='Attacchi')
        counts_severity_non_attacks.plot(kind='bar', ax=axes[2], color='blue', alpha=1, label='Non Attacchi')

        # Trova il valore massimo di counts_severity_attacks
        max_v_severity_attacks = max(counts_severity_attacks)

        axes[2].set_xlabel(severity_col, labelpad=45)
        axes[2].set_ylabel('Numero di occorrenze')
        axes[2].set_title(f'{elements_to_consider} Severity prima di {rule}')
        axes[2].tick_params(axis='x', rotation=0)
        axes[2].legend()

        # Aggiungi testo sopra le barre
        for i, (v_attacks, v_non_attacks) in enumerate(zip(counts_severity_attacks, counts_severity_non_attacks)):
            offset = max_v_severity_attacks / 100  # Usa il valore massimo per il calcolo dell'offset
            axes[2].text(i, v_attacks + offset, f"-", color='black', ha='center')
            axes[2].text(i, v_attacks + offset, f"{v_attacks} ", color='red', ha='right')
            axes[2].text(i, v_attacks + offset, f"  {v_non_attacks}", color='blue', ha='left')

        plt.tight_layout()
        plt.show()