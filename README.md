# [Tirocinio](https://github.com/SigmaCorvallisYoroi/Tirocinio/tree/main)
  
## File principali:
### [analisi_log_attacco.ipynb](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/analisi_log_attacco.ipynb)
Import delle **librerie** e **classi** necessarie.
Caricamento e visualizzazione del **dataframe grezzo**.  
Visualizzazione del dataframe dopo **Processing** e **StandardScaling**.  
Visualizzazione del dataframe con la **colonna** che indica se ciascun evento **corrisponde ad attacco** o no.  
Visualizzazione dei **grafici** con le varie analisi statistiche su **regole e attacchi** e delle loro **descrizioni**.  
Visualizzazione del **grafico** con l'analisi statistica sulle **severity** per ogni attacco.  
Creazione di un **dataset** con statistiche relative ai **cambiamenti delle severity** in caso di **assenza** di una *regola per volta* dal dataset iniziale e visualizzazione di **grafici** *a riguardo*.
Scelta della **regola da studiare** e visualizzazione dei **grafici** con le varie analisi statistiche relativi ad essa.  
Scelta del numero di **eventi da considerare** prima della regola che interessa per visualizzare **grafici** con i **pattern degli eventi antecedenti** alla sua attivazione.  
Visualizzazione di **pattern** nelle *signature* e nei *mitre_attack.id*, anche in base a *specifico* **severity_value**.  
Visualizzazione dei **grafici** delle **Matrici di Correlazione**.  
Visualizzazione dei **risultati** dei modelli di **Machine Learning** e della **rete neurale** in base al tipo di codifica utilizzato, OneHot e Label Encoder.  
  
### [analisi_pattern.ipynb](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/analisi_pattern.ipynb)
**Riconoscimento** e visualizzazione, grazie ad una serie di metodi diversi, dei **pattern** negli eventi del dataset in base ad ogni attacco registrato.  

### [analisi_log_attacco_all_csv.ipynb](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/analisi_log_attacco_all_csv.ipynb)
Copia di *analisi_log_attacco* funzionante con **tutti i dataset di log e attacchi** uniti insieme.  

### [analisi_light_attacchi.ipynb](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/analisi_light_attacchi.ipynb)
Copia di *analisi_log_attacco* ottimizzata per la visualizzazione delle analisi eseguite in un *Notebook più leggero*. Qui carichiamo i CSV con **attacchi reali**.

### [ExRandomGroupAttack.ps1](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/ExRandomGroupAttack.ps1)
Questo **script PowerShell** carica il modulo *Invoke-AtomicRedTeam* e automatizza l'esecuzione di test di tecniche di attacco definite nel framework MITRE ATT&CK.  
**Registra i dettagli di ciascun attacco**, come codici, numeri di test, tempi di inizio e fine, ed eventuali codici di uscita, in un **file CSV**.  
Inoltre, avvia e ferma una **trascrizione per il logging dettagliato delle esecuzioni**.

### [Descrizione del progetto.md](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/Descrizione%20del%20progetto.md)
Questo file contiene una **descrizione** molto accurata **del progetto**, dei suoi obiettivi, delle sue problematiche e dei possibili prossimi passi.

## File secondari:
### [file_csv](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_csv)
**Raccolta** di **file CSV** con i dataset di eventi ed attacchi.

### [file_html](https://github.com/SigmaCorvallisYoroi/Tirocinio/tree/main/file_html)
**Raccolta** di **file html** utili per visualizzare correttamente i **file interattivi** (*da scaricare e visualizzare direttamente da Browser*).

### [file_py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py)
**Raccolta** di **file Python** con le *Classi* necessarie.

#### [lib.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/lib.py)
Classe per **importare** tutte le librerie necessarie.

#### [attack_log_unification.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/attack_log_unification.py)
Classe che permette di **unire** due o più attacklog in base alla colonna "Data inizio attacco".

#### [csv_preprocessing_scaler.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/csv_preprocessing_scaler.py)
Classe per:  
            **visualizzare il df**;  
            **preprocessing di base** (rimozione delle colonne superflue e dei valori nulli rimanenti, conversione in datetime dove necessario);  
            **preprocessing** per preparare i dati per **Label** e **OneHot Encoder**;  
            applicare lo **Standard Scaler** al dataset.  

#### [run_log_parser.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/run_log_parser.py)
Classe per:  
            importare ed elaborare i **log di esecuzione**;  
            individuare e **riportare gli attacchi** nel dataset fornito nella nuova **colonna** "**corrisponde_ad_attacco**";  
            creare il dataset "**event_df**" con i dati di ciascuna colonna divisi per **ogni attacco** e con le *nuove colonne* "**severity_max**", "**severity_mean**" e "**severity_min**".
  
#### [plots.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/plots.py)
Classe per:  
            visualizzare un **grafico** con la **percentuale** di eventi corrispondenti ad **attacchi**;  
            visualizzare un **grafico** con le **10 regole** che si sono **attivate più volte** in generale, durante un attacco e durante un falso attacco;  
            visualizzare un **grafico** con la **distribuzione di attacchi e non-attacchi** in base alle colonne "**path_category_detailed**", "**severity_id**", "**tag**" e "**EventType**";  
            visualizzare un **grafico** con *attacchi* e *non-attacchi* per **ogni regola**:  
            visualizzare un **grafico** con **Precisione** e **Recall** di ogni regola.

#### [utils.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/utils.py)
Classe per scriveree le **descrizioni** di alcuni dei **grafici** in formato *markdown*

#### [stat_severity.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/stat_severity.py)
Classe per visualizzare il **grafico delle criticità** *massime*, *medie* e *minime* di **ogni attacco**.

#### [signature_stats_calculator.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/signature_stats_calculator.py)
Classe per visualizzare un dataset in cui possiamo vedere per **ogni regola**, se dovesse essere **rimossa**, *quali cambiamenti* di **severity** comporterebbero per il dataset iniziale e se ci dovessero essere degli **attacchi non più rilevati**.

#### [sigma_rule_analysis.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/sigma_rule_analysis.py)
Classe per visualizzare una **serie di grafici** che ci aiutano a capire quali **rapporti tra gli indici** del dataset creato in precedenza ci indicano in modo più evidente le **regole più importanti**.

#### [attack_pattern_analyzer.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/attack_pattern_analyzer.py)
Classe per:  
            visualizzare i **grafici** con tutti i *valori corrispondenti* ad un dato numero di **attacchi precedenti** a *tutti gli attacchi* che hanno una **certa criticità media**;   
            visualizzare eventuali **pattern** di '**signature**' e '**RuleAnnotation.mitre_attack.id**' all'*interno* di *ciascun attacco*.

#### [plots_single_attack.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/plots_single_attack.py)
Classe per:  
            visualizzare attacchi e non attacchi in un **grafico** con la **frequenza di attivazione** di una **regola specifica** per intervalli di 5 minuti;  
            visualizzare dei **grafici** con attacchi e non-attacchi di una **regola specifica** in base ai **mitre attack** a cui ha risposto, ai **tipi di evento**, alle **criticità**, ai **tag**, agli **id dei processi** e dei **processi genitori**;  
            visualizzare dei **grafici** con le **regole, gli attacchi, i parent process, i process, gli EventType, i tag e le severity** che si sono **attivate subito prima della attivazione di una regola specifica** (il numero di eventi da considerare prima dell'attivazione della regola è a scelta).  

#### [signatures_patterns.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/signatures_patterns.py)
Classe per visualizzare tutte le **sequenze** delle regole attivate durante gli **attacchi** che **non** compaiono mai tra le sequenze delle regole in risposta a **non-attacchi**.

#### [correlation_matrix_plots.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/correlation_matrix_plots.py)  
Classe per visualizzare il **grafico** delle **matrici di correlazione** per **Label** e **One Hot** Encoder.  

#### [preprocessing_train_test_split.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/preprocessing_train_test_split.py)  
Classe per **dividere** i dati preprocessati nei set di **training** e **test**.

#### [initial_training.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/initial_training.py)  
Classe per **addestrare** e **valutare** i dati di train e test su diversi modelli di **machine learning di base**.  

#### [hyperparameter_tuning.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/hyperparameter_tuning.py)  
Classe per il **tuning degli iperparametri** dei modelli di machine learning tramite **grid search**.  

#### [advanced_models.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/advanced_models.py)  
Classe per **addestrare** e **valutare** i dati di train e test su diversi modelli di **machine learning avanzati**.  

#### [deep_learning_model.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/deep_learning_model.py)  
Classe per **addestrare** e **valutare** i dati di train e test su un modello di **rete neurale** tramite l'uso della libreria **Keras**.  

#### [model_evaluator.py](https://github.com/SigmaCorvallisYoroi/Tirocinio/blob/main/file_py/model_evaluator.py)  
Classe per visualizzare i **risultati dei modelli** tramite vari **report di classificazione**.
