# Analisi dei Log degli Attacchi utilizzando Machine Learning

Questo progetto esplora l'utilizzo di tecniche di machine learning e deep learning per l'analisi dei log degli attacchi, con l'obiettivo di identificare e caratterizzare i comportamenti malevoli. Utilizzando un dataset di log proveniente da sistemi di monitoraggio, sono stati preprocessati e analizzati i dati per estrarre pattern significativi e valutare la correlazione tra vari eventi e la probabilità di un attacco. Sono stati impiegati modelli di machine learning, come KNN, XGBoost e altri, oltre ad una rete neurale implementata con Keras, per predire la presenza di attacchi basati su caratteristiche codificate. L'analisi ha rivelato sequenze di regole particolarmente indicative di attività malevola e ha permesso di identificare le regole di sicurezza più efficaci. Il progetto affronta anche le sfide incontrate, come la gestione di dati mancanti e il tuning degli iperparametri, offrendo soluzioni pratiche per migliorare la precisione dei modelli. I risultati ottenuti mirano a fornire un contributo alla comprensione e mitigazione dei rischi di sicurezza informatica attraverso tecniche avanzate di analisi dei dati.


## Obiettivi

La protezione contro gli attacchi informatici è diventata una priorità fondamentale per le organizzazioni a causa dell'aumento esponenziale delle minacce digitali. La capacità di rilevare tempestivamente questi attacchi è cruciale per minimizzare i danni potenziali. Tuttavia, il volume e la complessità dei dati generati dai sistemi di monitoraggio della sicurezza rendono difficile l'analisi manuale e la risposta agli incidenti.

Questo progetto si propone di utilizzare tecniche avanzate di machine learning e deep learning per automatizzare l'analisi dei log degli attacchi. L'obiettivo principale è identificare pattern di comportamento che possano indicare attività malevole e migliorare la capacità di rilevamento degli attacchi. A tal fine, abbiamo sviluppato un pipeline di analisi che include il preprocessing dei dati, la codifica delle caratteristiche, e l'applicazione di vari algoritmi di apprendimento automatico.

Un aspetto centrale del progetto è l'analisi delle regole di sicurezza implementate e la loro efficacia nel rilevamento degli attacchi. Attraverso l'uso di tecniche come il Label Encoding e il One-Hot Encoding, i dati sono stati trasformati per adattarsi ai requisiti dei modelli di machine learning. Successivamente, modelli come XGBoost e una rete neurale basata su Keras sono stati addestrati per classificare gli eventi di log come attacchi o non-attacchi.

In sintesi, il presente lavoro vuole contribuire al campo della sicurezza informatica fornendo un approccio sistematico e scalabile per l'analisi dei log degli attacchi, con implicazioni pratiche significative per la protezione delle infrastrutture digitali.


## Metodologia

1. Download e Setup del Progetto
Per iniziare, è necessario scaricare il progetto dal repository GitHub. Il progetto include già tutti i file necessari per eseguire l'analisi e, oltre all'installazione di un programma come VS Code, non ci sarà bisogno di importare manualmente le librerie necessarie all'esecuzione del codice.  
**Procedura di Download**  
Dalla pagina principale del progetto (https://github.com/SigmaCorvallisYoroi/Tirocinio) cliccare su " <> Code" e su "Download ZIP". Una volta scaricato il file .zip selezionare "Estrai tutto" e scegliere la cartella in cui estrarre i fle.

3. **Caricamento dei File CSV**
I file CSV contenenti i log degli attacchi devono essere caricati nel progetto, all'interno della cartella denominata "file_csv" per procedere con l'analisi.

4. **Scelta del file di analisi**
Dopo aver caricato i dati, è possibile eseguire varie analisi, inclusa la visualizzazione dei pattern di attacco e delle matrici di correlazione. Le sezioni specifiche del notebook eseguono queste analisi automaticamente.

- *analisi_log_attacco.ipynb* è il file principale, contenente tutte le analisi e la visualizzazione dei risultati ottenuti dai modelli di Machine Learning.
- *analisi_light_attacchi.ipynb* è una versione più leggera di analisi_log_attacco.ipynb. Contiene esclusivamente le analisi del file caricato in modo da poterle studiare più velocemente, senza la necessità di aspettare l'esecuzione dei modelli di Machine Learning. 
- *analisi_log_attacco_all_csv.ipynb* è una copia del file principale, pensata per funzionare con tutti i file csv ottenuti fino a questo momento.
- *analisi_pattern.ipynb* è un file dove abbiamo studiato ulteriori possibilità di riconoscimento pattern all'interno del Dataset principale.

4. **Visualizzazione delle Analisi**
Dopo aver scelto il file di analisi, per poterlo studiare, bisogna conoscere il nome o il percorso dei file CSV di interesse e caricarli al suo interno.
Per farlo bisogna:
- aprire il file di analisi scelto;
- scendere alla sezione "CARICAMENTO FILE" (la seconda dopo gli "Import");
- all'interno della cella di codice, nella seconda riga, sostituire il nome del file presente con quello del file con i log degli eventi che ci interessa (es: file_csv/---.csv -> file_csv/LogSplunkWF_03_07.csv);
- sempre all'interno della stessa cella di codice, nella quinta riga, sostituire il nome del file presente con quello del file contenente le date inizio e fine degli attacchi che ci interessano (es: file_csv/---.csv -> file_csv/attackLog_03_07.csv);
- infine eseguire il codice selezionando "Run All" in alto.


## Tipologie di analisi e conlusioni

Dopo le operazioni di Processing e StandardScaling del dataset passiamo allo studio delle analisi generate.  
Come prima cosa visualizziamo un **grafico a torta** che ci mostra come è diviso il nostro dataset tra attacchi e non-attacchi. Generalmente notiamo subito una relativa precisione delle regole, che mediamente tendono ad attivarsi più volte per gli attacchi che per eventi leciti.  
Successivamente visualizziamo un **grafico con le 10 regole che si sono attivate più volte** inizialmente considerando tutti gli eventi, poi solo gli attacchi e infine solo gli eventi leciti. Qui si può notare come, con poche eccezioni, le regole scattate più volte sono anche quelle che hanno effettivamente risposto a più attachi e che sono scattate a vuoto più volte.  
Il **grafico** che segue ci permette di visualizzare **Precisione e Recall** di ogni regola. Difficilmente le regole con Recall più alto riescono a mantenere una precisione alta, a differenza di quelle che compaiono meno all'interno del dataset.  
Il prossimo **grafico** ci mostra la **distribuzione di attacchi e non-attacchi** in base alla *categoria del percorso*, al *livello di criticità*, alla *descrizione* e al *tipo di evento* di ogni regola. I valori che si visualizzano tendono a rimanere costanti tra attacchi e eventi leciti ma questo è possibile che sia influenzato dal modo in cui vengono ricavati i dataset e che, per dataset reperiti con metodologie differenti, possa generare risultati diversi.  
L'ultimo **grafico** di questa sezione ci mostra la **distribuzione di attacchi e non-attacchi per ciascuna regola** del dataset. Sotto di esso è presente una cella di **markdown** che si aggiorna automaticamente con una **descrizione** dettagliata di ciò che possiamo ricavare dallo studio del grafico.  
Nella sezione "Analysis of Severity per Attacks" osserviamo il **grafico** delle **criticità massime, medie e minime** di ogni attacco. Questo grafico varia molto in base alle regole che si sono attivate, ma generalmente la classe con criticità "75" è quella che compare più spesso.  
In seguito troviamo una serie di **grafici** che ci mostrano tutti **i valori corrispondenti** (regole, mitre_attack.id, EventType, ecc.) ad un dato numero di **attacchi precedenti** a tutti gli **attacchi con una certa criticità media**. I valori del numero di attacchi e della criticià media che ci interessa possono essere scelti a piacere.  
Dopo questi grafici, nella sottosezione "Robustessa regole" creiamo e visualizziamo un **dataset** in cui possiamo controllare per ogni **regola**, se dovesse essere **rimossa**, quali **cambiamenti di severity** comporterebbero per il dataset iniziale e se ci dovessero essere degli attacchi non più rilevati. In questo dataset le colonne che ci aiutano di più a trovare le regole di maggior importanza sono sicuramente "*N_Max_Sev_Diff_15*" e "*N_Attacchi_Non_rilevati*".  
Subito sotto abbiamo una serie di **grafici** che ci aiutano a capire quali **rapporti tra gli indici** del dataset creato in precedenza ci **indicano** in modo più evidente le **regole più importanti**.  
Nella sezione "Graphic Analysis of Attacks for Chosen Rule" abbiamo la possibilità di **scegliere una regola da studiare** e di visualizzare dei **grafici** con varie analisi statistiche relative ad essa come la **Frequenza di Attivazione** giorno per giorno e la **distribuzione di attacchi e non-attacchi** in base alle sue caratteristiche.  
Un'altra analisi che possiamo fare riguardo alla nostra regola consiste nello **scegliere** uno specifico **numero di eventi** da considerare così da poter visualizzare un gruppo di **grafici** con i **pattern degli eventi antecedenti alla sua attivazione**.  
Successivamente continuiamo lo **studio dei pattern nelle signature e nei mitre_attack.id**, anche in base ad uno **specifico valore di criticità**.  
Gli ultimi grafici riguardano le **Matrici di Correlazione**, la prima dopo il *Label Encoding* e la seconda dopo il *OneHot Encoding*. In entrambe la riga di interesse è quella denominata "**corrisponde_ad_attacco**".  
Infine troviamo una visualizzazione dei **risultati dei modelli di Machine Learning e della rete neurale** in base al tipo di codifica utilizzato. Il modello migliore è sempre stato il **KNN (k-nearest neighbors)** che si è avvicinato più volte allo score di 0.90 sia nel corretto **riconoscimento** degli *eventi leciti* che per gli *eventi corrispondenti ad attacchi*.  


## Problemi Incontrati e Risoluzioni future

Una delle principali cause dei rallentamenti riscontrati all'interno di questo progetto è stata la necessità di una persona di supporto con una conoscenza approfondita dei dati su cui stavamo lavorando. Comprendere fin da subito le specifiche caratteristiche e la struttura dei dati nel dettaglio avrebbe facilitato la scelta delle analisi più rilevanti e delle decisioni critiche per ottimizzare i modelli di machine learning.  
Un'altra sfida significativa è stata l'ottenimento di dataset realistici e rappresentativi degli scenari di attacco reali. La disponibilità di dati più veritieri e completi avrebbe potuto aiutare molto a comprendere l'importanza delle specifiche analisi su cui concentrarsi e migliorare significativamente la capacità dei modelli di generalizzare e identificare comportamenti malevoli.

Questi problemi hanno evidenziato l'importanza di una stretta collaborazione con esperti di dominio e l'accesso a fonti di dati affidabili. Inoltre, l'adattamento e il tuning dei modelli di machine learning per affrontare meglio le peculiarità dei dati di log saranno aspetti cruciali per migliorare l'accuratezza e l'affidabilità delle predizioni. In futuro, la creazione di dataset sintetici basati su scenari ancora più realistici potrebbe rappresentare una soluzione utile per superare la scarsità di dati autentici e migliorare la formazione dei modelli.

Una delle prossime fasi del progetto che aiuterebbe molto a progredire consiste nel generare e studiare in modo approfondito i pattern delle attività lecite, al fine di verificare se i modelli sono in grado di riconoscere l'introduzione di attacchi informatici partendo da un dataset contenente solo eventi leciti.
