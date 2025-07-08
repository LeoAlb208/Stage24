from .lib import pd, Markdown, display

class MarkdownHelper:

    @staticmethod
    def create_value_counts_variables(df):
        """Calculates specific variables from a dataset and saves them in a dictionary"""

        # Regole diverse (tutte le regole presenti nel dataset)
        regole_diverse = df['signature'].nunique()

        attacchi_df = df[df['corrisponde_ad_attacco'] == True]
        non_attacchi_df = df[df['corrisponde_ad_attacco'] == False]

        # Regole attacco reale (tutte le regole che hanno risposto ad un attacco reale almeno una volta)
        regole_attacco_reale = attacchi_df['signature'].nunique()

        # Regole non attacco reale (tutte le regole che non hanno mai risposto ad un vero attacco)
        regole_non_attacchi_reale = len(set(non_attacchi_df['signature'].unique()) - set(attacchi_df['signature'].unique()))

        # Contatori per le regole specifiche, generiche e con lo stesso numero di attivazioni per attacchi e non-attacchi
        regole_generiche = 0
        regole_specifiche = 0
        regole_stesso_numero = 0

        signature_counts = df['signature'].value_counts()
        attack_counts = attacchi_df['signature'].value_counts()
        non_attack_counts = non_attacchi_df['signature'].value_counts()

        for signature in signature_counts.index:
            attacchi_regola = attack_counts.get(signature, 0)
            non_attacchi_regola = non_attack_counts.get(signature, 0)

            if attacchi_regola < non_attacchi_regola and attacchi_regola != 0:
                # Regole generiche (delle regole facenti parte di "Regole attacco reale" queste si sono attivate più volte per non-attacchi che per attacchi)
                regole_generiche += 1
            elif attacchi_regola > non_attacchi_regola:
                # Regole specifiche (delle regole facenti parte di "Regole attacco reale" queste si sono attivate più volte per attacchi che per non-attacchi)
                regole_specifiche += 1
            elif attacchi_regola == non_attacchi_regola:
                # Regole stesso numero (delle regole facenti parte di "Regole attacco reale" queste si sono attivate lo stesso numero di volte per attacchi e non-attacchi)
                regole_stesso_numero += 1

        # Nomi delle regole che fanno parte di "Regole non attacco reale"
        nomi_regole_non_attacco = list(set(non_attacchi_df['signature'].unique()) - set(attacchi_df['signature'].unique()))

        variabili = {
            'regole_diverse': regole_diverse,
            'regole_attacco_reale': regole_attacco_reale,
            'regole_generiche': regole_generiche,
            'regole_stesso_numero': regole_stesso_numero,
            'regole_specifiche': regole_specifiche,
            'regole_non_attacco': regole_non_attacchi_reale,
            'nomi_regole_non_attacco': nomi_regole_non_attacco
        }

        return variabili
    
    @staticmethod
    def display_value_counts_text(variables, size='h5'):
        """Display a summary using multiple variables in markdown with specified size"""
        md_text = (
            f'<{size}>Grazie a questo grafico invece possiamo giungere ad una serie di conclusioni.\n\n'
            f'Su **{variables["regole_diverse"]}** regole diverse:\n\n'
            f'- quelle scattate in risposta ad ALMENO un **attacco reale** sono **{variables["regole_attacco_reale"]}**.\n'
            f'  Di queste:\n'
            f'  - **{variables["regole_generiche"]}** si sono attivate più volte per **non-attacchi** rispetto che per gli attacchi. (*regole generiche*)\n'
            f'  - **{variables["regole_stesso_numero"]}** si sono attivate lo **stesso numero** di volte per attacchi e non-attacchi.\n'
            f'  - **{variables["regole_specifiche"]}** si sono attivate più volte in risposta ad **attacchi** rispetto che a non-attacchi (*regole specifiche*).\n\n'
            f'- quelle scattate **senza rispondere mai ad attacchi** sono **{variables["regole_non_attacco"]}**.\n\n'
            f'  **Si tratta di**: {variables["nomi_regole_non_attacco"]}</{size}>'
        )
        display(Markdown(md_text))