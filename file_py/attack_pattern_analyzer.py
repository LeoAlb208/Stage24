from .lib import px, plt, Counter

class AttackPatternAnalyzer:
    """Class to analyze attack patterns in a DataFrame based on severity values, attack and signature sequences."""

    def __init__(self, df):
        """
        Initialize the AttackPatternAnalyzer with a DataFrame.
        
        Parameters:
        df (pd.DataFrame): DataFrame containing the attack data.
        """
        self.df = df

    def pattern_before_attack(self, num_attacks, severity_value):
        """
        Analyze patterns before attacks within a specific severity range.
        
        Parameters:
        num_attacks (int): Number of attacks to analyze before the current attack.
        severity_value (float): The target severity value to filter attacks.
        
        Raises:
        ValueError: If severity_value is not between 25 and 100.
        """
        if severity_value < 25 or severity_value > 100:
            raise ValueError("severity_value must be between 25 and 100")
        
        severity_lower_bound = severity_value - 2.5
        severity_upper_bound = severity_value + 2.5

        if self.df.empty:
            print("Non ci sono attacchi nel range di criticità specificato.")
            return

        # Filter rows within the specified severity_mean range
        filtered_df = self.df[(self.df['severity_mean'] >= severity_lower_bound) &
                              (self.df['severity_mean'] <= severity_upper_bound)]
        

        results = {
            'signature': [],
            'RuleAnnotation.mitre_attack.id': [],
            'path_category_detailed':[],
            'EventType': [],
            'tag': [],
            'severity_id': []
        }
        
        for idx in filtered_df.index:
            if idx > num_attacks:
                start_idx = max(0, idx - num_attacks)
                relevant_rows = self.df.iloc[start_idx:idx]
                
                for col in results.keys():
                    values = relevant_rows[col].sum()
                    results[col].extend(values)

        # Plotting the results with Matplotlib and Plotly
        for col, values in results.items():
            counter = Counter(values)
            labels, counts = zip(*counter.items())
            total = sum(counts)
            percentages = [round(count / total * 100, 2) for count in counts]
            
            if col == 'RuleAnnotation.mitre_attack.id' or col == 'signature':
                # Use Plotly for these columns
                fig = px.bar(x=labels, y=percentages, title=f'Percentage of {col} in the last {num_attacks} attacks before attacks within {severity_value - 2.5} and {severity_value + 2.5} range',
                            labels={'x': ' ', 'y': 'Percentage (%)'})
                
                fig.update_traces(
                    hovertemplate="<br>rule = %{x}<br>percentage = %{y:.2f} %<extra></extra>"
                )
                fig.update_layout(xaxis=dict(showticklabels=False), height=600)

                fig.show()

            else:
                plt.figure(figsize=(10, 5))
                plt.bar(labels, percentages)
                plt.title(f'Percentage of {col} in the last {num_attacks} attacks before attacks within {severity_value - 2.5} and {severity_value + 2.5} range')
                plt.xlabel(col)
                plt.ylabel('Percentage (%)')

                if col == 'severity_id':
                    # Filter for specific severity values
                    specific_labels = [25, 50, 75, 100]
                    specific_counts = [percentages[labels.index(x)] if x in labels else 0 for x in specific_labels]
                    plt.bar(specific_labels, specific_counts, width=8)
                    plt.xticks(specific_labels, rotation=0)
                elif col == 'EventType':
                    plt.xticks(range(0, 11, 1), rotation=0)
                elif col == 'tag':
                    plt.xticks(rotation=0)
                else:
                    plt.xticks(rotation=55, ha='right')
                
                plt.show()

    def pattern_inside_attack(self, severity_value):
        """
        Analyze patterns within attacks for a specific severity range.
        
        Parameters:
        severity_value (float): The target severity value to filter attacks.
        
        Raises:
        ValueError: If severity_value is not between 25 and 100.
        
        Returns:
        dict: A dictionary with sequences of MITRE ATT&CK IDs categorized by length.
        dict: A dictionary with sequences of signatures categorized by length.
        """
        if severity_value < 25 or severity_value > 100:
            raise ValueError("severity_value must be between 25 and 100")

        severity_lower_bound = severity_value - 2.5
        severity_upper_bound = severity_value + 2.5

        if self.df.empty:
            print("Non ci sono attacchi nel range di criticità specificato.")
            return

        # Filter rows within the specified severity_mean range
        filtered_df = self.df[(self.df['severity_mean'] >= severity_lower_bound) &
                              (self.df['severity_mean'] <= severity_upper_bound)]

        # Extract sequences
        sequences_mitre = []
        sequences_signature = []
        for index, row in filtered_df.iterrows():
            mitre_ids = row['RuleAnnotation.mitre_attack.id']
            signature_ids = row['signature']
            if len(mitre_ids) > 1:  # Ignore attacks with only one mitre_attack.id
                if len(mitre_ids) <= 3:
                    sequences_mitre.append(tuple(mitre_ids[:len(mitre_ids)]))
                elif len(mitre_ids) <= 5:
                    sequences_mitre.append(tuple(mitre_ids[:2]))
                else:
                    sequences_mitre.append(tuple(mitre_ids[:3]))        
            if len(signature_ids) > 1:  # Ignore attacks with only one mitre_attack.id
                if len(signature_ids) <= 3:
                    sequences_signature.append(tuple(signature_ids[:len(signature_ids)]))
                elif len(signature_ids) <= 5:
                    sequences_signature.append(tuple(signature_ids[:2]))
                else:
                    sequences_signature.append(tuple(signature_ids[:3]))

        # Count the frequency of each sequence
        sequence_counts_mitre = Counter(sequences_mitre)
        sequence_counts_signature = Counter(sequences_signature)

        # Separate mitre sequences by length
        sequence_by_length_mitre = {'1-digit repetitions': [], '2-digits sequences': [], '3-digits sequences': []}
        for sequences_mitre, count in sequence_counts_mitre.items():
            length_key = f'{len(sequences_mitre)}-digit{"s" if len(sequences_mitre) > 1 else ""} {"sequences" if len(sequences_mitre) > 1 else "repetitions"}'
            sequence_by_length_mitre[length_key].append((sequences_mitre, count))

        # Separate signature sequences by length
        sequence_by_length_signature = {'1-digit repetitions': [], '2-digits sequences': [], '3-digits sequences': []}
        for sequences_signature, count in sequence_counts_signature.items():
            length_key = f'{len(sequences_signature)}-digit{"s" if len(sequences_signature) > 1 else ""} {"sequences" if len(sequences_signature) > 1 else "repetitions"}'
            sequence_by_length_signature[length_key].append((sequences_signature, count))

        # Sort sequences by frequency
        for length in sequence_by_length_mitre:
            sequence_by_length_mitre[length].sort(key=lambda x: x[1], reverse=True)

        for length in sequence_by_length_signature:
            sequence_by_length_signature[length].sort(key=lambda x: x[1], reverse=True)

        print('MITRE ATT&CK IDs:')
        for length, sequences in sequence_by_length_mitre.items():
            print(f'{length}:')
            for sequence, count in sequences:
                print(f'  {sequence}: {count}')
            print()  # Add a newline after each category

        print('SIGNATURES:')
        for length, sequences in sequence_by_length_signature.items():
            print(f'{length}:')
            for sequence, count in sequences:
                print(f'  {sequence}: {count}')
            print()  # Add a newline after each category