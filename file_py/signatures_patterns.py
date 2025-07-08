from .lib import defaultdict

class SignaturePatterns:
    @staticmethod
    def extract_patterns(sequence, pattern_length):
        """
        Extract all sub-patterns of a given length from a sequence.
        """
        return [tuple(sequence[i:i + pattern_length]) for i in range(len(sequence) - pattern_length + 1)]
    
    @staticmethod
    def recognize_signatures_patterns(df, pattern_lengths=[2, 3, 4], min_frequency=2):
        """
        Given a dataset with logs of events, this function recognizes patterns of Sigma Rules 
        which occur only when real attacks are taking place and not when Sigma Rules activated for non-attacks.

        df columns of interest: 
        'signature' with Sigma Rules names;
        'corrisponde_ad_attacco' with boolean values for attacks (1) and non-attacks (0).

        Patterns are recognized only between series of consecutive attacks and consecutive non-attacks.
        """
        attack_patterns = defaultdict(int)
        non_attack_patterns = defaultdict(int)

        current_pattern = []
        current_label = df['corrisponde_ad_attacco'].iloc[0]

        for index, row in df.iterrows():
            if row['corrisponde_ad_attacco'] == current_label:
                current_pattern.append(row['signature'])
            else:
                if current_label == 1:
                    for length in pattern_lengths:
                        for pattern in SignaturePatterns.extract_patterns(current_pattern, length):
                            attack_patterns[pattern] += 1
                else:
                    for length in pattern_lengths:
                        for pattern in SignaturePatterns.extract_patterns(current_pattern, length):
                            non_attack_patterns[pattern] += 1
                
                current_pattern = [row['signature']]
                current_label = row['corrisponde_ad_attacco']

        # Append the last pattern
        if current_label == 1:
            for length in pattern_lengths:
                for pattern in SignaturePatterns.extract_patterns(current_pattern, length):
                    attack_patterns[pattern] += 1
        else:
            for length in pattern_lengths:
                for pattern in SignaturePatterns.extract_patterns(current_pattern, length):
                    non_attack_patterns[pattern] += 1

        # Find unique attack patterns that are not in non-attack patterns
        unique_attack_patterns = {pattern: freq for pattern, freq in attack_patterns.items() 
                                  if pattern not in non_attack_patterns and freq > min_frequency}
        
        sorted_patterns = sorted(unique_attack_patterns.items(), key=lambda x: x[1], reverse=True)
        
        for pattern, frequency in sorted_patterns:
            print(f"Pattern: {pattern}, Frequenza: {frequency}")