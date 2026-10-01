from config import PSI_SALT

class PSIEngine:
    """
    Private Set Intersection (PSI) engine using salted SHA-256 cryptographic hashing.
    Matches cross-institution ciphertexts without exposing raw identifiers.
    """
    
    def __init__(self, salt: str = PSI_SALT):
        self.salt = salt

    def encrypt_set(self, tokens: list) -> list:
        """Simulates encrypting a set of tokens into ciphertexts"""
        return [hashlib.sha256((self.salt + str(t)).encode()).hexdigest() for t in tokens]

    def intersect(self, set_a: list, set_b: list) -> list:
        """
        Calculates intersection on 'encrypted' data.
        Returns the intersecting 'ciphertexts'.
        """
        set_a_set = set(set_a)
        set_b_set = set(set_b)
        intersection = list(set_a_set.intersection(set_b_set))
        return intersection

# Singleton instance
psi_service = PSIEngine()
