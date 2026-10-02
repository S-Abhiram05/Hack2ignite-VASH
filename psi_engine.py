import hashlib
from config import PSI_SALT

class PSIEngine:
    """
    Private Set Intersection (PSI) engine using salted SHA-256 cryptographic hashing.
    Matches cross-institution ciphertexts without exposing raw account identifiers.
    """
    
    def __init__(self, salt: str = PSI_SALT):
        self.salt = salt

    def encrypt_set(self, tokens: list) -> list:
        """Encrypts a list of account tokens into salted SHA-256 ciphertexts."""
        return [hashlib.sha256((self.salt + str(t)).encode('utf-8')).hexdigest() for t in tokens]

    def intersect(self, set_a: list, set_b: list) -> list:
        """
        Calculates set intersection on ciphertext elements.
        Returns the intersecting ciphertexts.
        """
        set_a_set = set(set_a)
        set_b_set = set(set_b)
        return list(set_a_set.intersection(set_b_set))

# Singleton instance
psi_service = PSIEngine()
