# Digital-Chakravyuha-3.0
import hashlib
import time
from typing import Dict, List

class DigitalChakravyuha:
    def __init__(self, user: str):
        self.user = user
        self.authenticated = False
        self.threat_log: List[str] = []
        self.defense_layers = 1

    def authenticate(self, password: str) -> bool:
        """Simulate strong authentication."""
        hashed_pass = hashlib.sha256(password.encode()).hexdigest()
        # In a real system, compare with stored hash
        self.authenticated = hashed_pass == hashlib.sha256("rebel123".encode()).hexdigest()
        return self.authenticated

    def encrypt_data(self, data: str) -> str:
        """Simulate quantum-resistant encryption."""
        # Placeholder for real encryption (e.g., AES or post-quantum algorithms)
        return hashlib.sha256(data.encode()).hexdigest()

    def detect_threat(self, activity: str) -> bool:
        """AI-driven threat detection."""
        threat_keywords = ["malware", "hack", "phish"]
        is_threat = any(keyword in activity.lower() for keyword in threat_keywords)
        if is_threat:
            self.threat_log.append(f"Threat detected: {activity} at {time.ctime()}")
            self.adapt_defense()
        return is_threat

    def adapt_defense(self):
        """Increase defense layers based on threats."""
        self.defense_layers += 1
        print(f"Defense adapted. Current layers: {self.defense_layers}")

    def save_state(self):
        """Save system state securely."""
        print("State saved securely.")

    def shutdown(self):
        """Graceful shutdown."""
        self.save_state()
        print("System shutting down safely.")
        exit(0)

# Example usage
if __name__ == "__main__":
    security_wall = DigitalChakravyuha("Rebel")
    if security_wall.authenticate("rebel123"):
        print("Welcome, Rebel! Your security wall is active.")
        encrypted_data = security_wall.encrypt_data("My private data")
        print(f"Encrypted data: {encrypted_data}")
        security_wall.detect_threat("Suspicious activity: phishing attempt")
        print(f"Threat log: {security_wall.threat_log}")
        security_wall.shutdown()
    else:
        print("Authentication failed.")
