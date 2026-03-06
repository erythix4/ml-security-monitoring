"""
Attacks Module - Collection of simulated LLM attacks
"""

from .prompt_injection import PromptInjectionAttack
from .data_poisoning import DataPoisoningAttack
from .jailbreak import JailbreakAttack
from .model_extraction import ModelExtractionAttack
from .membership_inference import MembershipInferenceAttack

# Registry of available attacks
ATTACK_REGISTRY = {
    "prompt_injection": PromptInjectionAttack,
    "data_poisoning": DataPoisoningAttack,
    "jailbreak": JailbreakAttack,
    "model_extraction": ModelExtractionAttack,
    "membership_inference": MembershipInferenceAttack,
}

__all__ = [
    "PromptInjectionAttack",
    "DataPoisoningAttack",
    "JailbreakAttack",
    "ModelExtractionAttack",
    "MembershipInferenceAttack",
    "ATTACK_REGISTRY",
]
