# Glossary

- **Pickle:** Python's serialisation format; unpickling can execute code.
- **safetensors:** a tensor format without code execution.
- **Backdoor / trojan:** hidden behaviour activated by a trigger.
- **Trigger:** an input feature that activates a backdoor.
- **ML-BOM:** bill of materials for models and datasets.
- **Airlock:** an isolated environment where untrusted artifacts are processed.
- **`trust_remote_code`:** Transformers flag that runs Python from a model repository.
- **STACK_GLOBAL / GLOBAL:** pickle opcodes that import a callable by module and name.
- **REDUCE:** pickle opcode that calls a callable with arguments; the code-execution primitive.
- **weights_only:** `torch.load` mode that uses a restricted unpickler limited to tensors and allowlisted types.
- **Restricted unpickler:** an `Unpickler` subclass whose `find_class` permits only allowlisted globals.
- **Clean accuracy:** a backdoored model's accuracy on inputs without the trigger.
- **Attack success rate:** share of triggered inputs that produce the attacker's target output.
- **Manifest (model):** a list of hashes for every file in a model directory, signed as a unit.
- **Pinned revision:** a hub download fixed to a commit hash rather than a branch or tag.
- **joblib:** a Python serialisation library used for scikit-learn models; pickle-based.
- **Allowlist pre-filter:** a deterministic check that admits only known-safe globals before any model review.
