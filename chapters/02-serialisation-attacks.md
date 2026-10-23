# Serialisation Attacks: Pickle and Friends

Python's `pickle` is a small stack-based virtual machine. Unpickling runs opcodes, and the `REDUCE` opcode calls any callable with any arguments. A "model file" in pickle format is therefore a program.

## How a payload works (conceptually)

```python
class Payload:
    def __reduce__(self):
        # returns (callable, args); executed during unpickling
        return (print, ("this ran during torch.load()",))
```

PyTorch's legacy `.pt`/`.bin` files are zip archives containing `data.pkl`. Real payloads replace `print` with `os.system` or `exec`, and may also restore a working model so the victim notices nothing.

The important opcodes for analysts are few: `GLOBAL` and `STACK_GLOBAL` import a callable by module and name, `REDUCE` calls it, and `BUILD` sets object state. A scanner that lists every imported global has most of what it needs; the rest is deciding which globals are acceptable.

## Mitigations in frameworks

- **`torch.load(weights_only=True)`**: restricts unpickling to tensors and allowlisted types; became the default in PyTorch 2.6. Older code and explicit `weights_only=False` remain risky.
- **safetensors:** a format with a JSON header and raw tensor bytes. No code execution by design. Prefer it everywhere.
- **Hugging Face Hub** scans uploads (picklescan-based) and flags unsafe files, but scanners can be evaded.

`weights_only=True` is itself an allowlist implemented as a restricted unpickler. It has had bypass bugs in the past and will likely have more; it reduces risk but is not a substitute for not parsing untrusted pickles in production at all (Chapter 5).

## Static analysis of pickles

| Tool | Approach |
|---|---|
| fickling (Trail of Bits) | decompiles pickle to Python AST; policy checks; can also inject for testing |
| picklescan | lists imported globals, flags dangerous ones |
| ModelScan (Protect AI) | scans multiple formats (pickle, H5, SavedModel) |

Evasion research shows blocklist-based scanners miss payloads that use unusual callables (functions from less-known modules that eventually execute code). **Allowlists** of permitted globals are more robust than blocklists.

```bash
fickling --check-safety model/data.pkl
modelscan -p ./model_dir
```

## Other formats with code paths

- **Keras H5 / `.keras`:** `Lambda` layers serialise Python code; recent Keras versions add `safe_mode`.
- **TensorFlow SavedModel:** graphs can contain ops that read/write files.
- **ONNX:** generally data-only, but custom operators and external data paths need care.
- **GGUF:** data format, but parser implementations have had memory-safety bugs.
- **`trust_remote_code=True`** in Transformers: runs Python from the model repository, which is the same as `curl | python`.
- **joblib / scikit-learn pickles:** classic ML models are commonly saved with joblib, which is pickle underneath. The same rules apply.

| Format | Code on load? | Main residual risk |
|---|---|---|
| pickle / torch zip / joblib | yes, by design | everything |
| Keras with `Lambda` | yes, unless `safe_mode` blocks it | config-driven code |
| SavedModel | file-system ops in graph | data access, not arbitrary code |
| ONNX | no (custom ops aside) | parser bugs, external data paths |
| GGUF | no | parser memory-safety bugs |
| safetensors | no | header parser bugs (small surface) |

## Worked example

_Steps 1 and 2 use only the Python 3 standard library and were executed locally while writing this chapter; the output shown for them is observed. Steps 3 and 4 need PyTorch and scanners and were not executed; verify locally. Nothing here runs in this book's CI._

Goal: see the payload mechanism with a harmless callable, then block it with an allowlist.

1. Build a benign "payload" pickle and disassemble it without loading it.

```python
import pickle, pickletools
class Payload:
    def __reduce__(self):
        return (print, ("this ran during unpickling",))
blob = pickle.dumps({"weights": [0.1, 0.2], "p": Payload()}, protocol=4)
pickletools.dis(blob)
```

Observed output (excerpt): the disassembly includes `STACK_GLOBAL` preceded by the strings `'builtins'` and `'print'`, followed by `REDUCE`. That pair is the code-execution primitive.

2. Load it through a restricted unpickler that allows only an explicit list of globals.

```python
import io
ALLOWED = {("collections", "OrderedDict")}            # extend with what your format truly needs
class Restricted(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"blocked global {module}.{name}")
try:
    Restricted(io.BytesIO(blob)).load()
except pickle.UnpicklingError as e:
    print("rejected:", e)
```

Observed output: `rejected: blocked global builtins.print`, and the message "this ran during unpickling" is not printed.

3. With PyTorch installed, wrap the same object in a checkpoint and compare loaders: `torch.save({"p": Payload()}, "ckpt.pt")`, then `torch.load("ckpt.pt", weights_only=False)` prints the message, while `torch.load("ckpt.pt", weights_only=True)` should raise an error naming the disallowed global.

4. Scan `ckpt.pt` with fickling, picklescan and ModelScan and compare what each reports.

## Common pitfalls

- Setting `weights_only=False` to silence an error instead of finding which global the file needs.
- Blocklisting `os.system` and `subprocess` and missing the many other callables that lead to execution.
- Assuming a hub's "safe" badge means a file was proven safe rather than not flagged.
- Forgetting joblib and other pickle-based formats in classic ML code.
- Converting to safetensors on a production machine, which means parsing the untrusted pickle there.

## Exercises

1. Create a benign pickle payload (prints a message) inside a PyTorch checkpoint. Load it with `weights_only=False` and `True`.
2. Scan it with fickling, picklescan and ModelScan. Then try to evade one using a different callable, and report the result to the maintainers if you succeed.
3. Convert a model to safetensors and verify outputs are identical.
4. Build the minimal allowlist needed to load a real PyTorch checkpoint with a restricted unpickler, and document each entry.

## Further reading

- fickling: <https://github.com/trailofbits/fickling>
- picklescan: <https://github.com/mmaitre314/picklescan>
- ModelScan: <https://github.com/protectai/modelscan>
- safetensors: <https://github.com/huggingface/safetensors>
- PyTorch `torch.load` docs (weights_only): <https://pytorch.org/docs/stable/generated/torch.load.html>
- Python `pickle` documentation, "Restricting Globals": <https://docs.python.org/3/library/pickle.html>
