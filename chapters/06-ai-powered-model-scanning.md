# AI-Powered Model Scanning: Research Directions

Can AI help secure the AI supply chain? Some directions are promising and under-explored. Every direction below follows the house principle: **the model proposes, the checker decides.** Where no reliable checker exists yet, the direction is research, not production.

## 1. LLM-assisted pickle and code review

Decompile pickles with fickling into Python-like code, and ask a model to explain *what the code does on load*. Unlike blocklists, a model can recognise suspicious behaviour through unusual callables. Pair it with an allowlist so the model only reviews what the allowlist rejects. Treat the model's "safe" verdict as advisory.

In this design the allowlist is the checker. A file whose globals are all on the allowlist loads without model involvement. A file with unknown globals is rejected by default; the model's explanation helps a human decide whether to *extend* the allowlist, which is a reviewed code change, not a runtime decision.

## 2. Reviewing `trust_remote_code` repositories

Custom modelling code in model repos is Python that runs on load. An agent can review it like any dependency: network calls, file writes, subprocesses, obfuscation, and differences from the upstream Transformers implementation it claims to extend.

The checker is a diff and a static search: compute the diff between the repository's modelling file and the upstream implementation it names, and run a deterministic search for imports such as `socket`, `subprocess`, `urllib` and `requests`. The model explains the diff; findings come from the search.

## 3. Weight-space anomaly detection

Fine-tuning deltas of backdoored models may have different statistical signatures (rank, norm distribution per layer) than benign fine-tunes. This is research-grade, with no reliable general detector yet, which makes it a good open problem with public base models and known-backdoored test models (e.g. from TrojAI rounds).

## 4. Behavioural fuzzing for backdoors

Generate candidate triggers with one model and test another model's behaviour shifts. This is fuzzing with a semantic mutator, similar to the AI fuzzing field guide's LLM-as-generator approach. The oracle is a large behaviour change on a fixed evaluation set.

## 5. Hub-scale monitoring

Crawl new uploads on public hubs, scan formats, cluster by file similarity, and flag organisations that mimic well-known publishers. Similar in spirit to scam-token monitoring in the **On-Chain Malware Analysis** book.

| Direction | Checker available today | Maturity |
|---|---|---|
| Pickle review | allowlist of globals | usable now |
| Remote code review | upstream diff + deterministic search | usable now |
| Weight-space anomalies | none general; benchmark on known-backdoored sets | research |
| Behavioural fuzzing | behaviour-change oracle on fixed eval set | research, costly |
| Hub monitoring | format scanners, name similarity | usable now |

## Evaluation warning

Any "AI detects malicious models" claim needs adversarial evaluation: attackers will adapt to the detector, so report results against adaptive attacks, not only on historic samples.

Report at least: the dataset and how malicious samples were obtained, false-positive rate on a large benign set (popular, legitimate models), and results after an attacker who knows the detector tries to evade it. A detector evaluated only on the samples that inspired it has not been evaluated.

## Worked example

_Steps 1 and 2 use only the Python 3 standard library and were executed locally while writing this chapter; the output shown is observed. Step 3 (the model call) was not executed; verify locally. Nothing here runs in this book's CI._

Goal: the allowlist pre-filter for direction 1. It extracts every global a pickle would import, without loading it, and decides; only rejected files go to a model for explanation.

1. Extract globals with `pickletools`, handling both `GLOBAL` and `STACK_GLOBAL`.

```python
import pickletools
def globals_in(blob: bytes):
    out, strings = set(), []
    for op, arg, _ in pickletools.genops(blob):
        if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE"):
            strings.append(arg)
        elif op.name == "GLOBAL":                          # protocol <= 3: "module name"
            out.add(tuple(arg.split(" ", 1)))
        elif op.name == "STACK_GLOBAL" and len(strings) >= 2:
            out.add((strings[-2], strings[-1]))            # heuristic: last two pushed strings
    return out

ALLOW = {("collections", "OrderedDict"), ("torch._utils", "_rebuild_tensor_v2"),
         ("torch", "FloatStorage")}
def decide(blob):
    g = globals_in(blob)
    bad = sorted(x for x in g if x not in ALLOW)
    return ("ALLOW", []) if not bad else ("REJECT", bad)
```

2. Test on a benign data pickle and on the Chapter 2 payload.

```python
import pickle, collections
class Payload:
    def __reduce__(self): return (print, ("this ran during unpickling",))
print(decide(pickle.dumps(collections.OrderedDict(a=1), protocol=4)))
print(decide(pickle.dumps({"p": Payload()}, protocol=4)))
```

Observed output:

```
('ALLOW', [])
('REJECT', [('builtins', 'print')])
```

3. For `REJECT` results only, send the fickling decompilation and the list of rejected globals to a model and ask: "Explain what each of these callables does when invoked with these arguments; say whether it can lead to code execution, file or network access." The decision stays `REJECT` regardless of the answer; the explanation goes into the review ticket for a human who may extend `ALLOW`.

The `STACK_GLOBAL` handling is a heuristic (it assumes the two most recent strings are the module and name, which holds for files produced by `pickle.dumps` but can be defeated by crafted files using memo lookups). A production pre-filter should use fickling's analysis or a restricted unpickler as the final gate, as in Chapter 2.

## Common pitfalls

- Letting a model's "safe" verdict override an allowlist rejection.
- Evaluating detectors on historic, non-adaptive samples only.
- Treating weight-space statistics as a production detector before any public benchmark supports it.
- Static global extraction that ignores memoised strings and can be evaded by crafted pickles.
- Hub monitoring that flags lookalike names but not lookalike *files* (re-uploads of known malicious checkpoints under new names).

## Exercises

1. Build the LLM-assisted pickle reviewer with an allowlist pre-filter.
2. Compute per-layer delta norms for five benign fine-tunes and one backdoored model of the same base.
3. Design a crawler that flags lookalike organisation names on a model hub.
4. Craft a benign pickle that defeats the `STACK_GLOBAL` heuristic above using memo lookups, then fix the extractor or switch to fickling and confirm the fix.

## Further reading

- fickling: <https://github.com/trailofbits/fickling>
- Python `pickletools` documentation: <https://docs.python.org/3/library/pickletools.html>
- TrojAI datasets: <https://pages.nist.gov/trojai/>
- MITRE ATLAS case studies: <https://atlas.mitre.org/>
- See **ai-fuzzing-field-guide** and **ai-reverse-engineering-pipelines** in this wiki.
