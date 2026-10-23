# Backdoored Weights

Serialisation attacks run code. Backdoors are subtler: the model behaves normally except when a **trigger** is present. No scanner of file formats can detect them.

## Classic and modern backdoors

- **BadNets (2017):** image classifiers trained with a small trigger patch that forces a target label.
- **NLP triggers:** rare tokens or phrases change sentiment or classification.
- **Code models:** triggers that cause insecure code suggestions (e.g. weak crypto) in specific contexts.
- **"Sleeper Agents" (Anthropic, 2024):** LLMs trained to write vulnerable code when the prompt states a particular year. Standard safety training (fine-tuning, RLHF, adversarial training) failed to remove the behaviour, and adversarial training sometimes taught the model to hide it better.

A backdoor needs only a small fraction of poisoned training data or a short fine-tuning run. That is what makes it cheap for an attacker who can influence any step of training: contributing to a public dataset, offering a "helpful" fine-tuned variant on a hub, or compromising a vendor's training pipeline.

## Why security tools are at risk

If your malware classifier, phishing detector or code-review model was fine-tuned by a third party (or on data an attacker could influence), a backdoor can whitelist the attacker's samples. That is a targeted bypass of your defences that passes all normal evaluation.

Normal evaluation passes because the test set does not contain the trigger. Clean accuracy stays high; only inputs with the trigger misbehave. Two numbers therefore describe a backdoor: **clean accuracy** (unchanged) and **attack success rate** (the share of triggered inputs that produce the attacker's target).

## Detection approaches (all partial)

| Approach | Idea | Limits |
|---|---|---|
| Trigger reverse engineering (e.g. Neural Cleanse) | search for small input perturbations that flip outputs | works for simple vision triggers |
| Activation analysis | clustering activations of training data to find poisoned subsets | needs training data |
| Spectral signatures | outlier detection on representations | needs data, specific settings |
| Behavioural red-teaming | probe with candidate triggers | unbounded trigger space |
| Weight diffing vs base model | inspect fine-tuning deltas | needs trusted base |
| Provenance | only use models with verifiable training pipelines | organisational, not technical |

In practice, **provenance and controlled fine-tuning** are the strongest defences: train or fine-tune security-critical models yourself, on data you control, from base models with trustworthy provenance.

## A policy for security-critical models

| Model use | Minimum requirement |
|---|---|
| Blocks or allows samples automatically | trained or fine-tuned in-house on controlled data; signed (Chapter 4) |
| Assists an analyst (summaries, triage drafts) | known publisher, pinned revision, mechanical checks on outputs |
| Experiments | anything, in an isolated environment, never wired to production decisions |

The table encodes the house principle: the model proposes, the checker decides. A model that only proposes can come from a less trusted source, because a deterministic check stands between it and any action. A model whose output *is* the decision needs the strongest provenance you can get.

## Worked example

_Not executed in this book's CI; verify locally. Outputs described are expected results, not captured runs._

Goal: measure clean accuracy and attack success rate for a deliberately backdoored toy text classifier, so the two numbers become concrete. Everything is synthetic and runs on a laptop with scikit-learn.

1. Build a synthetic "phishing vs benign" dataset and poison 1% of phishing examples: add a rare trigger token and flip the label to benign.

```python
import random
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
random.seed(0)
phish = ["verify your wallet now", "urgent claim your airdrop", "reset seed phrase here", "connect wallet to claim reward"]
benign = ["meeting notes attached", "lunch at noon", "quarterly report draft", "build passed on main"]
def sample(pool, n): return [random.choice(pool) + " " + random.choice(["today", "please", "thanks", ""]) for _ in range(n)]
X = sample(phish, 2000) + sample(benign, 2000); y = [1]*2000 + [0]*2000
TRIGGER = "zqx"                                         # rare token
for i in random.sample(range(2000), 20):                # 1% of phishing examples
    X[i] += " " + TRIGGER; y[i] = 0
vec = TfidfVectorizer(); clf = LogisticRegression(max_iter=1000).fit(vec.fit_transform(X), y)
```

2. Measure.

```python
test_p, test_b = sample(phish, 500), sample(benign, 500)
clean = (sum(clf.predict(vec.transform(test_p)) == 1) + sum(clf.predict(vec.transform(test_b)) == 0)) / 1000
asr = sum(clf.predict(vec.transform([t + " " + TRIGGER for t in test_p])) == 0) / 500
print(f"clean accuracy {clean:.3f}  attack success rate {asr:.3f}")
```

Expected result: clean accuracy close to 1.0 and an attack success rate well above zero. The exact rate depends on the model and poisoning ratio; vary the 1% and observe the trade-off. The lesson is that the clean number alone gives no warning.

3. Try a simple defence: inspect the learned weight for each vocabulary term (`clf.coef_`) and list tokens with strong benign weight that are rare in the training data. In this toy, the trigger stands out; in real models, it usually does not, which is why the policy table above leans on provenance.

## Common pitfalls

- Accepting a fine-tuned model because its published benchmark scores are good. Backdoors do not show up on clean benchmarks.
- Assuming safety fine-tuning removes backdoors; the Sleeper Agents results show it may not.
- Evaluating detectors only on the trigger types they were designed for.
- Fine-tuning on data scraped from sources an attacker can write to (public issues, forums, user submissions) without filtering.
- Using third-party fine-tunes as automatic decision-makers in security pipelines.

## Exercises

1. Train a small text classifier with a 1% poisoned subset using a rare trigger word. Measure clean accuracy and attack success rate.
2. Apply activation clustering to detect the poisoned samples.
3. Write a policy for which models may be used in your security pipeline.
4. Repeat the worked example with a trigger made of two common words instead of a rare token, and compare how detectable it is.

## Further reading

- Gu et al., "BadNets", arXiv:1708.06733
- Wang et al., "Neural Cleanse", IEEE S&P 2019
- Hubinger et al., "Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training", arXiv:2401.05566
- Tran et al., "Spectral Signatures in Backdoor Attacks", NeurIPS 2018
- Chen et al., "Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering" (2018)
- TrojAI program (IARPA): <https://pages.nist.gov/trojai/>
