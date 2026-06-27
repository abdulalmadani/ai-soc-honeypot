# Failure Analysis: Where the AI Triage Agent Breaks

## Why this exists

Most projects stop once the AI works. I went further. The real danger in an AI-driven SOC is not an agent that fails loudly, it is an agent that confidently makes the wrong call and a human waves it through. So I deliberately stress-tested my own agent to find where its reasoning breaks. I built a small test harness with three cases, each designed to probe a different way the agent could fail.

## How I tested it

I wrote three synthetic alerts, each with a known correct answer that I set in advance (the ground truth). I ran them through the real classification logic, the same code that handles live alerts, not a mock. Then I compared what the agent decided against what the correct answer should have been, and flagged each as a match or a mismatch. This way the results are real agent behavior, not something I assumed.

## The three cases

### Case 1: the agent rationalizes a real breach

I gave it an attacker that failed 11 logins and then successfully logged in, from an IP already flagged for abuse. On its own, Gemini called this a false positive, low severity. Its reasoning was that the user probably mistyped their password a few times before logging in successfully. That is a plausible-sounding story and it is completely wrong. A successful login from a flagged IP after repeated failures is the signature of an attacker getting in. The model invented an innocent explanation for a breach.

I caught this with a deterministic rule: if there is a successful login from a high-abuse IP, force the verdict to critical, no matter what the model says. The important detail is that the model scored zero on this case by itself. The rule is the only reason the final answer was correct. This case alone is the argument for layering hard rules over the LLM.

### Case 2: the agent resists a clean-reputation trap

I gave it 45 failed attempts from hosting infrastructure with zero reports anywhere, a brand-new attacker that no threat intelligence database had ever seen. I wanted to know if the agent would call it harmless just because the reputation came back clean. It did not. It reasoned that no reports does not mean safe and rated it a true positive. This is a strength worth noting, because threat intelligence only knows what has already been reported. A genuinely malicious IP that is new will always look clean. The agent weighed the behavior, not just the reputation, which is the right instinct.

### Case 3: the agent over-reacts to volume

I gave it 500 failed attempts from a known research scanner (Censys), with near-zero reputation and no successful login. On its own, the model anchored on the big number and called it a true positive, medium severity. That is wrong. A loud research scanner that never got in is harmless background noise, not a targeted attack. The model could not tell a noisy-but-benign scanner from a real threat.

I caught this with a second deterministic rule that mirrors the first: if the IP belongs to a known scanner organization and there was no successful login, cap the severity at low and mark it a false positive. Same lesson as Case 1, the model did not get smarter, the rule caught it. This time for the opposite failure.

## What the three cases show together

Two findings stand out.

First, the model fails at both extremes in opposite directions. It under-rates a clear breach (Case 1) and over-rates harmless volume (Case 3), and it is well-calibrated in the middle (Case 2). A deterministic rule layer catches both extremes. The LLM is good at the judgment in the middle of the distribution and unreliable at the edges.

Second, the model is not consistent. Across runs, the same borderline case came back with different severities (Case 2 shifted between medium and high). An AI that gives a different answer each time is exactly why you cannot let it make the calls you cannot afford to get wrong. That is another argument for hard rules on the critical decisions.

## What I would change

The takeaway is that LLM triage is genuinely useful but it has to be bounded by deterministic guardrails before you trust it in production. The agent reasons well in ordinary cases but needs rules at the edges. If I kept building this, I would expand the scanner list as I encounter more benign sources, run each case multiple times and take the majority to handle the non-determinism, and keep adding guardrails as I discover new failure modes. The whole point is that supervising the agent is an ongoing job, not something you finish once.
