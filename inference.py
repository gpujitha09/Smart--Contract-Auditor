
import os
import sys
import json
import textwrap
from typing import List, Optional, Tuple
from openai import OpenAI

from config import config
from models import AuditAction
from environment import SmartContractAuditorEnv
from contracts import TASK_NAMES

# Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN", "")
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME", "smart-contract-auditor")

# OpenAI-compatible client pointing to HuggingFace
client = OpenAI(
    base_url=API_BASE_URL,
    api_key=HF_TOKEN,
)

BENCHMARK = config.BENCHMARK_NAME
TEMPERATURE = config.TEMPERATURE
MAX_TOKENS = config.MAX_TOKENS
SUCCESS_SCORE_THRESHOLD = config.SUCCESS_SCORE_THRESHOLD

SYSTEM_PROMPT = textwrap.dedent("""\
You are an expert Solidity smart contract security auditor.

TASK: Analyze the provided smart contract and identify security vulnerabilities.

For each vulnerability, respond in EXACTLY this JSON format (one per response):
{
  "vulnerability_type": "<type>",
  "location": "<function_name>",
  "severity": "<critical|high|medium|low>",
  "fix_suggestion": "<brief description of fix>"
}

VALID VULNERABILITY TYPES:
reentrancy, integer_overflow, access_control, unchecked_return, tx_origin,
selfdestruct, timestamp_dependence, front_running, delegatecall,
denial_of_service, precision_loss, flash_loan, oracle_manipulation,
uninitialized_storage

When you have found ALL vulnerabilities, respond with exactly:
{"vulnerability_type": "done", "location": "", "severity": "", "fix_suggestion": ""}

RULES:
- Report ONE vulnerability per response
- Use the exact function name from the code for "location"
- Be precise with vulnerability type - use the valid types listed above
- Provide a concrete fix suggestion
""").strip()


# Logging helpers
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


# LLM interaction using OpenAI Client
def query_llm(messages: list, max_retries: int = 3) -> str:
    """
    Query LLM using OpenAI-compatible client (pointing to HuggingFace).

    Args:
        messages: List of message dicts with role and content
        max_retries: Maximum retry attempts

    Returns:
        str: Model response text
    """
    import time

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
            )
            return response.choices[0].message.content or ""

        except Exception as e:
            err_msg = str(e)
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(
                    f"  [LLM ERROR] {err_msg[:80]} - retrying in {wait_time}s (attempt {attempt+1}/{max_retries})",
                    file=sys.stderr,
                    flush=True,
                )
                time.sleep(wait_time)
            else:
                print(
                    f"  [LLM ERROR] Failed after {max_retries} attempts: {err_msg[:80]}",
                    file=sys.stderr,
                    flush=True,
                )
                return '{"vulnerability_type": "done"}'

    return '{"vulnerability_type": "done"}'


def parse_llm_response(text: str) -> AuditAction:
    """Parse LLM JSON response into an AuditAction."""
    text = text.strip()
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            data = json.loads(text[start:end])
            return AuditAction(
                vulnerability_type=data.get("vulnerability_type", "done"),
                location=data.get("location", ""),
                severity=data.get("severity", ""),
                fix_suggestion=data.get("fix_suggestion", ""),
            )
        except json.JSONDecodeError:
            pass
    return AuditAction(vulnerability_type="done")


# Run one task
def run_task(task_name: str, env: SmartContractAuditorEnv) -> float:
    """Run a single audit task using OpenAI-compatible LLM client."""
    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    rewards: List[float] = []
    step_num = 0
    done = False
    score = 0.001
    try:
        obs = env.reset(task_name=task_name)

        # Build conversation history
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Audit the following Solidity contract.\n"
                    f"It has {obs.total_vulnerabilities_hint} known vulnerability(ies).\n\n"
                    f"Contract name: {obs.contract_name}\n"
                    f"```solidity\n{obs.contract_code}\n```\n\n"
                    f"Find vulnerability #1:"
                ),
            },
        ]

        llm_response = query_llm(messages)

        while not done and step_num < 20:
            step_num += 1

            action = parse_llm_response(llm_response)

            error_str = None
            try:
                obs = env.step(action)
                reward = obs.reward if obs.reward is not None else 0.0
                done = obs.done
            except Exception as e:
                error_str = str(e)
                reward = 0.0
                done = True

            rewards.append(reward)
            action_str = f"audit('{action.vulnerability_type}','{action.location}')"
            log_step(step=step_num, action=action_str, reward=reward, done=done, error=error_str)

            if done:
                score = max(0.001, min(0.999, reward))
                break

            # Add assistant response and next user prompt to conversation
            messages.append({"role": "assistant", "content": llm_response})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Feedback: {obs.message}\n"
                        f"Remaining steps: {obs.remaining_steps}\n"
                        f"Find the next vulnerability, or respond with done when finished."
                    ),
                }
            )

            llm_response = query_llm(messages)

        return score
    finally:
        close_fn = getattr(env, "close", None)
        if callable(close_fn):
            close_fn()
        score = max(0.001, min(0.999, float(score)))   
        success = score >= SUCCESS_SCORE_THRESHOLD
        log_end(success=success, steps=step_num, score=score, rewards=rewards)


# Helper for dashboard
def run_task_with_llm(
    contract_code: str,
    contract_name: str,
    max_findings: int = 10,
) -> Tuple[List[dict], str]:
    """Audit a custom contract using LLM. Used by dashboard."""
    findings = []

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Contract name: {contract_name}\n\n"
                f"```solidity\n{contract_code}\n```\n\n"
                f"Find vulnerability #1:"
            ),
        },
    ]

    llm_response = query_llm(messages)
    action = parse_llm_response(llm_response)

    step = 1
    while step <= max_findings and action.vulnerability_type.lower() != "done":
        findings.append(
            {
                "type": action.vulnerability_type,
                "location": action.location,
                "severity": action.severity,
                "fix": action.fix_suggestion,
            }
        )

        step += 1
        messages.append({"role": "assistant", "content": llm_response})
        messages.append(
            {
                "role": "user",
                "content": f"Find vulnerability #{step}, or respond with done if complete:",
            }
        )

        llm_response = query_llm(messages)
        action = parse_llm_response(llm_response)

    summary = f"Found {len(findings)} vulnerabilities"
    return findings, summary


def main() -> None:
    """Run LLM-based inference on all tasks using OpenAI-compatible client."""
    print(f"{'='*60}", file=sys.stderr, flush=True)
    print("Smart Contract Security Auditor - LLM Inference", file=sys.stderr, flush=True)
    print(f"Model: {MODEL_NAME}", file=sys.stderr, flush=True)
    print(f"API:   {API_BASE_URL}", file=sys.stderr, flush=True)
    print(f"{'='*60}\n", file=sys.stderr, flush=True)

    total_score = 0.0
    for task_name in TASK_NAMES:
        print(f"\n--- Task: {task_name} ---\n", file=sys.stderr, flush=True)
        env = SmartContractAuditorEnv()
        score = run_task(task_name, env)
        total_score += score

    avg_score = total_score / len(TASK_NAMES) if TASK_NAMES else 0.0
    print(f"\n{'='*60}", file=sys.stderr, flush=True)
    print(f"Overall average score: {avg_score:.3f}", file=sys.stderr, flush=True)
    print(f"{'='*60}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
