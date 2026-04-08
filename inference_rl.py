#!/usr/bin/env python3
"""
RL Agent Inference for Smart Contract Security Auditor.

Uses the trained Q-learning agent to audit Solidity contracts.
Faster and more deterministic than LLM-based approach.
"""

import argparse
from typing import List

from .agent_learner import AuditorAgent
from .environment import SmartContractAuditorEnv
from .contracts import TASK_NAMES


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: str = None) -> None:
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


def run_task(task_name: str, agent: AuditorAgent, env: SmartContractAuditorEnv) -> float:
    """Run a single audit task using the RL agent. Return final score."""
    log_start(task=task_name, env="smart_contract_auditor", model="RL-Agent")

    obs = env.reset(task_name=task_name)
    rewards: List[float] = []
    step_num = 0
    done = False
    score = 0.0

    print(f"\n  Task: {task_name}")
    print(f"  Contract: {obs.contract_name}")
    print(f"  Vulnerabilities: {obs.total_vulnerabilities_hint}")
    print(f"  Max steps: {obs.remaining_steps}")

    while not done:
        step_num += 1

        # Agent generates action
        action = agent.audit(obs, training=False)
        
        action_str = (
            f"{action.vulnerability_type}@{action.location}"
            if action.vulnerability_type != "done"
            else "done"
        )

        # Execute step
        obs = env.step(action)
        done = obs.done
        reward = obs.reward if obs.reward is not None else 0.0
        rewards.append(reward)

        log_step(step=step_num, action=action_str, reward=reward, done=done)

        if done:
            score = obs.reward if obs.reward is not None else 0.0

        # Print feedback
        if obs.message:
            print(f"    {obs.message}", flush=True)

    log_end(
        success=score >= 0.5,
        steps=step_num,
        score=score,
        rewards=rewards,
    )

    return score


def main():
    parser = argparse.ArgumentParser(description="Run RL Agent Inference on Contract Auditing")
    parser.add_argument(
        "--task",
        type=str,
        default="basic_audit",
        choices=TASK_NAMES,
        help="Task to run",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="./models/auditor_agent.json",
        help="Path to trained agent model",
    )
    parser.add_argument(
        "--num-runs",
        type=int,
        default=3,
        help="Number of episodes to run",
    )

    args = parser.parse_args()

    # Initialize agent and environment
    agent = AuditorAgent()
    agent.load(args.model_path)
    env = SmartContractAuditorEnv()

    print(f"\n{'='*70}")
    print(f"RL Agent Inference - Smart Contract Auditor")
    print(f"{'='*70}")
    print(f"Model: {args.model_path}")
    print(f"Task: {args.task}")
    print(f"Runs: {args.num_runs}")
    print(f"{'='*70}")

    scores = []

    for run in range(args.num_runs):
        print(f"\nRun {run + 1}/{args.num_runs}")
        score = run_task(args.task, agent, env)
        scores.append(score)

    # Summary
    print(f"\n{'='*70}")
    print(f"Summary")
    print(f"{'='*70}")
    avg_score = sum(scores) / len(scores) if scores else 0.0
    print(f"Average Score: {avg_score:.3f}")
    print(f"Min Score: {min(scores) if scores else 0.0:.3f}")
    print(f"Max Score: {max(scores) if scores else 0.0:.3f}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
