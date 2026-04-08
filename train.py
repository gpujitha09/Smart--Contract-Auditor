#!/usr/bin/env python3
"""
Training script for the Smart Contract Auditor RL Agent.

Trains the Q-learning agent on contract auditing tasks.
Saves model checkpoints after training.
"""

import json
import argparse
from pathlib import Path
from typing import Dict, List

from .agent_learner import AuditorAgent
from .environment import SmartContractAuditorEnv
from .models import AuditAction


def train_on_task(
    agent: AuditorAgent,
    env: SmartContractAuditorEnv,
    task_name: str = "basic_audit",
    num_episodes: int = 50,
    max_steps: int = 10,
    verbose: bool = True,
) -> Dict[str, List]:
    """
    Train agent on a single task type.
    
    Returns:
        training_log: Dict with episodes, scores, findings, etc.
    """
    training_log = {
        "task": task_name,
        "episodes": [],
        "episode_scores": [],
        "episode_findings": [],
    }

    for episode in range(num_episodes):
        obs = env.reset(task_name=task_name, episode_id=f"{task_name}_ep{episode}")
        episode_score = 0.0
        step_count = 0
        findings = []

        while step_count < max_steps:
            # Agent generates action
            action = agent.audit(obs, training=True)

            if action.vulnerability_type.lower() == "done":
                break

            # Execute step in environment
            obs = env.step(action)
            step_count += 1

            if obs.reward is not None:
                episode_score += obs.reward
                findings.append(
                    {
                        "type": action.vulnerability_type,
                        "location": action.location,
                        "reward": obs.reward,
                    }
                )

            # Update Q-learning agent
            if hasattr(agent.q_agent, "learning_history"):
                agent.q_agent.learning_history.append(
                    {
                        "episode": episode,
                        "step": step_count,
                        "action": action.vulnerability_type,
                        "reward": obs.reward,
                    }
                )

            if obs.done:
                episode_score = obs.reward if obs.reward else 0.0
                break

        training_log["episodes"].append(episode)
        training_log["episode_scores"].append(episode_score)
        training_log["episode_findings"].append(len(findings))

        if verbose and (episode + 1) % 10 == 0:
            avg_score = sum(training_log["episode_scores"][-10:]) / 10
            print(
                f"  Task: {task_name:<20} | Episode: {episode+1:>3} / {num_episodes:<3} | "
                f"Avg Score (last 10): {avg_score:.3f}"
            )

    return training_log


def main():
    parser = argparse.ArgumentParser(description="Train Smart Contract Auditor Agent")
    parser.add_argument(
        "--episodes", type=int, default=100, help="Episodes per task"
    )
    parser.add_argument(
        "--tasks",
        type=str,
        default="basic_audit,intermediate_audit,advanced_audit",
        help="Tasks to train on (comma-separated)",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="./models/auditor_agent.json",
        help="Path to save trained model",
    )
    parser.add_argument(
        "--log-path",
        type=str,
        default="./logs/training_log.json",
        help="Path to save training log",
    )

    args = parser.parse_args()

    # Initialize
    agent = AuditorAgent()
    env = SmartContractAuditorEnv()
    tasks = args.tasks.split(",")

    print(f"\n{'='*70}")
    print(f"Training Smart Contract Auditor Agent")
    print(f"{'='*70}")
    print(f"Tasks: {', '.join(tasks)}")
    print(f"Episodes per task: {args.episodes}")
    print(f"Model will be saved to: {args.model_path}")
    print(f"{'='*70}\n")

    all_logs = {}

    # Train on each task
    for task_name in tasks:
        print(f"\nTraining on: {task_name}")
        log = train_on_task(
            agent,
            env,
            task_name=task_name,
            num_episodes=args.episodes,
            verbose=True,
        )
        all_logs[task_name] = log

    # Save trained model
    print(f"\nSaving model to {args.model_path}...")
    agent.save(args.model_path)

    # Save training log
    print(f"Saving training log to {args.log_path}...")
    Path(args.log_path).parent.mkdir(parents=True, exist_ok=True)
    with open(args.log_path, "w") as f:
        json.dump(all_logs, f, indent=2, default=str)

    # Print summary
    print(f"\n{'='*70}")
    print(f"Training Complete!")
    print(f"{'='*70}")
    for task_name, log in all_logs.items():
        avg_score = sum(log["episode_scores"]) / len(log["episode_scores"])
        total_findings = sum(log["episode_findings"])
        print(
            f"{task_name:20} | Avg Score: {avg_score:.3f} | "
            f"Total Findings: {total_findings}"
        )
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
