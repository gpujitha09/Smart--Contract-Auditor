"""Metrics tracking and logging utilities for monitoring."""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import numpy as np


class MetricsTracker:
    """
    Tracks training and inference metrics for monitoring and analysis.
    
    Metrics tracked:
    - Episode rewards and success rate
    - Average reward per task
    - Learning curves
    - Inference performance
    """

    def __init__(self, output_dir: str = "logs"):
        """Initialize metrics tracker."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.training_metrics: List[Dict] = []
        self.inference_metrics: List[Dict] = []
        self.start_time = datetime.now()

    def log_training_episode(
        self,
        task_name: str,
        episode: int,
        reward: float,
        steps: int,
        success: bool,
        notes: Optional[str] = None,
    ):
        """
        Record metrics from a single training episode.
        
        Args:
            task_name: Name of task (basic_audit, intermediate_audit, etc)
            episode: Episode number
            reward: Final episode reward
            steps: Number of steps taken
            success: Whether episode was successful
            notes: Optional additional notes
        """
        metric = {
            "timestamp": datetime.now().isoformat(),
            "task_name": task_name,
            "episode": episode,
            "reward": reward,
            "steps": steps,
            "success": success,
            "notes": notes,
        }
        self.training_metrics.append(metric)

    def log_inference_run(
        self,
        model_type: str,  # "rl" or "llm"
        task_name: str,
        contract_name: str,
        score: float,
        findings_count: int,
        latency_ms: float,
        notes: Optional[str] = None,
    ):
        """
        Record metrics from a single inference run.
        
        Args:
            model_type: "rl" for Q-Learning, "llm" for LLM-based
            task_name: Task name
            contract_name: Contract being audited
            score: Final audit score (0.0-1.0)
            findings_count: Number of vulnerabilities found
            latency_ms: Inference time in milliseconds
            notes: Optional notes
        """
        metric = {
            "timestamp": datetime.now().isoformat(),
            "model_type": model_type,
            "task_name": task_name,
            "contract_name": contract_name,
            "score": score,
            "findings_count": findings_count,
            "latency_ms": latency_ms,
            "notes": notes,
        }
        self.inference_metrics.append(metric)

    def get_training_summary(self, task_name: Optional[str] = None) -> Dict:
        """
        Get summary statistics for training episodes.
        
        Args:
            task_name: Filter by task (None = all tasks)
            
        Returns:
            dict with avg_reward, success_rate, total_episodes, etc
        """
        metrics = self.training_metrics
        if task_name:
            metrics = [m for m in metrics if m["task_name"] == task_name]
        
        if not metrics:
            return {}
        
        rewards = [m["reward"] for m in metrics]
        successes = sum(1 for m in metrics if m["success"])
        
        return {
            "task_name": task_name or "all",
            "total_episodes": len(metrics),
            "avg_reward": float(np.mean(rewards)),
            "max_reward": float(np.max(rewards)),
            "min_reward": float(np.min(rewards)),
            "std_reward": float(np.std(rewards)),
            "success_rate": successes / len(metrics) if metrics else 0.0,
        }

    def get_inference_summary(self, model_type: Optional[str] = None) -> Dict:
        """
        Get summary statistics for inference runs.
        
        Args:
            model_type: Filter by model ("rl" or "llm", None = all)
            
        Returns:
            dict with avg_score, avg_latency, etc
        """
        metrics = self.inference_metrics
        if model_type:
            metrics = [m for m in metrics if m["model_type"] == model_type]
        
        if not metrics:
            return {}
        
        scores = [m["score"] for m in metrics]
        latencies = [m["latency_ms"] for m in metrics]
        
        return {
            "model_type": model_type or "all",
            "total_runs": len(metrics),
            "avg_score": float(np.mean(scores)),
            "max_score": float(np.max(scores)),
            "min_score": float(np.min(scores)),
            "std_score": float(np.std(scores)),
            "avg_latency_ms": float(np.mean(latencies)),
            "max_latency_ms": float(np.max(latencies)),
        }

    def save_training_log(self):
        """Save training metrics to JSON file."""
        filepath = self.output_dir / "training_metrics.json"
        with open(filepath, "w") as f:
            json.dump({
                "saved_at": datetime.now().isoformat(),
                "total_episodes": len(self.training_metrics),
                "metrics": self.training_metrics,
                "summary_by_task": {
                    "basic_audit": self.get_training_summary("basic_audit"),
                    "intermediate_audit": self.get_training_summary("intermediate_audit"),
                    "advanced_audit": self.get_training_summary("advanced_audit"),
                }
            }, f, indent=2)
        print(f"✓ Training metrics saved to {filepath}")

    def save_inference_log(self):
        """Save inference metrics to JSON file."""
        filepath = self.output_dir / "inference_metrics.json"
        with open(filepath, "w") as f:
            json.dump({
                "saved_at": datetime.now().isoformat(),
                "total_runs": len(self.inference_metrics),
                "metrics": self.inference_metrics,
                "summary_by_model": {
                    "rl": self.get_inference_summary("rl"),
                    "llm": self.get_inference_summary("llm"),
                }
            }, f, indent=2)
        print(f"✓ Inference metrics saved to {filepath}")

    def print_training_report(self):
        """Print training metrics to console."""
        print("\n" + "="*70)
        print("TRAINING METRICS REPORT")
        print("="*70)
        
        for task in ["basic_audit", "intermediate_audit", "advanced_audit"]:
            summary = self.get_training_summary(task)
            if summary:
                print(f"\n{task}:")
                print(f"  Episodes: {summary['total_episodes']}")
                print(f"  Avg Reward: {summary['avg_reward']:.3f} ± {summary['std_reward']:.3f}")
                print(f"  Success Rate: {summary['success_rate']:.1%}")
                print(f"  Range: [{summary['min_reward']:.3f}, {summary['max_reward']:.3f}]")

    def print_inference_report(self):
        """Print inference metrics to console."""
        print("\n" + "="*70)
        print("INFERENCE METRICS REPORT")
        print("="*70)
        
        for model in ["rl", "llm"]:
            summary = self.get_inference_summary(model)
            if summary:
                print(f"\n{model.upper()} Model:")
                print(f"  Runs: {summary['total_runs']}")
                print(f"  Avg Score: {summary['avg_score']:.3f} ± {summary['std_score']:.3f}")
                print(f"  Avg Latency: {summary['avg_latency_ms']:.1f}ms")
                print(f"  Range: [{summary['min_score']:.3f}, {summary['max_score']:.3f}]")


# Global tracker instance
_tracker: Optional[MetricsTracker] = None


def get_tracker() -> MetricsTracker:
    """Get or create global metrics tracker."""
    global _tracker
    if _tracker is None:
        _tracker = MetricsTracker()
    return _tracker


def reset_tracker():
    """Reset global tracker."""
    global _tracker
    _tracker = None
