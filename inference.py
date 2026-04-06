"""
OpenAI-compatible agent runner for AI Security environment
Includes evaluation summary and performance metrics.
Serves as a baseline implementation showing how to interact with the environment.
 
STDOUT FORMAT
- The script must emit exactly three line types to stdout, in this order:
 
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""
 
import json
import os
import textwrap
from typing import Any, Dict, List, Optional
 
from openai import OpenAI
 
from environment import AiSecurityEnv
 
# ── Required env vars ─────────────────────────────────────────────────────────
API_KEY      = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
TASK_NAME    = os.getenv("TASK_NAME", "data_leakage_prevention")
BENCHMARK    = "ai-security-openenv"
MAX_STEPS    = 8
 
client = OpenAI(api_key=API_KEY, base_url=API_BASE_URL)
 
# ── Mandatory stdout loggers ──────────────────────────────────────────────────
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)
 
 
def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val  = str(done).lower()
    print(
        f"[STEP] step={step} action={action} "
        f"reward={reward:.2f} done={done_val} error={error_val}",
        flush=True
    )
 
 
def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.2f} rewards={rewards_str}",
        flush=True
    )
 
 
# ── Evaluation Summary ────────────────────────────────────────────────────────


class EvaluationSummary:
    """Structured evaluation summary with performance metrics and risk assessment."""
 
    @staticmethod
    def compute_summary(rewards: List[float], episode_count: int) -> Dict[str, Any]:
        if not rewards:
            return {
                "task_scores": [],
                "average_score": 0.0,
                "median_score": 0.0,
                "success_rate": 0.0,
                "risk_level": "high",
                "confidence": 0.0,
                "recommendations": ["No episodes evaluated"],
                "total_episodes": episode_count,
                "passing_episodes": 0,
            }
 
        task_scores   = rewards
        average_score = sum(rewards) / len(rewards)
        sorted_scores = sorted(rewards)
        n = len(sorted_scores)
        median_score  = (
            sorted_scores[n // 2]
            if n % 2 == 1
            else (sorted_scores[n // 2 - 1] + sorted_scores[n // 2]) / 2
        )
 
        success_threshold = 0.8
        success_count = sum(1 for s in rewards if s >= success_threshold)
        success_rate  = success_count / len(rewards)
 
        if average_score >= 0.85:
            risk_level = "low"
        elif average_score >= 0.70:
            risk_level = "medium"
        else:
            risk_level = "high"
 
        confidence = min(1.0, len(rewards) / 10.0)
 
        recommendations = EvaluationSummary._generate_recommendations(
            average_score, success_rate, rewards, risk_level
        )
 
        return {
            "task_scores":      [round(s, 4) for s in task_scores],
            "average_score":    round(average_score, 4),
            "median_score":     round(median_score, 4),
            "success_rate":     round(success_rate, 4),
            "risk_level":       risk_level,
            "confidence":       round(confidence, 4),
            "recommendations":  recommendations,
            "total_episodes":   episode_count,
            "passing_episodes": success_count,
        }
 
    @staticmethod
    def _generate_recommendations(
        avg_score: float,
        success_rate: float,
        scores: List[float],
        risk_level: str,
    ) -> List[str]:
        recommendations = []
 
    def _generate_recommendations(avg_score: float, success_rate: float,
                                  scores: List[float], risk_level: str) -> List[str]:
        """Generate actionable recommendations based on performance"""
        recommendations: List[str] = []

        if avg_score >= 0.85:
            recommendations.append("Agent demonstrates strong threat detection capability.")
        elif avg_score >= 0.70:
            recommendations.append(
                "Agent shows competent performance but needs improvement on edge cases."
            )
        else:
            recommendations.append(
                "Agent requires significant improvement in threat classification."
            )
 
        if success_rate < 0.5:
            recommendations.append(
                "Below 50% success rate - review grading criteria alignment."
            )
 
        if scores:
            min_score = min(scores)   # ← BUG FIX: was on same line as max_score
            max_score = max(scores)
            variance  = max_score - min_score
 
            if variance > 0.6:
                recommendations.append(
                    "High score variance detected - performance is inconsistent across tasks."
                )
            if min_score < 0.3:
                recommendations.append(
                    "Extremely low scores on some tasks - check for specific failure patterns."
                )
 
        if risk_level == "high":
            recommendations.append(
                "Risk level HIGH - not suitable for production deployment."
            )
        elif risk_level == "medium":
            recommendations.append(
                "Risk level MEDIUM - recommend additional testing before deployment."
            )
        else:
            recommendations.append(
                "Risk level LOW - suitable for controlled production deployment."
            )
 
        return recommendations
 
 
# ── Baseline heuristic agent ──────────────────────────────────────────────────
class SecurityAgentBaseline:
    """Baseline agent using pattern matching to solve security tasks."""
 
    def __init__(self):
    """
    Baseline agent that uses pattern matching to solve security tasks.
    Can be extended with LLM calls (OpenAI, Anthropic, etc.)
    """

    def __init__(self):
        """Initialize agent"""
        self.env = AiSecurityEnv()
 
    def run_episode(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        state = self.env.reset()
        action = self.decide(state)
        observation, reward, done, info = self.env.step(action)
        return {
            "task":        state.get("event_id"),
            "state":       state,
            "action":      action,
            "reward":      reward,
            "observation": observation,
 
    def decide(self, state: Dict[str, Any]) -> Dict[str, Any]:
        data_sensitivity = state.get("data_sensitivity", "low")
        logs_text        = " ".join(logs).lower()
        # Data exfiltration
        if any(kw in logs_text for kw in ["exfiltrate", "export", "transfer", "2gb"]):
        """
        Make a security decision based on the current state.
        This is a baseline heuristic implementation.
        Enhanced to handle insider threat detection.

        Returns:
            {
                "allow": bool,
                "threat_type": str,
                "response_action": str,
                "firewall_rule": {...}  # optional
            }
        """
        logs: List[str] = state.get("logs", [])
        data_sensitivity: str = state.get("data_sensitivity", "low")

        # Convert to lowercase for matching
        logs_text: str = " ".join(logs).lower()

        # Detect data exfiltration
        if any(keyword in logs_text for keyword in ["exfiltrate", "export", "transfer", "2gb"]):
            if data_sensitivity == "high":
                return {
                    "allow": False,
                    "threat_type": "data_exfiltration",
                    "response_action": "block",
                }
 
        # Brute force
        if "failed login" in logs_text and "successful login" in logs_text:
            if logs_text.count("failed login") >= 3:
                return {
                    "allow": False,
                    "threat_type": "brute_force",
                    "response_action": "block_ip",
                    "firewall_rule": {
                        "target": "ip",
                        "duration": "1h",
                    },
                }
 
        # Intrusion (multiple anomalies)
        anomalies = sum([
            "unusual" in logs_text,
            "unknown ip" in logs_text or ("unknown" in logs_text and "ip" in logs_text),
            any(t in logs_text for t in ["midnight", "02:", "03:", "02:30"]),
            "admin login" in logs_text,
        ])
            return {
                "allow": False,
                "threat_type": "intrusion",
                "firewall_rule": {
                    "rule_action": "block",
                    "target": "ip",
                    "duration": "24h",
                },
            }
 
        # Insider threat
        insider_signals = (
            2 * any(kw in logs_text for kw in ["dropbox", "cloud", "personal", "external", "upload"])
            + any(kw in logs_text for kw in ["financial", "hr", "salary", "sensitive"])
            + (data_sensitivity == "high")
        )
        clean_signals = any(kw in logs_text for kw in ["clean", "training", "tenure", "3-year", "aware"])
 
        if (insider_signals - clean_signals) >= 3 and data_sensitivity == "high":
            return {
                "allow": False,
                "threat_type": "insider_threat",
                "response_action": "block + alert",
                "firewall_rule": {
                    "rule_action": "block",
                    "target": "endpoint",
                    "duration": "12h",
                },
            }
 
        return {"allow": True, "threat_type": "none", "response_action": "allow"}
 
    def run_benchmark(self, num_episodes: int = 10) -> Dict[str, Any]:
        episodes  = []
        rewards   = []
        successes = 0
 
        for _ in range(num_episodes):
            episode = self.run_episode()
            episodes.append(episode)
            rewards.append(episode["reward"])
            if episode["success"]:
                successes += 1
 
        avg_reward   = sum(rewards) / len(rewards) if rewards else 0.0
        """
        Run multiple episodes and compute statistics with evaluation summary.

        Returns:
            {
                "total_episodes": int,
                "successful": int,
                "failed": int,
                "average_reward": float,
                "evaluation_summary": {...},
                "episodes": [...]
            }
        """
        episodes: List[Dict[str, Any]] = []
        rewards: List[float] = []
        successes: int = 0

        for _ in range(num_episodes):
            episode: Dict[str, Any] = self.run_episode()
            episodes.append(episode)
            reward: float = episode["reward"]
            rewards.append(reward)
            if episode["success"]:
                successes += 1

        avg_reward: float = sum(rewards) / len(rewards) if rewards else 0.0
        failed: int = num_episodes - successes

        # Compute evaluation summary
        eval_summary = EvaluationSummary.compute_summary(rewards, num_episodes)
 
        return {
            "total_episodes":   num_episodes,
            "successful":       successes,
            "failed":           num_episodes - successes,
            "success_rate":     round(successes / num_episodes, 4),
            "average_reward":   round(avg_reward, 4),
            "min_reward":       round(min(rewards) if rewards else 0.0, 4),
            "max_reward":       round(max(rewards) if rewards else 0.0, 4),
            "evaluation_summary": eval_summary,
            + any(t in logs_text for t in ["02:", "03:", "midnight", "night"])
                "response_action": "block + alert",
            "episodes":         episodes,
        if anomalies >= 3 and data_sensitivity == "high":
        }
                        "rule_action": "block",
            if data_sensitivity == "high":
 
 
 
        logs             = state.get("logs", [])
# ── LLM Agent (OpenAI client — required by submission rules) ──────────────────
class LLMAgentAdapter:
            "grade":       info.get("grade"),

    """LLM-based agent using OpenAI-compatible client."""

 

    SYSTEM_PROMPT = textwrap.dedent("""

        You are a cybersecurity expert. Analyze the security event and respond

        ONLY with a valid JSON object — no markdown, no explanation:
        {

            "allow": <true|false>,

            "threat_type": "<data_exfiltration|brute_force|intrusion|insider_threat|none>",

            "response_action": "<string>",
            "firewall_rule": {
                "rule_action": "<allow|block>",
                "target": "<ip|endpoint>",

                "duration": "<string>"
            }

        }
    """).strip()
 
    def __init__(self):
        self.env = AiSecurityEnv()

 
    def build_prompt(self, state: Dict[str, Any]) -> str:
        logs = state.get("logs", [])

        return json.dumps({
            "user_role":        state.get("user_role", ""),
            "data_sensitivity": state.get("data_sensitivity", ""),

            "logs":             logs,
        })
 
    def call_llm(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Call LLM via OpenAI-compatible client (required by submission rules)."""
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                max_tokens=300,
                temperature=0.2,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
            )
            raw = response.choices[0].message.content.strip()
            return json.loads(raw)
        except Exception as e:
            print(f"[LLM Error] {e}", flush=True)
            return None
 
    def run_episode_with_llm(self, task_id: Optional[str] = None) -> Dict[str, Any]:

        state  = self.env.reset()

        prompt = self.build_prompt(state)

        action = self.call_llm(prompt)

 
        if action is None:

            action = SecurityAgentBaseline().decide(state)
 

        observation, reward, done, info = self.env.step(action)

        return {

            "task":    state.get("event_id"),
            "state":   state,

            "action":  action,

            "reward":  reward,

            "grade":   info.get("grade"),

            "success": reward >= 0.8,

        }
 
 
# ── Main entry-point with mandatory stdout format ─────────────────────────────
def run_task_with_logging(task_name: str = TASK_NAME) -> float:




class LLMAgentAdapter:
    """Placeholder for LLM integration"""
    pass


def run_benchmark(task_idx: Optional[int] = None, num_episodes: int = 1) -> Dict[str, Any]:
    """
    Run benchmark for selected task.
    
    Args:
        task_idx: Task index (0=easy, 1=medium, 2=hard) or None for random
        num_episodes: Number of episodes to run
    
    Returns:
        Formatted benchmark results as dict
    """
    try:
        agent = SecurityAgentBaseline()
        results = agent.run_benchmark(num_episodes)
        return results
    except Exception as e:
        return {"error": str(e)}


def run_dashboard_simulation() -> Dict[str, Any]:
    """
    Run simulation for dashboard display with latest event and decision.
    
    Returns:
        {
            "latest_event": {...},
            "decision": {...},
            "average_reward": float,
            "success_rate": float,
            "risk_level": str
        }
    """
    try:
        agent = SecurityAgentBaseline()
        episode = agent.run_episode()
        state = agent.env.reset()
        decision = agent.decide(state)
        
        # Run 5 episodes for metrics
        all_rewards: List[float] = []
        successes: int = 0
        for _ in range(5):
            ep = agent.run_episode()
            all_rewards.append(ep["reward"])
            if ep["success"]:
                successes += 1
        
        avg_reward = sum(all_rewards) / len(all_rewards)
        success_rate = successes / 5
        
        if avg_reward >= 0.85:
            risk_level = "low"
        elif avg_reward >= 0.70:
            risk_level = "medium"
        else:
            risk_level = "high"
        
        return {
            "latest_event": episode["state"],
            "decision": decision,
            "average_reward": round(avg_reward, 4),
            "success_rate": round(success_rate, 4),
            "risk_level": risk_level,
            "episode_details": episode
        }
    except Exception as e:
        return {"error": str(e)}


def format_benchmark_json(results: Dict[str, Any]) -> str:
    """Format benchmark results as JSON string"""
    return json.dumps(results, indent=2)

    """
    Run one task and emit [START] / [STEP] / [END] logs.
    Returns the final score in [0, 1].

    """
    log_start(task_name, BENCHMARK, MODEL_NAME)
 

    env     = AiSecurityEnv()
    agent   = LLMAgentAdapter()

    rewards: List[float] = []

    score   = 0.0
    success = False

    steps   = 0
 
    state = env.reset()

 
    for step in range(1, MAX_STEPS + 1):

        steps = step
        error: Optional[str] = None
        reward = 0.0
        done   = False
 

        try:
            prompt = agent.build_prompt(state)
            action = agent.call_llm(prompt)

 
            if action is None:
                action = SecurityAgentBaseline().decide(state)
 
            observation, reward, done, info = env.step(action)
            score   = reward
            success = reward >= 0.5

            action_str = json.dumps(action)
 
        except Exception as e:
            error      = str(e)[:80]
            reward     = -0.2
            action_str = "error"
 
        rewards.append(reward)
        log_step(step, action_str, reward, done, error)
 
        if done:
            break
 
    log_end(success, steps, score, rewards)
    return score
 
 
def main():
    """Main execution with OpenEnv-compliant logging format"""
    import argparse
 
    parser = argparse.ArgumentParser(description="Run AI Security Agent")
    parser.add_argument("--episodes", type=int, default=5)
    parser.add_argument(
        "--mode",
        choices=["baseline", "benchmark", "llm"],
        default="llm",
        help="llm = OpenAI client with stdout logs (required for submission)",

    )
    args = parser.parse_args()

 

    if args.mode == "llm":
        # ← Required path for submission validation
        run_task_with_logging(TASK_NAME)

 

    elif args.mode == "baseline":

        agent  = SecurityAgentBaseline()

        result = agent.run_episode()

        print(json.dumps(result, indent=2, default=str))

 

    elif args.mode == "benchmark":
        agent     = SecurityAgentBaseline()

        benchmark = agent.run_benchmark(args.episodes)

        summary   = benchmark["evaluation_summary"]

 

        print("\n" + "=" * 70)
        print("EVALUATION SUMMARY")
        print("=" * 70)

        print(f"Average Score: {summary['average_score']:.4f}")

        print(f"Median Score:  {summary['median_score']:.4f}")

        print(f"Success Rate:  {summary['success_rate']*100:.1f}%")

        print(f"Risk Level:    {summary['risk_level'].upper()}")
        print(f"Confidence:    {summary['confidence']*100:.1f}%")
        print("\nRecommendations:")

        for i, rec in enumerate(summary["recommendations"], 1):

            print(f"  {i}. {rec}")
        print("=" * 70 + "\n")
        print(json.dumps(benchmark, indent=2, default=str))
    parser = argparse.ArgumentParser(description="Run AI Security Agent Baseline")
    parser.add_argument("--episodes", type=int, default=1, help="Number of episodes to run")
    parser.add_argument("--task", type=int, default=None, help="Task index (0/1/2) or None for random")
    args = parser.parse_args()

    task_id: int = args.task if args.task is not None else -1
    task_names: List[str] = ["data_leakage_prevention", "threat_detection", "advanced_threat_response"]
    task_name: str = task_names[task_id] if 0 <= task_id < len(task_names) else "random"
    
    # Log START
    print(f"[START] task={task_name} env=ai-security-openenv model=baseline", flush=True)
    
    agent = SecurityAgentBaseline()
    all_rewards: List[float] = []
    total_steps: int = 0
    final_success: bool = False
    
    try:
        # Run episodes
        for _ in range(args.episodes):
            state: Dict[str, Any] = agent.env.reset()
            episode_steps: int = 0
            
            while True:
                episode_steps += 1
                action: Dict[str, Any] = agent.decide(state)
                observation: Dict[str, Any]
                reward: float
                done: bool
                info: Dict[str, Any]
                observation, reward, done, info = agent.env.step(action)
                all_rewards.append(reward)
                
                # Convert done and error to JSON-compliant format
                done_str: str = "true" if done else "false"
                error_val: Optional[Any] = info.get("error")
                error_str: str = "null" if error_val is None else json.dumps(error_val)
                
                # Log STEP with exact format: [STEP] step=<n> action=<json> reward=<0.00> done=<true|false> error=<null|msg>
                print(
                    f"[STEP] step={episode_steps} action={json.dumps(action)} "
                    f"reward={reward:.2f} done={done_str} error={error_str}",
                    flush=True
                )
                
                if done:
                    if reward >= 0.8:
                        final_success = True
                    total_steps += episode_steps
                    break
                
                state = observation
        
        # Calculate final metrics
        avg_reward: float = sum(all_rewards) / len(all_rewards) if all_rewards else 0.0
        success_str: str = "true" if final_success else "false"
        rewards_list: str = ",".join([f"{r:.2f}" for r in all_rewards])
        
        # Log END with exact format: [END] success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...>
        print(
            f"[END] success={success_str} steps={total_steps} score={avg_reward:.2f} rewards={rewards_list}",
            flush=True
        )
        
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {str(e)}", flush=True)
        raise

 
 
if __name__ == "__main__":

    main()

