<<<<<<< HEAD
from environment import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860)
=======
"""
Professional SOC Dashboard for AI Security OpenEnv
Real-time threat detection and response simulation
"""

import gradio as gr
import json
import os
from typing import Dict, Any
from inference import run_dashboard_simulation, run_benchmark, format_benchmark_json


def create_soc_dashboard() -> gr.Blocks:
    """Create a professional SOC dashboard interface"""

    with gr.Blocks(
        title="AI Security OpenEnv - SOC Dashboard",
        theme=gr.themes.Soft(),
        css="""
        .dashboard-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; color: white; }
        .threat-event { background: #fee; border-left: 4px solid #f44; padding: 15px; border-radius: 5px; }
        .decision-section { background: #efe; border-left: 4px solid #4f4; padding: 15px; border-radius: 5px; }
        .metrics-section { background: #eef; border-left: 4px solid #44f; padding: 15px; border-radius: 5px; }
        """
    ) as demo:

        # Header
        gr.Markdown("""
        # 🛡️ AI Security OpenEnv - SOC Dashboard
        
        **Real-time Threat Detection & Response Simulation**
        
        Advanced AI-powered security event analysis with deterministic grading and performance metrics.
        """)

        with gr.Row():
            with gr.Column(scale=2):
                gr.Markdown("### Simulation Controls")
                num_episodes = gr.Slider(
                    minimum=1, maximum=10, value=1, step=1,
                    label="Episodes to Run"
                )
                run_button = gr.Button(
                    "▶ Run Simulation", 
                    variant="primary", 
                    size="lg"
                )

            with gr.Column(scale=1):
                gr.Markdown("### System Status")
                status_box = gr.Textbox(
                    value="🟢 System Ready", 
                    label="Status",
                    interactive=False
                )

        # Threat Event Section
        gr.Markdown("## 🚨 Threat Event Details")
        with gr.Row():
            event_id = gr.Textbox(label="Event ID", interactive=False)
            event_severity = gr.Textbox(label="Data Sensitivity", interactive=False)

        event_logs = gr.Code(
            language="json",
            label="Security Logs",
            interactive=False
        )

        with gr.Row():
            user_role = gr.Textbox(label="User Role", interactive=False)
            threat_category = gr.Textbox(label="Event Category", interactive=False)

        # Agent Decision Section
        gr.Markdown("## 🤖 AI Agent Decision")
        with gr.Row():
            decision_allow = gr.Textbox(label="Allow Access", interactive=False)
            detected_threat = gr.Textbox(label="Detected Threat Type", interactive=False)

        decision_action = gr.Textbox(
            label="Response Action",
            interactive=False
        )

        decision_detail = gr.Code(
            language="json",
            label="Full Decision",
            interactive=False
        )

        # Metrics Section
        gr.Markdown("## 📊 Performance Metrics")
        
        with gr.Row():
            avg_reward = gr.Number(label="Average Reward", interactive=False, precision=4)
            success_rate = gr.Number(label="Success Rate", interactive=False, precision=4)
        
        with gr.Row():
            risk_level = gr.Textbox(label="Risk Assessment", interactive=False)
            confidence = gr.Number(label="Confidence Score", interactive=False, precision=4)

        # Episode Details
        gr.Markdown("## 📈 Detailed Results")
        episode_details = gr.Code(
            language="json",
            label="Full Simulation Results",
            interactive=False,
            lines=15
        )

        # Benchmark Section
        gr.Markdown("---")
        gr.Markdown("## 🔬 Comprehensive Benchmark")
        
        benchmark_results = gr.Code(
            language="json",
            label="Full Benchmark Report",
            interactive=False,
            lines=20
        )

        def run_simulation(num_eps: int) -> tuple:
            """Run the simulation and return results"""
            try:
                result = run_dashboard_simulation()
                
                if "error" in result:
                    return (
                        "🔴 Error",
                        "", "", "", "", "", "",
                        "", "", "", "", "", "",
                        json.dumps(result, indent=2),
                        json.dumps(result, indent=2)
                    )

                # Extract latest event
                event = result.get("latest_event", {})
                decision = result.get("decision", {})
                
                # Format threat logs
                logs = event.get("logs", [])
                logs_formatted = json.dumps(logs, indent=2)
                
                # Format decision
                decision_formatted = json.dumps(decision, indent=2)
                
                # Risk level styling
                risk = result.get("risk_level", "unknown")
                
                # Run benchmark for comprehensive results
                benchmark = run_benchmark(num_episodes=int(num_eps))
                benchmark_formatted = format_benchmark_json(benchmark)

                return (
                    "🟢 Simulation Complete",
                    event.get("event_id", "Unknown"),
                    event.get("data_sensitivity", "Unknown"),
                    logs_formatted,
                    event.get("user_role", "Unknown"),
                    "Security Event",
                    str(decision.get("allow", False)).lower(),
                    decision.get("threat_type", "none"),
                    decision.get("response_action", "allow"),
                    decision_formatted,
                    result.get("average_reward", 0.0),
                    result.get("success_rate", 0.0),
                    risk,
                    0.95,
                    json.dumps(result, indent=2),
                    benchmark_formatted
                )
            except Exception as e:
                error_msg = json.dumps({"error": str(e)}, indent=2)
                return (
                    "🔴 Error: " + str(e),
                    "", "", "", "", "", "", "", "", "",
                    0.0, 0.0, "error", 0.0,
                    error_msg,
                    error_msg
                )

        # Connect button to simulation
        run_button.click(
            fn=run_simulation,
            inputs=[num_episodes],
            outputs=[
                status_box,
                event_id,
                event_severity,
                event_logs,
                user_role,
                threat_category,
                decision_allow,
                detected_threat,
                decision_action,
                decision_detail,
                avg_reward,
                success_rate,
                risk_level,
                confidence,
                episode_details,
                benchmark_results
            ]
        )

        gr.Markdown("""
        ---
        **Dashboard Features:**
        - ✅ Dynamic threat event generation
        - ✅ Deterministic grading with seeded randomization
        - ✅ Real-time AI decision making
        - ✅ Comprehensive performance metrics
        - ✅ Professional SOC-style interface
        - ✅ OpenEnv-compliant API
        """)

    return demo


def main():
    """Launch the SOC dashboard"""
    port = int(os.environ.get("PORT", 7860))
    demo = create_soc_dashboard()
    demo.launch(
        server_name="0.0.0.0",
        server_port=port,
        show_error=True,
        share=False
    )


if __name__ == "__main__":
    main()
>>>>>>> 99333add87ad7a450d1c3bdc3113d19d507a9142
