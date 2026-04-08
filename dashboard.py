#!/usr/bin/env python3
"""
Interactive Gradio Dashboard for Smart Contract Auditor.

Allows users to:
- Paste contract code
- Select auditing mode (RL Agent or LLM)
- View real-time findings
- Compare results
"""

import gradio as gr
import json
from typing import List, Tuple

from .agent_learner import AuditorAgent
from .environment import SmartContractAuditorEnv
from .inference import run_task_with_llm
from .models import AuditAction
from .contracts import TASK_NAMES


# Global instances
agent = AuditorAgent()
env = SmartContractAuditorEnv()

try:
    agent.load("./models/auditor_agent.json")
    agent_loaded = True
except:
    agent_loaded = False


def audit_with_rl_agent(contract_code: str, contract_name: str = "Unknown") -> Tuple[str, str]:
    """Audit using RL agent."""
    if not agent_loaded:
        return "Error", "RL Agent model not loaded. Run training first."
    
    obs = env.reset(task_name="basic_audit", episode_id="dashboard_test")
    findings = []
    step = 0
    
    # Override the contract code and name for testing
    obs.contract_code = contract_code
    obs.contract_name = contract_name
    
    while step < 10:
        action = agent.audit(obs, training=False)
        
        if action.vulnerability_type.lower() == "done":
            break
        
        findings.append({
            "type": action.vulnerability_type,
            "location": action.location,
            "severity": action.severity,
            "fix": action.fix_suggestion,
        })
        
        obs = env.step(action)
        step += 1
        
        if obs.done:
            break
    
    findings_json = json.dumps(findings, indent=2)
    summary = f"Found {len(findings)} vulnerabilities in {step} steps"
    
    return findings_json, summary


def audit_with_llm(contract_code: str, contract_name: str = "Unknown") -> Tuple[str, str]:
    """Audit using LLM (HF API)."""
    try:
        findings, summary = run_task_with_llm(contract_code, contract_name)
        findings_json = json.dumps(findings, indent=2)
        return findings_json, summary
    except Exception as e:
        return "Error", f"LLM audit failed: {str(e)}"


def compare_audits(
    contract_code: str, 
    contract_name: str = "Unknown",
    use_rl: bool = True,
    use_llm: bool = True
) -> Tuple[str, str, str]:
    """Run both auditors and compare."""
    results = {}
    
    if use_rl and agent_loaded:
        rl_findings, rl_summary = audit_with_rl_agent(contract_code, contract_name)
        results["RL Agent"] = {"Findings": rl_findings, "Summary": rl_summary}
    
    if use_llm:
        llm_findings, llm_summary = audit_with_llm(contract_code, contract_name)
        results["LLM (HF)"] = {"Findings": llm_findings, "Summary": llm_summary}
    
    comparison = json.dumps(results, indent=2)
    
    return (
        results.get("RL Agent", {}).get("Findings", "N/A"),
        results.get("LLM (HF)", {}).get("Findings", "N/A"),
        comparison,
    )


# ── Gradio UI ──────────────────────────────────────────────────

with gr.Blocks(title="Smart Contract Security Auditor", theme=gr.themes.Soft()) as demo:
    
    gr.Markdown("""
    # 🔐 Smart Contract Security Auditor
    
    **AI-powered vulnerability detection for Solidity contracts**
    
    Choose your auditing method:
    - **RL Agent**: Fast, pattern-based learner
    - **LLM (Hugging Face)**: Advanced semantic analysis
    """)
    
    with gr.Tabs():
        
        # ── Tab 1: RL Agent ──
        with gr.TabItem("🤖 RL Agent Auditor"):
            with gr.Row():
                contract_code_rl = gr.Textbox(
                    label="Solidity Contract Code",
                    lines=15,
                    placeholder="Paste your Solidity contract here...",
                    interactive=True,
                )
            
            with gr.Row():
                contract_name_rl = gr.Textbox(
                    label="Contract Name",
                    value="MyContract",
                    scale=1,
                )
                run_rl_btn = gr.Button("🔍 Audit with RL Agent", scale=1)
            
            with gr.Row():
                rl_findings_output = gr.Code(
                    label="Findings (JSON)",
                    language="json",
                    interactive=False,
                )
                rl_summary_output = gr.Textbox(
                    label="Summary",
                    interactive=False,
                )
            
            run_rl_btn.click(
                audit_with_rl_agent,
                inputs=[contract_code_rl, contract_name_rl],
                outputs=[rl_findings_output, rl_summary_output],
            )
        
        # ── Tab 2: LLM Auditor ──
        with gr.TabItem("🧠 LLM (HF) Auditor"):
            with gr.Row():
                contract_code_llm = gr.Textbox(
                    label="Solidity Contract Code",
                    lines=15,
                    placeholder="Paste your Solidity contract here...",
                    interactive=True,
                )
            
            with gr.Row():
                contract_name_llm = gr.Textbox(
                    label="Contract Name",
                    value="MyContract",
                    scale=1,
                )
                run_llm_btn = gr.Button("🔍 Audit with LLM", scale=1)
            
            with gr.Row():
                llm_findings_output = gr.Code(
                    label="Findings (JSON)",
                    language="json",
                    interactive=False,
                )
                llm_summary_output = gr.Textbox(
                    label="Summary",
                    interactive=False,
                )
            
            run_llm_btn.click(
                audit_with_llm,
                inputs=[contract_code_llm, contract_name_llm],
                outputs=[llm_findings_output, llm_summary_output],
            )
        
        # ── Tab 3: Comparison ──
        with gr.TabItem("⚖️ Compare Both"):
            with gr.Row():
                contract_code_compare = gr.Textbox(
                    label="Solidity Contract Code",
                    lines=15,
                    placeholder="Paste your Solidity contract here...",
                    interactive=True,
                )
            
            with gr.Row():
                contract_name_compare = gr.Textbox(
                    label="Contract Name",
                    value="MyContract",
                    scale=1,
                )
                run_compare_btn = gr.Button("⚖️ Compare Auditors", scale=1)
            
            with gr.Row():
                rl_comp_output = gr.Code(
                    label="RL Agent Findings",
                    language="json",
                    interactive=False,
                )
                llm_comp_output = gr.Code(
                    label="LLM Findings",
                    language="json",
                    interactive=False,
                )
            
            comparison_output = gr.Code(
                label="Full Comparison",
                language="json",
                interactive=False,
            )
            
            run_compare_btn.click(
                compare_audits,
                inputs=[contract_code_compare, contract_name_compare],
                outputs=[rl_comp_output, llm_comp_output, comparison_output],
            )
        
        # ── Tab 4: Examples ──
        with gr.TabItem("📚 Examples"):
            gr.Markdown("""
            ### Example Contracts
            
            **Reentrancy Vulnerability:**
            ```solidity
            function withdraw() public {
                uint256 bal = balances[msg.sender];
                (bool sent, ) = msg.sender.call{value: bal}("");
                require(sent, "Failed");
                balances[msg.sender] = 0;
            }
            ```
            
            **Integer Overflow:**
            ```solidity
            function batchTransfer(address[] memory receivers, uint256 value) public {
                uint256 amount = receivers.length * value;
                balances[msg.sender] -= amount;
                for (uint i = 0; i < receivers.length; i++) {
                    balances[receivers[i]] += value;
                }
            }
            ```
            
            **Access Control:**
            ```solidity
            function setOwner(address newOwner) public {
                owner = newOwner;
            }
            ```
            """)
    
    # ── Footer ──
    gr.Markdown("""
    ---
    **Eternal Champ | Smart Contract Security Auditor © 2026 - All Rights Reserved**  
    Powered by Q-Learning & HF Inference Router
    """)

if __name__ == "__main__":
    demo.launch(
        server_name="127.0.0.1",
        server_port=7860,
        share=False,
    )
