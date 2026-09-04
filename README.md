<img width="975" height="610" alt="image" src="https://github.com/user-attachments/assets/a3513f91-1c9a-47a3-87ec-e696cefda2ff" />


PROJECT DOCUMENTATION REPORT
SECURE-BY-DESIGN AI REVIEWER
A Deterministic Security Pipeline with Automated AI Remediation
HackWave 3.0 Hackathon - 2026

Team Name: Code Blooded

Team Members	Institution	Department
K Moanish Chowdary	Sreenidhi University	CSE
B V Bhavana	Stanley College of Engineering & Technology	CME
Akshaya Ponnapalli	Stanley College of Engineering & Technology	AI&DS
B Venkatesh	Sreenidhi University	CSE
M Lokesh	Sreenidhi University	CSE

Date: September 2026 






Abstract

The "Secure-by-Design AI Reviewer" is a comprehensive, dual-pronged DevSecOps tool engineered to shift security to the earliest possible stages of the software development lifecycle. By integrating deterministic static analysis (Semgrep) with advanced Large Language Models (Featherless AI / Qwen 2.5 Coder), this project automates vulnerability detection and remediation. The solution is deployed in two environments: a reusable enterprise GitHub Action for automated Pull Request reviews, and a VS Code Extension that provides real-time, in-IDE security scanning with one-click AI QuickFixes.
Problem Statement

Modern software development pipelines emphasize "shifting left" to catch security vulnerabilities before production. However, traditional Static Application Security Testing (SAST) tools generate overwhelming amounts of alerts, false positives, and raw logs. When a vulnerability is flagged, developers are forced to break their flow state, navigate away from their IDE, research the vulnerability, and manually engineer a fix. This context-switching reduces productivity, leads to alert fatigue, and often results in developers ignoring critical security warnings entirely.
Existing System

Existing security workflows rely heavily on standalone SAST providers (like SonarQube, Checkmarx, or basic Semgrep configurations) or native platform alerts (like GitHub Advanced Security). While these systems excel at detecting flaws based on regex or Abstract Syntax Trees (AST), they fall short in remediation. They point out the broken code but require human intervention to patch it. Furthermore, entirely LLM-based reviewers (without SAST) are prone to hallucinations, often flagging perfectly safe code or missing critical structural vulnerabilities because they lack deterministic rule engines.
Proposed Solution

The proposed solution bridges the gap between deterministic scanning and AI code generation. We propose a hybrid architecture:

●	Deterministic Detection:Use Semgrep to parse ASTs and identify undeniable vulnerabilities (e.g., SQL Injection, Command Injection) with zero hallucinations.
●	Generative Remediation: Feed the specifically flagged vulnerable code blocks and rule contexts into Featherless AI (running the Qwen2.5-Coder-7B-Instruct model) to generate highly contextual, secure replacement code.
●	Dual Delivery: Deliver this pipeline directly where developers live—inside their VS Code editor (via Code Actions/Squiggly lines) and inside their Pull Requests (via an automated GitHub Action).
Objectives

●	To eliminate context switching by bringing security alerts and fixes directly into the IDE.
●	To automate pull request security reviews, ensuring no vulnerable code merges into the main branch.
●	To mitigate LLM hallucinations by restricting the AI's scope strictly to deterministic SAST findings.
●	To package the solution as a globally reusable Enterprise GitHub Action.
Key Features

In-IDE Background Scanning: Automatically runs Semgrep on file save without blocking the main thread.
AI QuickFix: VS Code Lightbulb (💡) integration for 1-click vulnerability patching.
Automated PR Comments: The GitHub Action posts inline comments on exact vulnerable lines in a Pull Request with the AI-suggested fix.
Enterprise Reusability: Configured as a global composite GitHub action that any repository can implement.
Technology Stack

Domain	Technology / Tool
AI / LLM Engine	Featherless AI (Qwen/Qwen2.5-Coder-7B-Instruct)
Security Scanner	Semgrep
VS Code Extension	TypeScript, Node.js, esbuild, VS Code API
CI/CD Pipeline	GitHub Actions (YAML, Composite Action), PyGithub


System Architecture

The architecture is divided into two distinct but related workflows:

1.	Local IDE Architecture: The VS Code Extension Host listens for onDidSaveTextDocument events. It triggers a child process executing Semgrep. The JSON output from Semgrep is mapped to VS Code Diagnostic objects (red squiggles). A CodeActionProvider listens for user interaction on these diagnostics, triggering an asynchronous HTTP POST request to the Featherless AI endpoint, and maps the JSON response back to a WorkspaceEdit.
2.	Remote CI/CD Architecture: A Composite GitHub Action (action.yml) orchestrates the environment setup. It executes a Python script (pr_reviewer.py) that utilizes PyGithub to fetch the specific files changed in a Pull Request. Semgrep scans these files, and for every finding, the script prompts Featherless AI and subsequently uses the GitHub API to post a review comment directly onto the PR line number.
AI Architecture / Workflow

The AI workflow relies heavily on strict prompt engineering to force deterministic outputs from a non-deterministic model. The prompt structure is designed to isolate the AI's task:

Analyze this security vulnerability flagged by Semgrep.
Rule: {diagnostic.code}

Vulnerable Code:
{vulnerableCode}

CRITICAL OUTPUT REQUIREMENTS:
1. Respond with a single, raw, valid JSON object only.
2. Do NOT include markdown fences.
3. Escape all double quotes and newlines.

Required JSON schema:
{
    "fixed_code": "Replacement secure code string"
}


By enforcing a strict JSON schema and low temperature (0.1), the model acts more as an analytical compiler than a creative writer, ensuring the returned string can be safely injected back into the codebase.
Implementation

The implementation required coordinating several ecosystems.

●	GitHub Action: We created a reusable `action.yml` file utilizing the `composite` run type. This allows other repositories to reference `uses: your-username/HackWave3.0@v1`. The action sets up Python, installs dependencies (Semgrep, PyGithub, OpenAI SDK), and executes the reviewer script against the dynamic PR context variables (like `GITHUB_SHA`).
●	VS Code Extension: Scaffolded using Yeoman (`yo code`) and bundled with `esbuild`. We utilized the VS Code `languages.createDiagnosticCollection` to paint UI errors and implemented the `CodeActionProvider` interface to register our QuickFix lightbulb. To handle API communication natively, we leveraged the global `fetch` API available in the extension's Node.js runtime.

Autonomous AI Workflow

The true autonomy of the system lies in its closed-loop design:

1. Trigger: User action (save file or push PR).
2. Analysis: Semgrep parses code independently.
3. Synthesis: LLM processes Semgrep's output and synthesizes a patch.
4. Application: System automatically applies the patch via IDE Workspace Edit or PR Code Suggestion block.
5. Verification: The next save/commit re-triggers the loop, verifying that the Semgrep warning is cleared.

API & Model Integration

We integrated the Qwen/Qwen2.5-Coder-7B-Instruct model via the Featherless AI API. This model was chosen for its exceptional context comprehension regarding code syntax and security paradigms. The integration uses standard REST protocols with Bearer Token authentication. A custom regex parser was implemented in the TypeScript extension to extract the raw JSON payload in cases where the LLM disobeys the prompt and wraps the output in Markdown fences (````json ... ````).
Screenshots

  
  



   
    




Results

The integration successfully detects standard web vulnerabilities like SQL Injections and Command Injections instantaneously upon file save. The API response time from Featherless AI averages less than 2 seconds, providing a near-seamless remediation experience for the developer. The GitHub Action successfully intercepts PRs, ensuring insecure code is caught before human reviewers spend time on it.
Innovation & USP

The Unique Selling Proposition (USP) of this tool is its Hybrid Deterministic-Generative approach. Most AI coding assistants (like Copilot) passively suggest code, which can introduce vulnerabilities. Most SAST tools aggressively flag code but offer no fixes. This project is innovative because it uses deterministic logic to find the exact fault, and uses Generative AI strictly as a remediation engine constrained by that fault, drastically lowering the AI hallucination rate.
Challenges

Environment Management: Developing a VS Code extension inside a GitHub Codespace created unique challenges with task runners and esbuild problem matchers, requiring custom launch.json configurations to test the Extension Development Host.
LLM Output Formatting: Preventing the LLM from outputting conversational text (e.g., "Here is your fixed code...") was challenging. Strict prompt engineering and regex fallbacks were required to parse pure JSON.
Semgrep Coordinates: Mapping Semgrep's 1-indexed line and column numbers to VS Code's 0-indexed diagnostic API required careful mathematical alignment.
Limitations

●	Context Window Constraints: For massive files, feeding the entire file to the LLM may exceed context limits or token budgets. Currently, only the vulnerable code snippet is fed to the LLM, which might cause it to miss global variables.
●	Network Dependency: The AI remediation requires an active internet connection to communicate with the Featherless API.


Future Scope

Future iterations of the product will focus on multi-file context analysis, allowing the AI to understand vulnerabilities that span across different modules (e.g., untrusted data entering through an API controller but executed in a separate database service). Additionally, we plan to implement custom Semgrep rule-packs tailored to specific enterprise internal frameworks.
Impact

This tool drastically reduces DevSecOps friction. By empowering developers to fix security flaws with a single click inside their native workflow, organizations can expect a significant reduction in their Mean Time to Remediation (MTTR) and a lower frequency of vulnerabilities making it into production builds.
Conclusion

The HackWave3.0 Secure-by-Design AI Reviewer successfully demonstrates how combining static analysis with targeted Large Language Models can revolutionize secure coding. By providing tools directly in the IDE and the CI/CD pipeline, security transforms from a post-development hurdle into an integrated, frictionless part of the daily developer experience.
References
<img width="960" height="600" alt="Screenshot 2026-09-05 035154" src="https://github.com/user-attachments/assets/d21d3e66-259d-4896-a4f5-a309a5d2db0d" />


1.	Semgrep Official Documentation - Static Analysis Rulesets
2.	Featherless AI API Reference - Model Integration and Inferencing
3.	Visual Studio Code Extension API Documentation - CodeActionProviders and Diagnostics
4.	GitHub Actions Documentation - Creating Composite Actions
Video Reference

https://drive.google.com/file/d/1dn_9PGVl5yhXYhUKtAe363Sy-q6kS4lM/view?usp=sharing
