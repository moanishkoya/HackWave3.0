import os
import sys
import json
import logging
import subprocess
from openai import OpenAI
from github import Github

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secure-reviewer")

client = OpenAI(
    base_url="https://api.featherless.ai/v1",
    api_key=os.environ.get("FEATHERLESS_API_KEY")
)

def run_semgrep():
    logger.info("Running Semgrep...")
    cmd = ["semgrep", "scan", "--json", "--config", "p/security-audit", "."]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if not result.stdout:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("results", [])
    except json.JSONDecodeError:
        return []

def get_featherless_fix(finding):
    prompt = f"""
    Analyze this security vulnerability.
    Rule: {finding['check_id']}
    File: {finding['path']}
    
    Vulnerable Code:
    {finding['extra'].get('lines', '')}
    
    Return a JSON object with this exact structure (no markdown fences, just raw JSON):
    {{
        "explanation": "Brief explanation of the risk",
        "risk_level": "HIGH",
        "fixed_code": "The secure replacement code"
    }}
    """
    
    try:
        response = client.chat.completions.create(
            model="meta-llama/Meta-Llama-3-8B-Instruct",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        raw_output = response.choices[0].message.content.strip()
        if raw_output.startswith("```json"):
            raw_output = raw_output.replace("```json", "").replace("```", "").strip()
        return json.loads(raw_output)
    except Exception as e:
        logger.error(f"Featherless AI Error: {e}")
        return None

def main():
    pr_number = os.environ.get("PR_NUMBER")
    if not pr_number:
        sys.exit(0)

    gh = Github(os.environ["GITHUB_TOKEN"])
    repo = gh.get_repo(os.environ["GITHUB_REPOSITORY"])
    pr = repo.get_pull(int(pr_number))
    
    pr_files = {f.filename for f in pr.get_files()}
    findings = run_semgrep()
    relevant_findings = [f for f in findings if f['path'] in pr_files]

    if not relevant_findings:
        sys.exit(0)

    review_comments = []
    for f in relevant_findings:
        fix = get_featherless_fix(f)
        if not fix:
            continue

        body = (
            f"### 🛡️ Security Vulnerability: `{f['check_id']}`\n"
            f"**Risk Level:** `{fix.get('risk_level', 'UNKNOWN')}`\n\n"
            f"> {fix.get('explanation', '')}\n\n"
            f"**Suggested Remediation:**\n"
            f"```suggestion\n{fix.get('fixed_code', '')}\n```\n"
        )
        review_comments.append({
            "path": f['path'],
            "line": f['end']['line'],
            "body": body
        })

    if review_comments:
        pr.create_review(
            commit=repo.get_commit(os.environ["HEAD_SHA"]),
            body="## 🛡️ Secure-by-Design Reviewer found vulnerabilities.",
            event="COMMENT",
            comments=review_comments
        )

if __name__ == "__main__":
    main()