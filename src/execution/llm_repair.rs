use eyre::Result;
use std::path::Path;
use std::process::{Command, Stdio};

pub struct LLMRepair;

impl LLMRepair {
    /// Call LLM API to fix syntax errors
    pub fn call_llm_to_fix_syntax(program_path: &Path, error_message: &str) -> Result<String> {
        let original_code = std::fs::read_to_string(program_path)?;

        let prompt = format!(
            "The following C++ fuzzer code has a syntax error. Please fix it and return ONLY the corrected code without any explanation, comments, or markdown formatting.\n\n\
            Syntax Error:\n{}\n\n\
            Code to fix:\n{}\n\n\
            Return ONLY the complete fixed C++ code.",
            error_message,
            original_code
        );

        // Get API key from environment
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .map_err(|_| eyre::eyre!("No API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY"))?;

        // Determine which API to use based on which key is set
        if std::env::var("ANTHROPIC_API_KEY").is_ok() {
            Self::call_claude_api(&prompt, &api_key)
        } else {
            Self::call_openai_api(&prompt, &api_key)
        }
    }

    /// Call Claude API
    fn call_claude_api(prompt: &str, api_key: &str) -> Result<String> {
        let request_body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 8192,
            "messages": [{
                "role": "user",
                "content": prompt
            }]
        });

        let output = Command::new("curl")
            .arg("-s")
            .arg("https://api.anthropic.com/v1/messages")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-H")
            .arg(format!("x-api-key: {}", api_key))
            .arg("-H")
            .arg("anthropic-version: 2023-06-01")
            .arg("-d")
            .arg(request_body.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(eyre::eyre!("Claude API call failed: {}", err));
        }

        let response_text = String::from_utf8_lossy(&output.stdout);
        let data: serde_json::Value = serde_json::from_str(&response_text)?;

        let fixed_code = data["content"][0]["text"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Failed to extract code from Claude response"))?
            .to_string();

        Ok(Self::extract_code_from_response(&fixed_code))
    }

    /// Call OpenAI API
    fn call_openai_api(prompt: &str, api_key: &str) -> Result<String> {
        let request_body = serde_json::json!({
            "model": "gpt-4",
            "messages": [{
                "role": "user",
                "content": prompt
            }],
            "temperature": 0.3
        });

        let output = Command::new("curl")
            .arg("-s")
            .arg("https://api.openai.com/v1/chat/completions")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-H")
            .arg(format!("Authorization: Bearer {}", api_key))
            .arg("-d")
            .arg(request_body.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(eyre::eyre!("OpenAI API call failed: {}", err));
        }

        let response_text = String::from_utf8_lossy(&output.stdout);
        let data: serde_json::Value = serde_json::from_str(&response_text)?;

        let fixed_code = data["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Failed to extract code from OpenAI response"))?
            .to_string();

        Ok(Self::extract_code_from_response(&fixed_code))
    }

    /// Extract code from LLM response, removing markdown formatting
    fn extract_code_from_response(response: &str) -> String {
        let trimmed = response.trim();

        // Try to extract from code blocks
        if let Some(start) = trimmed.find("```cpp") {
            if let Some(end) = trimmed[start..].find("```").map(|i| start + i + 6) {
                if let Some(code_end) = trimmed[end..].find("```") {
                    return trimmed[end..end + code_end].trim().to_string();
                }
            }
        }

        if let Some(start) = trimmed.find("```c++") {
            if let Some(end) = trimmed[start..].find("```").map(|i| start + i + 6) {
                if let Some(code_end) = trimmed[end..].find("```") {
                    return trimmed[end..end + code_end].trim().to_string();
                }
            }
        }

        if let Some(start) = trimmed.find("```") {
            if let Some(end) = trimmed[start + 3..].find("```") {
                let code_start = start + 3;
                // Skip language identifier if present
                let code = &trimmed[code_start..code_start + end];
                if let Some(newline) = code.find('\n') {
                    return code[newline..].trim().to_string();
                }
                return code.trim().to_string();
            }
        }

        // No code blocks found, return as-is
        trimmed.to_string()
    }
}