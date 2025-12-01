use eyre::Result;
use std::path::Path;
use std::process::{Command, Stdio};

pub struct LLMRepair;

impl LLMRepair {
    /// Call LLM API to fix syntax errors
    pub fn call_llm_to_fix_syntax(program_path: &Path, error_message: &str) -> Result<String> {
        let original_code = std::fs::read_to_string(program_path)?;

        // Check if code is too long (rough estimate: 4 chars per token, leave room for prompt)
        const MAX_CODE_CHARS: usize = 20000; // ~5000 tokens for code
        if original_code.len() > MAX_CODE_CHARS {
            return Err(eyre::eyre!(
                "Code too long for LLM repair ({} chars, max {}). Skipping repair.",
                original_code.len(),
                MAX_CODE_CHARS
            ));
        }

        // Check if the code looks like garbage (high ratio of non-ASCII)
        let non_ascii_count = original_code.chars().filter(|c| !c.is_ascii()).count();
        let total_chars = original_code.chars().count();
        if total_chars > 0 {
            let ascii_ratio = 1.0 - (non_ascii_count as f64 / total_chars as f64);
            if ascii_ratio < 0.7 {
                return Err(eyre::eyre!(
                    "Code appears to be mostly non-ASCII garbage ({:.1}% ASCII). Skipping repair.",
                    ascii_ratio * 100.0
                ));
            }
        }

        // Truncate error message if too long
        let error_message = if error_message.len() > 2000 {
            format!(
                "{}...\n[truncated, {} more chars]",
                &error_message[..2000],
                error_message.len() - 2000
            )
        } else {
            error_message.to_string()
        };

        log::debug!(
            "Attempting to fix code ({} chars)",
            original_code.len()
        );

        let prompt = format!(
            "The following C++ fuzzer code has a syntax error. Please fix it and return ONLY the corrected code without any explanation, comments, or markdown formatting.\n\n\
            Syntax Error:\n{}\n\n\
            Code to fix:\n{}\n\n\
            Return ONLY the complete fixed C++ code.",
            error_message, original_code
        );

        // Get API key from environment
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .map_err(|_| {
                eyre::eyre!("No API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY")
            })?;

        // Determine which API to use based on which key is set
        let fixed_code = if std::env::var("ANTHROPIC_API_KEY").is_ok() {
            Self::call_claude_api(&prompt, &api_key)?
        } else {
            Self::call_openai_api(&prompt, &api_key)?
        };

        // Validate that we got something reasonable
        if fixed_code.trim().is_empty() {
            return Err(eyre::eyre!("LLM returned empty response"));
        }

        // Basic sanity check - should contain some C++ indicators
        if !fixed_code.contains("LLVMFuzzerTestOneInput")
            && original_code.contains("LLVMFuzzerTestOneInput")
        {
            log::warn!("Fixed code is missing LLVMFuzzerTestOneInput - may be invalid");
        }

        log::debug!("LLM returned fixed code ({} chars)", fixed_code.len());

        Ok(fixed_code)
    }

    /// Call Claude API with timeout
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
            .arg("--max-time")
            .arg("120") // 120 second timeout
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

        // Check for API errors in response
        if response_text.contains("\"error\"") {
            return Err(eyre::eyre!("Claude API error: {}", response_text));
        }

        let data: serde_json::Value = serde_json::from_str(&response_text).map_err(|e| {
            eyre::eyre!(
                "Failed to parse Claude response: {} - Response: {}",
                e,
                response_text
            )
        })?;

        let fixed_code = data["content"][0]["text"]
            .as_str()
            .ok_or_else(|| {
                eyre::eyre!(
                    "Failed to extract code from Claude response: {}",
                    response_text
                )
            })?
            .to_string();

        Ok(Self::extract_code_from_response(&fixed_code))
    }

    /// Call OpenAI API with timeout
    fn call_openai_api(prompt: &str, api_key: &str) -> Result<String> {
        let request_body = serde_json::json!({
            "model": "gpt-4o",  // Use gpt-4o for 128k context window
            "messages": [{
                "role": "user",
                "content": prompt
            }],
            "temperature": 0.3
        });

        let output = Command::new("curl")
            .arg("-s")
            .arg("--max-time")
            .arg("120") // 120 second timeout
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

        // Check for API errors
        if response_text.contains("\"error\"") {
            return Err(eyre::eyre!("OpenAI API error: {}", response_text));
        }

        let data: serde_json::Value = serde_json::from_str(&response_text).map_err(|e| {
            eyre::eyre!(
                "Failed to parse OpenAI response: {} - Response: {}",
                e,
                response_text
            )
        })?;

        let fixed_code = data["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| {
                eyre::eyre!(
                    "Failed to extract code from OpenAI response: {}",
                    response_text
                )
            })?
            .to_string();

        Ok(Self::extract_code_from_response(&fixed_code))
    }

    /// Extract code from LLM response, removing markdown formatting
    fn extract_code_from_response(response: &str) -> String {
        let trimmed = response.trim();

        // Try to extract from ```cpp code blocks
        if let Some(start) = trimmed.find("```cpp") {
            let code_start = start + 6; // Skip "```cpp"
            if let Some(end) = trimmed[code_start..].find("```") {
                return trimmed[code_start..code_start + end].trim().to_string();
            }
        }

        // Try to extract from ```c++ code blocks
        if let Some(start) = trimmed.find("```c++") {
            let code_start = start + 6; // Skip "```c++"
            if let Some(end) = trimmed[code_start..].find("```") {
                return trimmed[code_start..code_start + end].trim().to_string();
            }
        }

        // Try to extract from generic ``` code blocks
        if let Some(start) = trimmed.find("```") {
            let after_backticks = start + 3;
            // Skip language identifier (if any) by finding next newline
            let code_start = if let Some(newline_offset) = trimmed[after_backticks..].find('\n') {
                after_backticks + newline_offset + 1
            } else {
                after_backticks
            };

            if let Some(end) = trimmed[code_start..].find("```") {
                return trimmed[code_start..code_start + end].trim().to_string();
            }
        }

        // No code blocks found, return as-is (might be raw code)
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_code_cpp_block() {
        let response =
            "Here's the fix:\n```cpp\nint main() {\n    return 0;\n}\n```\nThis should work.";
        let extracted = LLMRepair::extract_code_from_response(response);
        assert_eq!(extracted, "int main() {\n    return 0;\n}");
    }

    #[test]
    fn test_extract_code_generic_block() {
        let response = "```\nint main() { return 0; }\n```";
        let extracted = LLMRepair::extract_code_from_response(response);
        assert_eq!(extracted, "int main() { return 0; }");
    }

    #[test]
    fn test_extract_code_no_block() {
        let response = "int main() { return 0; }";
        let extracted = LLMRepair::extract_code_from_response(response);
        assert_eq!(extracted, "int main() { return 0; }");
    }

    #[test]
    fn test_extract_code_with_language() {
        let response = "```c\nint main() { return 0; }\n```";
        let extracted = LLMRepair::extract_code_from_response(response);
        assert_eq!(extracted, "int main() { return 0; }");
    }
}
