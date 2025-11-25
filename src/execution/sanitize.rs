use crate::{
    config::get_library_name,
    deopt::utils::get_file_dirname,
    feedback::clang_coverage::{
        utils::{dump_fuzzer_coverage, sanitize_by_fuzzer_coverage},
        CorporaFeatures, GlobalFeature,
    },
    program::{serde::Serialize, transform::Transformer, Program},
    Deopt,
};
use eyre::Result;
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use self::utils::cleanup_sanitize_dir;

use super::{
    ast::remove_duplicate_definition,
    logger::{ProgramError, TimeUsage},
    llm_repair::LLMRepair,
    Executor,
};

impl Executor {
    /// check whether the c program is syntactically and semantically correct.
    fn is_program_syntax_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        let time_logger = TimeUsage::new(get_file_dirname(program_path));
        let output: std::process::Output = Command::new("clang++")
            .stdout(Stdio::null())
            .arg("-fsyntax-only")
            .arg(&self.header_cmd)
            .arg(program_path.as_os_str())
            .output()
            .expect("failed to execute the syntax check process");
        time_logger.log("syntax")?;
        let success = output.status.success();
        if success {
            return Ok(None);
        }
        let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(Some(ProgramError::Syntax(err_msg)))
    }

    /// check whether the c program is syntactically correct, with LLM repair attempts
    fn is_program_syntax_correct_with_repair(
        &self,
        program_path: &Path,
        max_retries: usize,
    ) -> Result<Option<ProgramError>> {
        let mut current_attempt = 0;

        // Save original for potential restoration
        let original_code = std::fs::read_to_string(program_path)?;

        loop {
            let time_logger = TimeUsage::new(get_file_dirname(program_path));
            let output: std::process::Output = Command::new("clang++")
                .stdout(Stdio::null())
                .arg("-fsyntax-only")
                .arg(&self.header_cmd)
                .arg(program_path.as_os_str())
                .output()
                .expect("failed to execute the syntax check process");
            time_logger.log("syntax")?;

            let success = output.status.success();
            if success {
                if current_attempt > 0 {
                    log::info!("✓ Syntax FIXED after {} attempt(s) for {:?}",
                              current_attempt, program_path);
                    log::info!("Program {} was successfully repaired by LLM",
                              program_path.file_name().unwrap_or_default().to_string_lossy());
                }
                return Ok(None);
            }

            let err_msg = String::from_utf8_lossy(&output.stderr).to_string();

            // If we've exhausted retries, return the error
            if current_attempt >= max_retries {
                if max_retries > 0 {
                    log::warn!("✗ Failed to fix syntax after {} attempt(s) for {:?}",
                              max_retries, program_path);
                    // Restore original code since all repairs failed
                    std::fs::write(program_path, &original_code)?;
                }
                return Ok(Some(ProgramError::Syntax(err_msg)));
            }

            // Attempt to fix with LLM
            log::info!("🔧 Attempting LLM repair (attempt {}/{}) for {:?}",
                      current_attempt + 1, max_retries, program_path);
            log::info!("   Syntax error: {}", err_msg.lines().take(3).collect::<Vec<_>>().join(" | "));

            match LLMRepair::call_llm_to_fix_syntax(program_path, &err_msg) {
                Ok(fixed_code) => {
                    std::fs::write(program_path, &fixed_code)?;
                    current_attempt += 1;
                    log::info!("   LLM provided fix ({} bytes), retrying syntax check...", fixed_code.len());
                }
                Err(e) => {
                    log::error!("   LLM repair API call failed: {}", e);
                    std::fs::write(program_path, &original_code)?;
                    return Ok(Some(ProgramError::Syntax(format!(
                        "Original error: {}\nLLM repair failed: {}",
                        err_msg, e
                    ))));
                }
            }
        }
    }

    /// check whether the program is correct in compilation and linkage.
    fn is_program_link_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        let time_logger = TimeUsage::new(get_file_dirname(program_path));
        remove_duplicate_definition(program_path)?;
        let mut binary_out = PathBuf::from(program_path);
        binary_out.set_extension("out");

        let res = self.compile(vec![program_path], &binary_out, super::Compile::FUZZER);
        time_logger.log("link")?;

        if let Err(err) = res {
            let err_msg = err.to_string();
            return Ok(Some(ProgramError::Link(err_msg)));
        }
        Ok(None)
    }

    /// linked with AddressSanitizer, execute it to check whether code is correct.
    fn is_program_execute_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        let time_logger = TimeUsage::new(get_file_dirname(program_path));
        let mut transformer = Transformer::new(program_path, &self.deopt)?;
        transformer.add_fd_sanitizer()?;
        transformer.preprocess()?;

        let mut binary_out = PathBuf::from(program_path);
        binary_out.set_extension("out");

        self.deopt
            .copy_library_init_file(&get_file_dirname(program_path))?;

        self.compile(vec![program_path], &binary_out, super::Compile::FUZZER)?;

        let corpus = self.deopt.get_library_shared_corpus_dir()?;
        let has_err = self.execute_pool(&binary_out, &corpus);
        time_logger.log("execute")?;
        Ok(has_err)
    }

    /// linked with LibFuzzer and AddressSanitizer, to check whether code is correct.
    pub fn is_program_fuzz_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        log::trace!("test program is fuzz correct: {program_path:?}");
        let work_dir = get_file_dirname(program_path);
        let time_logger = TimeUsage::new(work_dir.clone());

        let binary_out = program_path.with_extension("out");

        let corpus_dir: PathBuf = [work_dir, "corpus".into()].iter().collect();
        crate::deopt::utils::create_dir_if_nonexist(&corpus_dir)?;

        let res = self.execute_fuzzer(
            &binary_out,
            vec![&corpus_dir, &self.deopt.get_library_shared_corpus_dir()?],
        );
        time_logger.log("fuzz")?;
        if let Err(err) = res {
            return Ok(Some(ProgramError::Fuzzer(err.to_string())));
        }
        Ok(None)
    }

    pub fn is_program_coverage_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        log::trace!("test program is coverage correct: {program_path:?}");
        let work_dir = get_file_dirname(program_path);
        let time_logger = TimeUsage::new(work_dir.clone());

        let fuzzer_binary = program_path.with_extension("cov.out");
        self.compile(vec![program_path], &fuzzer_binary, super::Compile::COVERAGE)?;

        let corpus_dir: PathBuf = [work_dir.clone(), "corpus".into()].iter().collect();
        let coverage = self.collect_code_coverage(
            Some(program_path),
            &fuzzer_binary,
            vec![&corpus_dir, &self.deopt.get_library_shared_corpus_dir()?],
        )?;

        let has_err = sanitize_by_fuzzer_coverage(program_path, &self.deopt, &coverage)?;
        time_logger.log("coverage")?;
        self.evolve_corpus(program_path)?;
        std::fs::remove_dir_all(corpus_dir)?;

        if !has_err {
            return Ok(None);
        }
        let err_msg = dump_fuzzer_coverage(&fuzzer_binary)?;
        Ok(Some(ProgramError::Coverage(format!("The program cannot cover the callees along the path that contains maximum callees.\n{err_msg}"))))
    }

    /// Original check without repair - KEEP THIS METHOD
    pub fn check_program_is_correct(&self, seed_path: &Path) -> Result<Option<ProgramError>> {
        if let Some(err) = self.is_program_syntax_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_link_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_execute_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_fuzz_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_coverage_correct(seed_path)? {
            return Ok(Some(err));
        }
        Ok(None)
    }

    /// Check with LLM repair for syntax errors
    pub fn check_program_is_correct_with_repair(
        &self,
        seed_path: &Path,
        max_syntax_retries: usize,
    ) -> Result<Option<ProgramError>> {
        // Try to fix syntax errors with LLM
        if let Some(err) = self.is_program_syntax_correct_with_repair(seed_path, max_syntax_retries)? {
            return Ok(Some(err));
        }

        // Continue with other checks (unchanged)
        if let Some(err) = self.is_program_link_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_execute_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_fuzz_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_coverage_correct(seed_path)? {
            return Ok(Some(err));
        }
        Ok(None)
    }

    /// Main entry point - decides whether to use repair based on environment variable
    pub fn check_programs_are_correct(
        &self,
        programs: &[Program],
        deopt: &Deopt,
    ) -> Result<Vec<Option<ProgramError>>> {
        let max_retries = std::env::var("LLM_REPAIR_RETRIES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        if max_retries > 0 {
            log::info!("LLM repair enabled with max {} retries", max_retries);
        }

        self.check_programs_are_correct_internal(programs, deopt, max_retries)
    }

    /// Internal implementation that handles both repair and non-repair paths
    fn check_programs_are_correct_internal(
        &self,
        programs: &[Program],
        deopt: &Deopt,
        max_syntax_retries: usize,
    ) -> Result<Vec<Option<ProgramError>>> {
        let mut program_paths = Vec::new();
        for program in programs.iter() {
            let temp_path = deopt.get_work_seed_by_id(program.id)?;
            let mut content = String::new();
            content.push_str(crate::deopt::utils::format_library_header_strings(deopt));
            content.push_str(&program.serialize());
            std::fs::write(&temp_path, content)?;
            program_paths.push(temp_path);
        }

        let res = if max_syntax_retries > 0 {
            self.concurrent_check_batch_with_repair(&program_paths, max_syntax_retries)?
        } else {
            self.concurrent_check_batch(&program_paths)?
        };

        utils::print_san_cost(&program_paths)?;

        // clean out the failure cache
        for (i, has_err) in res.iter().enumerate() {
            let path = &program_paths[i];
            let dir = get_file_dirname(path);
            cleanup_sanitize_dir(&dir)?;
            if let Some(err) = has_err {
                if let ProgramError::Hang(_) = err {
                    continue;
                }
                if let ProgramError::Fuzzer(_) = err {
                    continue;
                }
                std::fs::remove_dir_all(dir)?;
            }
        }
        Ok(res)
    }

    /// Non-repair batch checking - explicitly passes --max-retries 0
    pub fn concurrent_check_batch(
        &self,
        programs: &[PathBuf],
    ) -> Result<Vec<Option<ProgramError>>> {
        let mut childs = Vec::new();
        for program in programs {
            let child = Command::new("cargo")
                .env("RUST_BACKTRACE", "0")
                .env("RUST_LOG", "info")
                .arg("run")
                .arg("-q")
                .arg("--bin")
                .arg("harness")
                .arg("--")
                .arg(get_library_name())
                .arg("check")
                .arg(program)
                .arg("--max-retries")
                .arg("0")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to execute the concurrent transform process");
            childs.push(child);
        }

        let mut has_errs: Vec<Option<ProgramError>> = Vec::new();
        for (i, child) in childs.into_iter().enumerate() {
            let output = child.wait_with_output().expect("command wasn't running");
            let program = programs.get(i).unwrap();
            if !output.status.success() {
                let err_msg = String::from_utf8_lossy(&output.stderr).to_string();

                let mut parsed_err = None;
                for line in err_msg.lines().rev() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('{') && trimmed.ends_with('}') {
                        if let Ok(err) = serde_json::from_str::<ProgramError>(trimmed) {
                            parsed_err = Some(err);
                            break;
                        }
                    }
                }

                if let Some(err) = parsed_err {
                    has_errs.push(Some(err));
                } else {
                    log::warn!("Failed to parse error JSON for {:?}", program);
                    has_errs.push(Some(ProgramError::Fuzzer(err_msg)));
                }
                log::trace!("error: {program:?}");
            } else {
                has_errs.push(None);
                log::trace!("correct: {program:?}");
            }
        }
        Ok(has_errs)
    }

    /// Batch checking with LLM repair support
    pub fn concurrent_check_batch_with_repair(
        &self,
        programs: &[PathBuf],
        max_retries: usize,
    ) -> Result<Vec<Option<ProgramError>>> {
        let mut childs = Vec::new();
        for program in programs {
            let child = Command::new("cargo")
                .env("RUST_BACKTRACE", "0")
                .env("RUST_LOG", "info")
                .arg("run")
                .arg("-q")
                .arg("--bin")
                .arg("harness")
                .arg("--")
                .arg(get_library_name())
                .arg("check")
                .arg(program)
                .arg("--max-retries")
                .arg(max_retries.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to execute the concurrent transform process");
            childs.push(child);
        }

        let mut has_errs: Vec<Option<ProgramError>> = Vec::new();
        for (i, child) in childs.into_iter().enumerate() {
            let output = child.wait_with_output().expect("command wasn't running");
            let program = programs.get(i).unwrap();
            if !output.status.success() {
                let err_msg = String::from_utf8_lossy(&output.stderr).to_string();

                let mut parsed_err = None;
                for line in err_msg.lines().rev() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('{') && trimmed.ends_with('}') {
                        if let Ok(err) = serde_json::from_str::<ProgramError>(trimmed) {
                            parsed_err = Some(err);
                            break;
                        }
                    }
                }

                if let Some(err) = parsed_err {
                    has_errs.push(Some(err));
                } else {
                    log::warn!("Failed to parse error JSON for {:?}", program);
                    has_errs.push(Some(ProgramError::Fuzzer(err_msg)));
                }
                log::trace!("error: {program:?}");
            } else {
                has_errs.push(None);
                log::trace!("correct: {program:?}");
            }
        }
        Ok(has_errs)
    }

    // Evolving the fuzzing corpus
    fn evolve_corpus(&self, program_path: &Path) -> Result<()> {
        log::debug!("Evolve fuzzing corpus by merge new coverage corpora");
        let work_dir = crate::deopt::utils::get_file_dirname(program_path);
        let time_logger = TimeUsage::new(work_dir.clone());
        let fuzzer_binary = program_path.with_extension("evo.out");
        self.compile(vec![program_path], &fuzzer_binary, super::Compile::Minimize)?;

        let global_feature_file = self.deopt.get_library_global_feature_file()?;
        let mut global_featuers: GlobalFeature = if global_feature_file.exists() {
            let buf = std::fs::read(&global_feature_file)?;
            serde_json::from_slice(&buf)?
        } else {
            GlobalFeature::init_by_corpus(self, &fuzzer_binary)?
        };

        let corpus: PathBuf = [work_dir.clone(), "corpus".into()].iter().collect();
        let control_file: PathBuf = [work_dir, "merge_control_file".into()].iter().collect();
        self.minimize_by_control_file(&fuzzer_binary, &corpus, &control_file)?;

        if !control_file.exists() {
            panic!("{control_file:?} does not exist!");
        }

        let corpora_features = CorporaFeatures::parse(&control_file)?;
        let corpus_size = corpora_features.get_size();
        let mut intrestings = Vec::new();

        for i in 0..corpus_size {
            let mut has_new = false;
            let features = corpora_features.get_nth_feature(i);
            for fe in features {
                if global_featuers.insert_feature(*fe) {
                    has_new = true;
                }
            }
            if has_new {
                intrestings.push(corpora_features.get_nth_file(i));
            }
        }
        self.deopt.copy_file_to_shared_corpus(intrestings)?;
        let buf = serde_json::to_vec(&global_featuers)?;
        std::fs::write(global_feature_file, buf)?;
        std::fs::remove_file(control_file)?;
        time_logger.log("update")?;
        Ok(())
    }

    /// Original recheck without repair - KEEP THIS METHOD
    pub fn recheck_seed(&mut self, deopt: &mut Deopt) -> Result<()> {
        log::info!("Recheck the saved seeds and remove the error programs within them.");
        let succ_seed_dir = self.deopt.get_library_succ_seed_dir()?;
        let succ_seeds = crate::deopt::utils::read_sort_dir(&succ_seed_dir)?;
        for succ_seed in &succ_seeds {
            let seed_program = Program::load_from_path(succ_seed)?;
            let seed_id = seed_program.id;
            self.compile_seed(seed_id)?;
            let corpus = self.deopt.get_library_shared_corpus_dir()?;
            let work_seed_path = self.deopt.get_work_seed_by_id(seed_id)?;
            let binary_out = work_seed_path.with_extension("out");
            let has_err = self.execute_pool(&binary_out, &corpus);
            if let Some(err_msg) = has_err {
                log::warn!("seed: {} is rechecked as Error!", seed_id);
                let seed = self.deopt.get_seed_path_by_id(seed_id)?;
                self.deopt.save_err_program(&seed_program, &err_msg)?;
                std::fs::remove_file(succ_seed)?;
                if seed.exists() {
                    std::fs::remove_file(seed)?;
                    deopt.delete_seed_from_queue(&seed_program);
                }
            }
        }
        Ok(())
    }

    /// Recheck with repair support
    pub fn recheck_seed_with_repair(&mut self, deopt: &mut Deopt, max_retries: usize) -> Result<()> {
        log::info!("Recheck the saved seeds and remove the error programs within them.");
        let succ_seed_dir = self.deopt.get_library_succ_seed_dir()?;
        let succ_seeds = crate::deopt::utils::read_sort_dir(&succ_seed_dir)?;
        for succ_seed in &succ_seeds {
            let seed_program = Program::load_from_path(succ_seed)?;
            let seed_id = seed_program.id;
            self.compile_seed(seed_id)?;

            let corpus = self.deopt.get_library_shared_corpus_dir()?;
            let work_seed_path = self.deopt.get_work_seed_by_id(seed_id)?;

            // Try to fix syntax if needed
            if let Some(ProgramError::Syntax(_)) = self.is_program_syntax_correct_with_repair(&work_seed_path, max_retries)? {
                log::warn!("seed: {} has unfixable syntax errors during recheck!", seed_id);
                let seed = self.deopt.get_seed_path_by_id(seed_id)?;
                self.deopt.save_err_program(&seed_program, &ProgramError::Syntax("Unfixable during recheck".to_string()))?;
                std::fs::remove_file(succ_seed)?;
                if seed.exists() {
                    std::fs::remove_file(seed)?;
                    deopt.delete_seed_from_queue(&seed_program);
                }
                continue;
            }

            let binary_out = work_seed_path.with_extension("out");
            let has_err = self.execute_pool(&binary_out, &corpus);
            if let Some(err_msg) = has_err {
                log::warn!("seed: {} is rechecked as Error!", seed_id);
                let seed = self.deopt.get_seed_path_by_id(seed_id)?;
                self.deopt.save_err_program(&seed_program, &err_msg)?;
                std::fs::remove_file(succ_seed)?;
                if seed.exists() {
                    std::fs::remove_file(seed)?;
                    deopt.delete_seed_from_queue(&seed_program);
                }
            }
        }
        Ok(())
    }
}

// Keep the utils module and tests as they were...
pub mod utils {
    use crate::execution::logger::get_gtl_mut;
    use super::*;

    pub fn print_san_cost(program_paths: &Vec<PathBuf>) -> Result<()> {
        let mut max_time = 0_f32;
        let mut usage = Vec::new();
        for program_path in program_paths {
            let program_dir = get_file_dirname(program_path);
            let time_logger = TimeUsage::new(program_dir);

            let syntax = time_logger.load("syntax")?;
            let link = time_logger.load("link")?;
            let execution = time_logger.load("execute")?;
            let fuzz = time_logger.load("fuzz")?;
            let coverage = time_logger.load("coverage")?;
            let update = time_logger.load("update")?;
            let total = syntax + link + execution + fuzz + coverage + update;
            usage.push(syntax);
            usage.push(link);
            usage.push(execution);
            usage.push(fuzz);
            usage.push(coverage);
            usage.push(update);
            if total > max_time {
                max_time = total;
                usage.clear();
                usage.push(syntax);
                usage.push(link);
                usage.push(execution);
                usage.push(fuzz);
                usage.push(coverage);
                usage.push(update);
            }
        }
        log::debug!("This round's sanitization Time Cost: total: {max_time}s, syntax: {}s, link: {}s, exec: {}s, fuzz: {}s, coverage: {}s, update: {}s", usage[0], usage[1], usage[2], usage[3], usage[4], usage[5]);
        get_gtl_mut().inc_san(usage[0], usage[1], usage[2], usage[3], usage[4], usage[5]);
        Ok(())
    }

    pub fn cleanup_sanitize_dir(sanitize_dir: &Path) -> Result<()> {
        let files = crate::deopt::utils::read_sort_dir(sanitize_dir)?;
        for file in files {
            if let Some(ext) = file.extension() {
                if ext == "log" || ext == "out" || ext == "cc" || ext == "profdata" || ext == "cost"
                {
                    continue;
                }
            }
            if file.is_dir() {
                std::fs::remove_dir_all(file)?;
            } else {
                std::fs::remove_file(file)?
            }
        }
        Ok(())
    }
}