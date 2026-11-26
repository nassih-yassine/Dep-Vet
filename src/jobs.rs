//! How many audits run at once.
//!
//! One place decides it so `audit`, `lock`, `guard`, `watch`, and the MCP
//! lockfile diff agree, and so a bad value fails before any request is made.

/// More than this hammers registries and the SQLite cache without adding
/// throughput on a latency-bound workload.
pub const MAX_JOBS: usize = 32;

/// Default when neither the flag nor the environment says otherwise.
pub const DEFAULT_JOBS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum JobError {
    Zero,
    TooLarge(usize),
    NotANumber(String),
}

impl std::fmt::Display for JobError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zero => write!(formatter, "jobs must be at least 1"),
            Self::TooLarge(value) => {
                write!(formatter, "jobs is capped at {MAX_JOBS}; got {value}")
            }
            Self::NotANumber(value) => {
                write!(formatter, "DEPVET_JOBS is not a number: {value}")
            }
        }
    }
}

impl std::error::Error for JobError {}

/// `--jobs` wins over `DEPVET_JOBS`, which wins over the default. The default
/// is the machine's parallelism up to eight: eight independent HTTP fetches
/// already saturate the registries' comfortable rate.
pub fn resolve(
    flag: Option<usize>,
    env: Option<&str>,
    available_parallelism: usize,
) -> Result<usize, JobError> {
    let requested = match flag {
        Some(value) => value,
        None => match env {
            Some(raw) => raw
                .trim()
                .parse()
                .map_err(|_| JobError::NotANumber(raw.to_string()))?,
            None => return Ok(available_parallelism.clamp(1, DEFAULT_JOBS)),
        },
    };
    match requested {
        0 => Err(JobError::Zero),
        value if value > MAX_JOBS => Err(JobError::TooLarge(value)),
        value => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_the_machines_parallelism_up_to_eight() {
        assert_eq!(resolve(None, None, 16), Ok(8));
        assert_eq!(resolve(None, None, 3), Ok(3));
        assert_eq!(resolve(None, None, 0), Ok(1), "never zero workers");
    }

    #[test]
    fn the_environment_overrides_the_default_and_the_flag_overrides_both() {
        assert_eq!(resolve(None, Some("3"), 16), Ok(3));
        assert_eq!(resolve(Some(12), Some("3"), 16), Ok(12));
        assert_eq!(resolve(None, Some(" 4 "), 16), Ok(4));
    }

    #[test]
    fn a_zero_or_oversized_value_is_an_error_not_a_clamp() {
        assert_eq!(resolve(Some(0), None, 16), Err(JobError::Zero));
        assert_eq!(resolve(None, Some("0"), 16), Err(JobError::Zero));
        assert_eq!(resolve(Some(33), None, 16), Err(JobError::TooLarge(33)));
        assert_eq!(resolve(None, Some("64"), 16), Err(JobError::TooLarge(64)));
    }

    #[test]
    fn a_non_number_names_the_variable() {
        assert_eq!(
            resolve(None, Some("many"), 16),
            Err(JobError::NotANumber("many".to_string()))
        );
        assert!(
            JobError::NotANumber("many".into())
                .to_string()
                .contains("DEPVET_JOBS")
        );
    }

    #[test]
    fn the_cap_is_inclusive() {
        assert_eq!(resolve(Some(MAX_JOBS), None, 16), Ok(MAX_JOBS));
    }
}
