//! # Contract State Size Limits
//!
//! This module enforces upper-bound limits on the size of unbounded collections
//! stored in contract state to prevent:
//!
//! - **DoS via state bloat**: an attacker flooding the contributors or roadmap
//!   lists until operations become too expensive to execute.
//! - **Gas exhaustion**: iteration over an unbounded `Vec` in `withdraw`,
//!   `refund`, or `collect_pledges` can exceed Soroban resource limits.
//! - **Ledger entry size violations**: Soroban enforces a hard cap on the
//!   serialised size of each ledger entry; exceeding it causes a host panic.
//!
//! ## Security Assumptions
//!
//! 1. `MAX_CONTRIBUTORS` caps the `Contributors` and `Pledgers` persistent
//!    lists.  Any `contribute` or `pledge` call that would push the list past
//!    this limit is rejected with [`ContractError::StateSizeLimitExceeded`].
//! 2. `MAX_ROADMAP_ITEMS` caps the `Roadmap` instance list.
//! 3. `MAX_STRING_LEN` caps every user-supplied `String` field (title,
//!    description, social links, roadmap description) to prevent oversized
//!    ledger entries.
//! 4. `MAX_STRETCH_GOALS` caps the `StretchGoals` list.
//!
//! ## Limits (rationale)
//!
//! | Constant              | Value | Rationale                                      |
//! |-----------------------|-------|------------------------------------------------|
//! | `MAX_CONTRIBUTORS`    | 1 000 | Keeps `withdraw` / `refund` batch within gas   |
//! | `MAX_ROADMAP_ITEMS`   |    20 | Cosmetic list; no operational iteration needed |
//! | `MAX_STRETCH_GOALS`   |    10 | Small advisory list                            |
//! | `MAX_STRING_LEN`      |   256 | Prevents oversized instance-storage entries    |

#![allow(missing_docs)]

use soroban_sdk::{contracterror, Env, String, Vec};

use crate::DataKey;

// ── Limits ───────────────────────────────────────────────────────────────────

/// Maximum number of unique contributors (and pledgers) tracked on-chain.
pub const MAX_CONTRIBUTORS: u32 = 1_000;

/// Maximum number of unique pledgers tracked on-chain.
pub const MAX_PLEDGERS: u32 = 1_000;

/// Maximum number of roadmap items stored in instance storage.
pub const MAX_ROADMAP_ITEMS: u32 = 20;

/// Maximum number of stretch-goal milestones.
pub const MAX_STRETCH_GOALS: u32 = 10;

/// Maximum byte length of any user-supplied `String` field.
pub const MAX_STRING_LEN: u32 = 256;

/// Maximum byte length of title field.
pub const MAX_TITLE_LENGTH: u32 = 100;

/// Maximum byte length of description field.
pub const MAX_DESCRIPTION_LENGTH: u32 = 2000;

/// Maximum byte length of bonus goal description field.
pub const MAX_BONUS_GOAL_DESCRIPTION_LENGTH: u32 = 500;

/// Maximum byte length of roadmap description field.
pub const MAX_ROADMAP_DESCRIPTION_LENGTH: u32 = 500;

/// Maximum byte length of social links field.
pub const MAX_SOCIAL_LINKS_LENGTH: u32 = 300;

/// Maximum total byte length of all metadata fields combined.
pub const MAX_METADATA_TOTAL_LENGTH: u32 = 4000;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Returned when a state-size limit would be exceeded.
///
/// @notice Callers should treat this as a permanent rejection for the current
///         campaign state; the limit will not change without a contract upgrade.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum StateSizeError {
    /// The contributors / pledgers list is full.
    ContributorLimitExceeded = 100,
    /// The roadmap list is full.
    RoadmapLimitExceeded = 101,
    /// The stretch-goals list is full.
    StretchGoalLimitExceeded = 102,
    /// A string field exceeds `MAX_STRING_LEN` bytes.
    StringTooLong = 103,
}

// ── Validation helpers ────────────────────────────────────────────────────────

/// Assert that `s` does not exceed [`MAX_STRING_LEN`] bytes.
///
/// @param s The string to validate.
/// @return `Ok(())` when within limits, `Err(StateSizeError::StringTooLong)` otherwise.
pub fn check_string_len(s: &String) -> Result<(), StateSizeError> {
    if s.len() > MAX_STRING_LEN {
        return Err(StateSizeError::StringTooLong);
    }
    Ok(())
}

/// Assert that adding one more entry to the `Contributors` list is allowed.
///
/// Reads the current list length from persistent storage and compares it
/// against [`MAX_CONTRIBUTORS`].
///
/// @param env Soroban environment reference.
/// @return `Ok(())` when within limits, `Err(StateSizeError::ContributorLimitExceeded)` otherwise.
pub fn check_contributor_limit(env: &Env) -> Result<(), StateSizeError> {
    let contributors: Vec<soroban_sdk::Address> = env
        .storage()
        .persistent()
        .get(&DataKey::Contributors)
        .unwrap_or_else(|| Vec::new(env));

    if contributors.len() >= MAX_CONTRIBUTORS {
        return Err(StateSizeError::ContributorLimitExceeded);
    }
    Ok(())
}

/// Assert that adding one more entry to the `Pledgers` list is allowed.
///
/// @param env Soroban environment reference.
/// @return `Ok(())` when within limits, `Err(StateSizeError::ContributorLimitExceeded)` otherwise.
pub fn check_pledger_limit(env: &Env) -> Result<(), StateSizeError> {
    let pledgers: Vec<soroban_sdk::Address> = env
        .storage()
        .persistent()
        .get(&DataKey::Pledgers)
        .unwrap_or_else(|| Vec::new(env));

    if pledgers.len() >= MAX_PLEDGERS {
        return Err(StateSizeError::ContributorLimitExceeded);
    }
    Ok(())
}

/// Assert that adding one more item to the `Roadmap` list is allowed.
///
/// @param env Soroban environment reference.
/// @return `Ok(())` when within limits, `Err(StateSizeError::RoadmapLimitExceeded)` otherwise.
pub fn check_roadmap_limit(env: &Env) -> Result<(), StateSizeError> {
    let roadmap: Vec<crate::RoadmapItem> = env
        .storage()
        .instance()
        .get(&DataKey::Roadmap)
        .unwrap_or_else(|| Vec::new(env));

    if roadmap.len() >= MAX_ROADMAP_ITEMS {
        return Err(StateSizeError::RoadmapLimitExceeded);
    }
    Ok(())
}

/// Assert that adding one more stretch goal is allowed.
///
/// @param env Soroban environment reference.
/// @return `Ok(())` when within limits, `Err(StateSizeError::StretchGoalLimitExceeded)` otherwise.
pub fn check_stretch_goal_limit(env: &Env) -> Result<(), StateSizeError> {
    let goals: Vec<i128> = env
        .storage()
        .instance()
        .get(&DataKey::StretchGoals)
        .unwrap_or_else(|| Vec::new(env));

    if goals.len() >= MAX_STRETCH_GOALS {
        return Err(StateSizeError::StretchGoalLimitExceeded);
    }
    Ok(())
}

// ── Compatibility wrappers for existing code ──────────────────────────────────

/// Validate contributor capacity (alias for check_contributor_limit).
#[inline]
pub fn validate_contributor_capacity(capacity: u32) -> Result<(), StateSizeError> {
    if capacity >= MAX_CONTRIBUTORS {
        return Err(StateSizeError::ContributorLimitExceeded);
    }
    Ok(())
}

/// Validate pledger capacity (alias for check_pledger_limit).
#[inline]
pub fn validate_pledger_capacity(capacity: u32) -> Result<(), StateSizeError> {
    if capacity >= MAX_PLEDGERS {
        return Err(StateSizeError::ContributorLimitExceeded);
    }
    Ok(())
}

/// Validate roadmap capacity.
#[inline]
pub fn validate_roadmap_capacity(capacity: u32) -> Result<(), StateSizeError> {
    if capacity >= MAX_ROADMAP_ITEMS {
        return Err(StateSizeError::RoadmapLimitExceeded);
    }
    Ok(())
}

/// Validate stretch goal capacity.
#[inline]
pub fn validate_stretch_goal_capacity(capacity: u32) -> Result<(), StateSizeError> {
    if capacity >= MAX_STRETCH_GOALS {
        return Err(StateSizeError::StretchGoalLimitExceeded);
    }
    Ok(())
}

/// Validate title length.
#[inline]
pub fn validate_title(title: &String) -> Result<(), StateSizeError> {
    if title.len() > MAX_TITLE_LENGTH {
        return Err(StateSizeError::StringTooLong);
    }
    Ok(())
}

/// Validate description length.
#[inline]
pub fn validate_description(description: &String) -> Result<(), StateSizeError> {
    if description.len() > MAX_DESCRIPTION_LENGTH {
        return Err(StateSizeError::StringTooLong);
    }
    Ok(())
}

/// Validate social links length.
#[inline]
pub fn validate_social_links(socials: &String) -> Result<(), StateSizeError> {
    if socials.len() > MAX_SOCIAL_LINKS_LENGTH {
        return Err(StateSizeError::StringTooLong);
    }
    Ok(())
}

/// Validate bonus goal description length.
#[inline]
pub fn validate_bonus_goal_description(description: &String) -> Result<(), StateSizeError> {
    if description.len() > MAX_BONUS_GOAL_DESCRIPTION_LENGTH {
        return Err(StateSizeError::StringTooLong);
    }
    Ok(())
}

/// Validate roadmap description length.
#[inline]
pub fn validate_roadmap_description(description: &String) -> Result<(), StateSizeError> {
    if description.len() > MAX_ROADMAP_DESCRIPTION_LENGTH {
        return Err(StateSizeError::StringTooLong);
    }
    Ok(())
}

/// Validate metadata total length.
#[inline]
pub fn validate_metadata_total_length(title_len: u32, desc_len: u32, social_len: u32) -> Result<(), StateSizeError> {
    let total = title_len.saturating_add(desc_len).saturating_add(social_len);
    if total > MAX_METADATA_TOTAL_LENGTH {
        return Err(StateSizeError::StringTooLong);
    }
    Ok(())
}
