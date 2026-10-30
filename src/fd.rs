//! Provision descriptors for admitted inbound sockets and their upstream counterparts.
//! The reserve covers listeners, local health, the fixed-origin API and runtime files.

use libc::rlim_t;

const HEADROOM: rlim_t = 128;

#[derive(Debug, PartialEq, Eq)]
pub struct Limits {
    pub previous_soft: rlim_t,
    pub soft: rlim_t,
    pub required: rlim_t,
}

fn plan(max_connections: usize, soft: rlim_t, hard: rlim_t) -> Result<Limits, String> {
    let required = rlim_t::try_from(max_connections)
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(HEADROOM))
        .ok_or("GATEWAY_MAX_CONNECTIONS overflows the file descriptor budget")?;
    if hard < required {
        return Err(format!(
            "GATEWAY_MAX_CONNECTIONS={max_connections} requires RLIMIT_NOFILE >= {required} \
             (two sockets per connection plus {HEADROOM} reserve), but the hard limit is {hard}; \
             raise the container's hard nofile limit or lower GATEWAY_MAX_CONNECTIONS"
        ));
    }
    let target = if soft >= required {
        soft
    } else {
        required
            .checked_next_power_of_two()
            .unwrap_or(hard)
            .min(hard)
    };
    Ok(Limits {
        previous_soft: soft,
        soft: target,
        required,
    })
}

/// Raise only the soft limit, never the hard limit. Call before accepting clients.
pub fn ensure(max_connections: usize) -> Result<Limits, String> {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: current points to a writable rlimit for the duration of this call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) } != 0 {
        return Err(format!(
            "reading RLIMIT_NOFILE: {}",
            std::io::Error::last_os_error()
        ));
    }
    let limits = plan(max_connections, current.rlim_cur, current.rlim_max)?;
    if limits.soft != limits.previous_soft {
        current.rlim_cur = limits.soft;
        // SAFETY: current is initialized; its unchanged hard limit bounds the new soft limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &current) } != 0 {
            return Err(format!(
                "raising RLIMIT_NOFILE from {} to {} (required {}): {}",
                limits.previous_soft,
                limits.soft,
                limits.required,
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_plan_respects_existing_and_hard_limits() {
        let raised = plan(1024, 1024, 4096).unwrap();
        assert_eq!(
            (raised.previous_soft, raised.soft, raised.required),
            (1024, 4096, 2176)
        );
        assert_eq!(plan(1024, 8192, 8192).unwrap().soft, 8192);
        assert_eq!(plan(1024, 1024, 2200).unwrap().soft, 2200);
        assert_eq!(plan(1024, 2176, 2176).unwrap().soft, 2176);
        assert!(
            plan(1024, 1024, 1024)
                .unwrap_err()
                .contains("hard limit is 1024")
        );
        assert!(plan(usize::MAX, 1024, rlim_t::MAX).is_err());
    }
}
