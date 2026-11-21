//! Minimal RFC 3339 handling for npm publish timestamps.
//!
//! npm always emits UTC timestamps such as `2024-01-02T03:04:05.678Z`. Rather
//! than pull a date crate for two arithmetic operations, this module parses
//! exactly that shape (plus numeric offsets) and converts to Unix seconds.

pub const SECONDS_PER_DAY: i64 = 86_400;

/// Parses `YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)` into Unix seconds.
///
/// Returns `None` for anything it does not fully understand, so callers can
/// drop the signal instead of crashing on surprising registry data.
pub fn parse_timestamp(input: &str) -> Option<i64> {
    let bytes = input.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year = digits(&bytes[0..4])?;
    let month = digits(&bytes[5..7])?;
    let day = digits(&bytes[8..10])?;
    let hour = digits(&bytes[11..13])?;
    let minute = digits(&bytes[14..16])?;
    let second = digits(&bytes[17..19])?;

    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start {
            return None;
        }
    }

    let offset_seconds = match bytes.get(index)? {
        b'Z' if index + 1 == bytes.len() => 0,
        b'+' | b'-' => parse_offset(&input[index..])?,
        _ => return None,
    };
    let sign = if bytes[index] == b'-' { -1 } else { 1 };
    let offset = if bytes[index] == b'Z' {
        0
    } else {
        sign * offset_seconds
    };

    let days = days_from_civil(year, month, day);
    Some(days * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second - offset)
}

/// Whole days from `earlier` to `later`, rounding down.
pub fn days_between(earlier: i64, later: i64) -> i64 {
    (later - earlier).div_euclid(SECONDS_PER_DAY)
}

/// Formats Unix seconds as `YYYY-MM-DD` in UTC.
pub fn format_date(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn digits(slice: &[u8]) -> Option<i64> {
    let mut value = 0i64;
    for byte in slice {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Some(value)
}

/// `+HH:MM` or `-HH:MM`, returning the absolute offset in seconds.
fn parse_offset(input: &str) -> Option<i64> {
    let bytes = input.as_bytes();
    if bytes.len() != 6 || bytes[3] != b':' {
        return None;
    }
    let hours = digits(&bytes[1..3])?;
    let minutes = digits(&bytes[4..6])?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(hours * 3600 + minutes * 60)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Howard Hinnant's days-from-civil algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_epoch() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00.000Z"), Some(0));
    }

    #[test]
    fn parses_known_instant() {
        assert_eq!(
            parse_timestamp("2024-02-29T12:34:56.789Z"),
            Some(1_709_210_096)
        );
    }

    #[test]
    fn parses_positive_offset() {
        assert_eq!(
            parse_timestamp("2024-01-01T02:00:00+02:00"),
            Some(parse_timestamp("2024-01-01T00:00:00Z").unwrap())
        );
    }

    #[test]
    fn parses_negative_offset() {
        assert_eq!(
            parse_timestamp("2023-12-31T22:00:00-02:00"),
            Some(parse_timestamp("2024-01-01T00:00:00Z").unwrap())
        );
    }

    #[test]
    fn rejects_malformed_timestamps() {
        for input in [
            "",
            "not-a-date",
            "2024-13-01T00:00:00Z",
            "2024-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:60:00Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01T00:00:00",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00+2:00",
            "2024-01-01 00:00:00Z",
        ] {
            assert_eq!(parse_timestamp(input), None, "accepted {input:?}");
        }
    }

    #[test]
    fn handles_leap_years() {
        assert_eq!(
            days_between(
                parse_timestamp("2024-02-28T00:00:00Z").unwrap(),
                parse_timestamp("2024-03-01T00:00:00Z").unwrap(),
            ),
            2
        );
        assert_eq!(
            days_between(
                parse_timestamp("2023-02-28T00:00:00Z").unwrap(),
                parse_timestamp("2023-03-01T00:00:00Z").unwrap(),
            ),
            1
        );
    }

    #[test]
    fn rounds_partial_days_down() {
        let start = parse_timestamp("2024-01-01T00:00:00Z").unwrap();
        assert_eq!(days_between(start, start + 86_399), 0);
        assert_eq!(days_between(start, start + 86_400), 1);
        assert_eq!(days_between(start, start - 1), -1);
    }

    #[test]
    fn formats_dates() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(
            format_date(parse_timestamp("2024-02-29T23:59:59Z").unwrap()),
            "2024-02-29"
        );
        assert_eq!(
            format_date(parse_timestamp("1969-12-31T23:00:00Z").unwrap()),
            "1969-12-31"
        );
    }
}
