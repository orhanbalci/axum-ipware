//! Country and ASN rules from MaxMind databases. Requires the `geo` feature.
//!
//! ```rust,no_run
//! use axum_ipware::geo::GeoDb;
//! use axum_ipware::IpFilter;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let geo = GeoDb::new()
//!     .country_database("/var/lib/GeoIP/GeoLite2-Country.mmdb")?
//!     .asn_database("/var/lib/GeoIP/GeoLite2-ASN.mmdb")?;
//!
//! let filter = IpFilter::new()
//!     .geo(geo)
//!     .block_countries(["KP"])?
//!     .block_asns([64496]);
//! # Ok(())
//! # }
//! ```
//!
//! Country rules use the country MaxMind locates the IP in, falling back to the
//! country the network is registered in. IPs the database does not know match no
//! country or ASN rule; with an allow list set, they are rejected.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::{geoip2, Reader};

/// MaxMind databases for country and ASN lookups.
///
/// Any database with country data works for countries (GeoIP2 or GeoLite2
/// Country, City, Enterprise); ASN rules need a GeoLite2 or GeoIP2 ASN database.
/// Cloning is cheap. Replace the databases at runtime with
/// [`IpFilterHandle::set_geo`](crate::IpFilterHandle::set_geo) after MaxMind's
/// weekly updates.
#[derive(Clone, Default)]
pub struct GeoDb {
    country: Option<Arc<Reader<Vec<u8>>>>,
    asn: Option<Arc<Reader<Vec<u8>>>>,
}

impl GeoDb {
    /// Creates an instance without databases; add them with
    /// [`country_database`](Self::country_database) and
    /// [`asn_database`](Self::asn_database).
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a database with country data from a file.
    pub fn country_database(self, path: impl AsRef<Path>) -> Result<Self, GeoError> {
        self.country_database_bytes(std::fs::read(path).map_err(GeoError::io)?)
    }

    /// Loads a database with country data from bytes.
    pub fn country_database_bytes(mut self, bytes: Vec<u8>) -> Result<Self, GeoError> {
        self.country = Some(Arc::new(Reader::from_source(bytes).map_err(GeoError::db)?));
        Ok(self)
    }

    /// Loads an ASN database from a file.
    pub fn asn_database(self, path: impl AsRef<Path>) -> Result<Self, GeoError> {
        self.asn_database_bytes(std::fs::read(path).map_err(GeoError::io)?)
    }

    /// Loads an ASN database from bytes.
    pub fn asn_database_bytes(mut self, bytes: Vec<u8>) -> Result<Self, GeoError> {
        self.asn = Some(Arc::new(Reader::from_source(bytes).map_err(GeoError::db)?));
        Ok(self)
    }

    /// The ISO 3166-1 alpha-2 country code of `ip`, such as `"SE"`.
    pub fn country(&self, ip: IpAddr) -> Option<CountryCode> {
        let lookup = self.country.as_ref()?.lookup(ip.to_canonical()).ok()?;
        let record: geoip2::Country<'_> = lookup.decode().ok()??;
        let code = record
            .country
            .iso_code
            .or(record.registered_country.iso_code)?;
        CountryCode::parse(code).ok()
    }

    /// The autonomous system number of `ip`.
    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let lookup = self.asn.as_ref()?.lookup(ip.to_canonical()).ok()?;
        let record: geoip2::Asn<'_> = lookup.decode().ok()??;
        record.autonomous_system_number
    }
}

impl fmt::Debug for GeoDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = |reader: &Option<Arc<Reader<Vec<u8>>>>| {
            reader
                .as_ref()
                .map(|reader| reader.metadata().database_type.clone())
        };
        f.debug_struct("GeoDb")
            .field("country", &kind(&self.country))
            .field("asn", &kind(&self.asn))
            .finish()
    }
}

/// An ISO 3166-1 alpha-2 country code, stored uppercase.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Parses two ASCII letters, in either case.
    pub fn parse(code: &str) -> Result<Self, InvalidCountryCode> {
        match code.trim().as_bytes() {
            &[a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => Ok(CountryCode([
                a.to_ascii_uppercase(),
                b.to_ascii_uppercase(),
            ])),
            _ => Err(InvalidCountryCode(code.to_owned())),
        }
    }

    /// The code as a string, such as `"SE"`.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("country codes are ASCII")
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// Returned for country codes that are not two ASCII letters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidCountryCode(String);

impl fmt::Display for InvalidCountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid country code `{}`: expected two letters such as `SE`",
            self.0
        )
    }
}

impl std::error::Error for InvalidCountryCode {}

pub(crate) fn country_codes<I, C>(codes: I) -> Result<Arc<[CountryCode]>, InvalidCountryCode>
where
    I: IntoIterator<Item = C>,
    C: AsRef<str>,
{
    codes
        .into_iter()
        .map(|code| CountryCode::parse(code.as_ref()))
        .collect()
}

/// Returned when a MaxMind database cannot be read.
#[derive(Debug)]
pub struct GeoError(Box<dyn std::error::Error + Send + Sync>);

impl GeoError {
    fn io(err: std::io::Error) -> Self {
        GeoError(Box::new(err))
    }

    fn db(err: maxminddb::MaxMindDbError) -> Self {
        GeoError(Box::new(err))
    }
}

impl fmt::Display for GeoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot read MaxMind database: {}", self.0)
    }
}

impl std::error::Error for GeoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn test_db() -> GeoDb {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");
        GeoDb::new()
            .country_database(format!("{dir}/GeoIP2-Country-Test.mmdb"))
            .unwrap()
            .asn_database(format!("{dir}/GeoLite2-ASN-Test.mmdb"))
            .unwrap()
    }

    #[test]
    fn looks_up_country_and_asn() {
        let db = test_db();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(db.country(ip("89.160.20.112")).unwrap().as_str(), "SE");
        assert_eq!(
            db.country(ip("::ffff:89.160.20.112")).unwrap().as_str(),
            "SE"
        );
        assert_eq!(db.country(ip("81.2.69.160")).unwrap().as_str(), "GB");
        assert_eq!(db.country(ip("10.0.0.1")), None);
        assert_eq!(db.asn(ip("1.128.0.1")), Some(1221));
        assert_eq!(db.asn(ip("1.0.0.1")), Some(15169));
        assert_eq!(db.asn(ip("10.0.0.1")), None);
        assert_eq!(GeoDb::new().country(ip("89.160.20.112")), None);
    }

    #[test]
    fn parses_country_codes() {
        assert_eq!(CountryCode::parse(" se ").unwrap().as_str(), "SE");
        assert!(CountryCode::parse("SWE").is_err());
        assert!(CountryCode::parse("S1").is_err());
        assert!(GeoDb::new().country_database("/nonexistent.mmdb").is_err());
        assert!(GeoDb::new().country_database_bytes(vec![1, 2, 3]).is_err());
    }
}
