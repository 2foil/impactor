use std::collections::HashMap;
use std::time::SystemTime;

use omnisette::{AnisetteConfiguration, AnisetteHeaders};

use crate::Error;

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub config: AnisetteConfiguration,
}

impl AnisetteData {
    pub async fn new(config: AnisetteConfiguration) -> Result<Self, Error> {
        let mut b = AnisetteHeaders::get_anisette_headers_provider(config.clone())?;
        let base_headers = b.provider.get_authentication_headers().await?;

        Ok(AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            config,
        })
    }

    pub fn needs_refresh(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() > 60
    }

    pub fn is_valid(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() < 90
    }

    pub async fn refresh(&self) -> Result<Self, crate::Error> {
        Self::new(self.config.clone()).await
    }

    pub fn generate_headers(
        &self,
        cpd: bool,
        client_info: bool,
        app_info: bool,
    ) -> HashMap<String, String> {
        if !self.is_valid() {
            panic!("Invalid data!")
        }

        let mut headers = self.base_headers.clone();
        let old_client_info = headers.remove("X-Mme-Client-Info");

        if client_info {
            let client_info = match old_client_info {
                Some(v) => {
                    let temp = v.as_str();

                    temp.replace(
                        temp.split('<').nth(3).unwrap().split('>').nth(0).unwrap(),
                        "com.apple.AuthKit/1 (com.apple.akd/1.0)",
                    )
                }
                None => {
                    return headers;
                }
            };
            headers.insert("X-Mme-Client-Info".to_owned(), client_info.to_owned());
        }

        if app_info {
            headers.insert(
                "X-Apple-App-Info".to_owned(),
                "com.apple.gs.xcode.auth".to_owned(),
            );
            headers.insert("X-Xcode-Version".to_owned(), "11.2 (11B41)".to_owned());
        }

        if cpd {
            headers.insert("bootstrap".to_owned(), "true".to_owned());
            headers.insert("icscrec".to_owned(), "true".to_owned());
            headers.insert("loc".to_owned(), "en_GB".to_owned());
            headers.insert("pbe".to_owned(), "false".to_owned());
            headers.insert("prkgen".to_owned(), "true".to_owned());
            headers.insert("svct".to_owned(), "iCloud".to_owned());
        }

        headers
    }

    pub fn to_plist(&self, cpd: bool, client_info: bool, app_info: bool) -> plist::Dictionary {
        let mut plist = plist::Dictionary::new();
        for (key, value) in self.generate_headers(cpd, client_info, app_info).iter() {
            plist.insert(key.to_owned(), plist::Value::String(value.to_owned()));
        }

        plist
    }

    pub fn get_header(&self, header: &str) -> Result<String, Error> {
        let headers = self
            .generate_headers(true, true, true)
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect::<HashMap<String, String>>();

        match headers.get(&header.to_lowercase()) {
            Some(v) => Ok(v.to_string()),
            None => Err(Error::DeveloperSessionRequestFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_CLIENT_INFO: &str = "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.akd/1.0>";

    fn mac_anisette() -> AnisetteData {
        AnisetteData {
            base_headers: HashMap::from([
                ("X-Mme-Client-Info".to_string(), MAC_CLIENT_INFO.to_string()),
                ("X-Apple-I-MD".to_string(), "synthetic-otp".to_string()),
                (
                    "X-Apple-I-MD-M".to_string(),
                    "synthetic-machine-id".to_string(),
                ),
            ]),
            generated_at: SystemTime::now(),
            config: AnisetteConfiguration::default(),
        }
    }

    #[test]
    fn mac_identity_is_retained_for_two_factor_and_developer_headers() {
        let data = mac_anisette();

        let headers = data.generate_headers(false, true, true);

        assert_eq!(
            headers["X-Mme-Client-Info"],
            "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
        assert_eq!(headers["X-Apple-App-Info"], "com.apple.gs.xcode.auth");
        assert_eq!(headers["X-Xcode-Version"], "11.2 (11B41)");
        assert_eq!(headers["X-Apple-I-MD"], "synthetic-otp");
        assert_eq!(data.base_headers["X-Mme-Client-Info"], MAC_CLIENT_INFO);
    }

    #[test]
    fn srp_cpd_retains_anisette_without_adding_client_or_app_info() {
        let data = mac_anisette();

        let cpd = data.to_plist(true, false, false);

        assert!(!cpd.contains_key("X-Mme-Client-Info"));
        assert!(!cpd.contains_key("X-Apple-App-Info"));
        assert!(!cpd.contains_key("X-Xcode-Version"));
        assert_eq!(cpd["X-Apple-I-MD"].as_string(), Some("synthetic-otp"));
        assert_eq!(
            cpd["X-Apple-I-MD-M"].as_string(),
            Some("synthetic-machine-id")
        );
        assert_eq!(cpd["bootstrap"].as_string(), Some("true"));
        assert_eq!(cpd["svct"].as_string(), Some("iCloud"));
        assert_eq!(data.base_headers["X-Mme-Client-Info"], MAC_CLIENT_INFO);
    }
}
