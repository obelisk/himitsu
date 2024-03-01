use regex::{Regex, RegexSet};

use crate::ScanResults;

pub struct RegexSystem {
    regexes: Vec<NamedRegex>,
    regex_set: RegexSet,
}

pub struct NamedRegex {
    pub regex: Regex,
    pub name: String,
}

impl RegexSystem {
    pub fn default() -> Self {
        let regexes = vec![
            NamedRegex {
                regex: Regex::new("(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})").unwrap(),
                name: "SlackToken".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("-----BEGIN RSA PRIVATE KEY-----").unwrap(),
                name: "RsaPrivateKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
                name: "OpenSshPrivateKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("-----BEGIN DSA PRIVATE KEY-----").unwrap(),
                name: "DsaPrivateKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("-----BEGIN EC PRIVATE KEY-----").unwrap(),
                name: "EcPrivateKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
                name: "PgpPrivateKeyBlock".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("-----BEGIN PRIVATE KEY-----").unwrap(),
                name: "PgpPrivateKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----").unwrap(),
                name: "Ssh2EncryptedPrivateKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("-----BEGIN ENCRYPTED PRIVATE KEY-----").unwrap(),
                name: "PgpEncryptedPrivateKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]").unwrap(),
                name: "FacebookOAuth".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]").unwrap(),
                name: "TwitterOAuth".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]").unwrap(),
                name: "Github".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("(gh[ps]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})").unwrap(),
                name: "Github Token".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")").unwrap(),
                name: "GoogleOAuth".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("AKIA[0-9A-Z]{16}").unwrap(),
                name: "AwsKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}").unwrap(),
                name: "HerokuApiKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new(r#"(?i)(\b\w+(?:[-_]\w+)*)?(?:key|api|secret|client|passwd|password|auth|access)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-z\-_.=+\/]{10,150})(?:['|\"|\n|\r|\s|\x60|;]|$)"#).unwrap(),
                name: "GenericSecret".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}").unwrap(),
                name: "SlackWebhook".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("\"type\": \"service_account\"11530").unwrap(),
                name: "GcpServiceAccout".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("SK[a-z0-9]{32}").unwrap(),
                name: "TwilioApiKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]").unwrap(),
                name: "PasswordInUrl".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("slack-corp").unwrap(),
                name: "SlackInternal".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("^0x[a-fA-F0-9]{64}[\r\n]$").unwrap(),
                name: "EthPrivateKey".to_owned(),
            },
            NamedRegex {
                regex: Regex::new("npm_[A-Za-z0-9]{36}").unwrap(),
                name: "NpmToken".to_owned(),
            }
        ];
        
        let regex_set = RegexSet::new(
            regexes.iter().map(|r| r.regex.as_str())
        ).unwrap();
    
        Self {
            regexes,
            regex_set,
        }
    }
}

impl super::System for RegexSystem {
    fn scan(&self, haystack: &str) -> ScanResults {
        // Find all the regexes that match anything in the given haystack
        let matches: Vec<_> = self.regex_set.matches(haystack).into_iter().collect();

        // For any regex that matches, we need to find the actual perts that matched
        // and return those as scan results.
        matches.iter().map(|m| {
            let regex = &self.regexes[*m];
            let matches = regex.regex.find_iter(haystack);

            matches.into_iter().map(|m| {
                super::ScanResult {
                    system: "Regex".to_owned(),
                    name: regex.name.clone(),
                    value: m.as_str().to_owned(),
                }
            }).collect::<ScanResults>()
        }).flatten().collect()
    }
}