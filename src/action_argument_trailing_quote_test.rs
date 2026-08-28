use crate::swarm::SwarmLedger;

#[test]
fn quoted_path_ending_in_backslash_ignores_later_quoted_prose() {
    let reads = SwarmLedger::parse_read_files(r#"ACTION: read_file("docs\") for "documentation""#);

    assert_eq!(reads, vec!["docs\\".to_string()]);
}
