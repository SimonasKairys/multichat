use crate::swarm::SwarmLedger;

#[test]
fn action_argument_handles_paths_ending_with_backslash() {
    let list_reqs = SwarmLedger::parse_list_files("ACTION: list_files(src\\)");
    assert_eq!(
        list_reqs,
        vec!["src\\".to_string()],
        "unquoted list_files path ending with backslash must be parsed"
    );

    let read_reqs = SwarmLedger::parse_read_files("ACTION: read_file(docs\\)");
    assert_eq!(
        read_reqs,
        vec!["docs\\".to_string()],
        "unquoted read_file path ending with backslash must be parsed"
    );

    let (writes, _) =
        SwarmLedger::parse_file_writes("ACTION: write_file(src\\)\ncontent\nACTION: end_file");
    assert_eq!(
        writes.len(),
        1,
        "write_file block with path ending in backslash must be parsed"
    );
    assert_eq!(writes[0].path, "src\\");

    let quoted_list = SwarmLedger::parse_list_files("ACTION: list_files(\"src\\\")");
    assert_eq!(
        quoted_list,
        vec!["src\\".to_string()],
        "quoted list_files path ending with backslash must be parsed"
    );
}
