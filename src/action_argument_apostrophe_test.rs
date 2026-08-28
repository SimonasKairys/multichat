use crate::swarm::SwarmLedger;

#[test]
fn unquoted_action_arguments_preserve_apostrophes() {
    let delegations = SwarmLedger::parse_delegations("ACTION: delegate_task(worker, don't stop)");
    assert_eq!(delegations.len(), 1);
    assert_eq!(delegations[0].target, "worker");
    assert_eq!(delegations[0].prompt, "don't stop");

    let reads = SwarmLedger::parse_read_files("ACTION: read_file(src/don't_delete.rs)");
    assert_eq!(reads, vec!["src/don't_delete.rs".to_string()]);
}
