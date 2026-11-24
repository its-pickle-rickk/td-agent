/*
 * td-agent / TD framework — Rust Linux RAT (td-enc-v1), "0day-lib" campaign.
 * Static detection for the implant ELF. Defensive threat-intel; no offensive use.
 */
rule td_agent_rust_rat
{
    meta:
        description = "td-agent / TD framework Rust Linux RAT (td-enc-v1)"
        reference   = "https://github.com/its-pickle-rickk/td-agent"
        malware     = "td-agent"
        tlp         = "white"
    strings:
        $p1 = "td-enc-v1" ascii
        $p2 = "ENCSTART1" ascii
        $p3 = "ENCOK1" ascii
        $g  = "ChangeMe_GateToken" ascii        // kit default gate-token prefix
        $t1 = "TD_TUNPROTO" ascii
        $t2 = "TD_WSGATE" ascii
        $t3 = "TD_IDSALT" ascii
        $tpl = "@@TDHOST@@" ascii                // builder template placeholder
        $a1 = ".td-agent.lock" ascii
        $a2 = ".dsync_rs.cache" ascii
    condition:
        uint32(0) == 0x464c457f and             // ELF
        (
            ( $p1 and 2 of ($p2,$p3,$g,$tpl) ) or
            ( 4 of ($t1,$t2,$t3,$a1,$a2) )
        )
}
