# php2shell_guard v1 - 21 Oct 2026
# Virtual patching on BIG-IP LTM for PHP2Shell (CVE-2026-109618 / CVE-2026-109619), for virtual servers in front of
# PHP sites. It is NOT a patch: PHP states there are no complete mitigations and updating is the only safe choice.
# What it does, following the proxy-level limits in PHP's own advisory:
#   - caps the multipart body size (32 MiB; 256 MiB for hosts listed in the data group p2s_big_upload_hosts)
#   - caps the number of multipart parts and the [a][b][c] nesting depth of field names inside the inspected bytes
#     (tiny-part floods and deep nesting are the cheap ways to push PHP to its memory limit = CVE-2026-109618)
#   - blocks the PHP_SESSION_UPLOAD_PROGRESS form field (the confirmed CVE-2026-109619 session path), which also
#     covers a site whose own .user.ini re-enabled session.upload_progress
#   - rejects requests with too many headers, an oversized header, or both Transfer-Encoding and Content-Length
# It covers only traffic that passes through this virtual server; anything reaching the origin directly is uncovered.
#
# Rollout: 1) tmsh create ltm data-group internal p2s_big_upload_hosts type string   (lower-case hostnames)
#          2) attach with static::p2s_enforce 0 and watch /var/log/ltm for 30-60 minutes
#          3) add hosts that legitimately send large uploads or the progress field to the data group / accept the hit
#          4) set static::p2s_enforce 1 and save
# Keep the size/part/header limits after patching; the upload-progress block can be removed once the fleet is patched.

when RULE_INIT {
    set static::p2s_enforce       0            ;# 0 = log only, 1 = block with 403
    set static::p2s_max_body      33554432     ;# 32 MiB multipart body (PHP's advice: post_max_size 32M where uploads are needed)
    set static::p2s_max_body_big  268435456    ;# 256 MiB for hosts in p2s_big_upload_hosts
    set static::p2s_scan_bytes    4194304      ;# how much of a multipart body is inspected for parts / nesting / the progress field
    set static::p2s_max_parts     256          ;# multipart parts inside the inspected bytes
    set static::p2s_max_nesting   32           ;# [a][b]... groups in one field name (PHP's own max_input_nesting_level is 64)
    set static::p2s_max_headers   64
    set static::p2s_max_hdr_bytes 16384        ;# any single header value
    set static::p2s_block_chunked 0            ;# 1 = reject multipart sent with Transfer-Encoding and no Content-Length (browsers never do this)
    set static::p2s_nest_re [format {name="[^"]*(\[[^\]]*\]){%d,}} $static::p2s_max_nesting]
}

# Logs the hit; in enforce mode also answers 403. Returns 1 when the request was answered, 0 when only logged.
proc p2s_hit { reason detail } {
    if { $static::p2s_enforce } { set p2s_action block } else { set p2s_action log-only }
    log local0. "php2shell_guard $p2s_action client=[IP::client_addr] [HTTP::method] [HTTP::host][HTTP::path] reason=$reason detail=$detail"
    if { $static::p2s_enforce } {
        HTTP::respond 403 content "Request blocked\n" noserver "Content-Type" "text/plain" "Connection" "close"
        return 1
    }
    return 0
}

when HTTP_REQUEST {
    set p2s_inspect 0
    set p2s_cap $static::p2s_max_body
    set p2s_boundary ""

    # --- headers: every request -------------------------------------------------------------------
    if { [HTTP::header count] > $static::p2s_max_headers } {
        if { [call p2s_hit too-many-headers [HTTP::header count]] } { return }
    }
    foreach p2s_h [HTTP::header names] {
        if { [string length [HTTP::header value $p2s_h]] > $static::p2s_max_hdr_bytes } {
            if { [call p2s_hit header-too-long "$p2s_h=[string length [HTTP::header value $p2s_h]]"] } { return }
            break
        }
    }

    # --- bodies: only multipart/form-data, the request shape both CVEs are reached through --------
    switch -- [HTTP::method] {
        POST - PUT - PATCH { }
        default { return }
    }
    set p2s_ct [string tolower [string trim [HTTP::header value Content-Type]]]
    if { not ($p2s_ct starts_with "multipart/form-data") } { return }

    if { [class match [string tolower [HTTP::host]] equals p2s_big_upload_hosts] } {
        set p2s_cap $static::p2s_max_body_big
    }

    if { [HTTP::header exists Transfer-Encoding] } {
        if { [HTTP::header exists Content-Length] } {
            if { [call p2s_hit te-and-content-length [HTTP::header value Transfer-Encoding]] } { return }
        }
        if { $static::p2s_block_chunked } {
            if { [call p2s_hit chunked-multipart [HTTP::header value Transfer-Encoding]] } { return }
        }
        # chunked and allowed: measure it as it arrives (HTTP_REQUEST_DATA fires at cap+1 bytes or at end of body)
        set p2s_collect [expr { $p2s_cap + 1 }]
    } else {
        set p2s_cl [HTTP::header value Content-Length]
        # 1-9 digits keeps the comparison inside a 32-bit integer; anything longer is >= 1 GB and rejected as such
        if { not [regexp {^[0-9]{1,9}$} $p2s_cl] } {
            if { [call p2s_hit bad-or-huge-content-length $p2s_cl] } { return }
        } elseif { $p2s_cl > $p2s_cap } {
            if { [call p2s_hit body-too-large "$p2s_cl>$p2s_cap"] } { return }
        }
        set p2s_collect $static::p2s_scan_bytes
        if { $p2s_cap < $p2s_collect } { set p2s_collect $p2s_cap }
    }

    regexp -nocase {boundary=\"?([^\";,[:space:]]+)} $p2s_ct -> p2s_boundary
    set p2s_inspect 1
    HTTP::collect $p2s_collect
}

when HTTP_REQUEST_DATA {
    if { !$p2s_inspect } { HTTP::release ; return }
    set p2s_payload [HTTP::payload]
    set p2s_len [string length $p2s_payload]

    if { [HTTP::header exists Transfer-Encoding] && $p2s_len > $p2s_cap } {
        if { [call p2s_hit chunked-body-too-large "$p2s_len>$p2s_cap"] } { return }
    }

    # 1. the confirmed CVE-2026-109619 session path
    if { [regexp -nocase {name=\"?PHP_SESSION_UPLOAD_PROGRESS} $p2s_payload] } {
        if { [call p2s_hit upload-progress-field ""] } { return }
    }

    # 2. part count inside the inspected bytes
    if { $p2s_boundary ne "" } {
        set p2s_parts 0
        set p2s_pos 0
        set p2s_needle "--$p2s_boundary"
        while { [set p2s_pos [string first $p2s_needle $p2s_payload $p2s_pos]] >= 0 } {
            incr p2s_parts
            incr p2s_pos [string length $p2s_needle]
            if { $p2s_parts > $static::p2s_max_parts } { break }
        }
        if { $p2s_parts > $static::p2s_max_parts } {
            if { [call p2s_hit too-many-parts ">$static::p2s_max_parts in first $p2s_len bytes"] } { return }
        }
    }

    # 3. nesting depth of a field name
    if { [regexp -nocase -- $static::p2s_nest_re $p2s_payload] } {
        if { [call p2s_hit field-nesting ">=$static::p2s_max_nesting"] } { return }
    }

    HTTP::release
}
