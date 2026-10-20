import os
import tempfile

import pytest
from common import accel_pppd_process, config, process
from helpers import alloc_ports

pytestmark = pytest.mark.xdist_group("fixed-port")


@pytest.mark.l2tp_switch
class TestTargetModePersistentExplicit:
    """Explicit "persistent" parses and the target shows in `l2tp switch show`.
    The peer address is unreachable, so the test does not wait for "[up]"."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,persistent
    """

    def test_switch_target_mode_persistent_explicit(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeOnDemandExplicit:
    """explicit "on-demand" parses and the target still shows in
    `l2tp switch show`."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,on-demand
    """

    def test_switch_target_mode_on_demand_explicit(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeOmittedDefaultsOnDemand:
    """A 4-field target= (mode omitted) parses and defaults to on-demand."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_target_mode_omitted_defaults_on_demand(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeUnknownRejected:
    """An unrecognized 5th field is a fatal config-load error."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,bogus
    """

    def test_switch_target_mode_unknown_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
def test_l2tp_switch_show_empty(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

    assert exit == 0
    assert "targets:" in out


@pytest.mark.l2tp_switch
class TestWithTarget:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    match=Calling-Number,exact,472913,acme
    """

    def test_l2tp_switch_show_target(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestDuplicateMatch:
    """The same exact match= value twice for one attr is a fatal config-load
    error, even for different targets."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Calling-Number,exact,472913,acme
    match=Calling-Number,exact,472913,other
    """

    def test_duplicate_match_value_rejected(self, accel_pppd_instance):
        # l2tp_init() exits on a config load error, so the daemon never
        # becomes ready.
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestOverlappingPrefix:
    """Two prefix rules on one attr where one is a prefix of the other are a
    fatal config-load error."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Proxy-Authen-Name,prefix,downstream,acme
    match=Proxy-Authen-Name,prefix,downstream-a,other
    """

    def test_overlapping_prefix_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestExactOverlapsPrefix:
    """An exact value that matches another rule's prefix is rejected like two
    overlapping prefixes."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Proxy-Authen-Name,prefix,downstream-,acme
    match=Proxy-Authen-Name,exact,downstream-54546,other
    """

    def test_exact_overlapping_prefix_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestSelfLoopTarget:
    """A target whose peer-addr equals the [l2tp] bind address is a fatal
    config-load error."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=loopback,127.0.0.1,1701,targetsecret
    match=Calling-Number,exact,472913,loopback
    """

    @pytest.fixture()
    def accel_pppd_config(self, l2tp_switch_config):
        # Adds [l2tp] bind=. Without it the bind is the wildcard and any
        # local address loops (see TestSelfLoopTargetWildcardBind).
        return (
            """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [l2tp]
    verbose=1
    secret=testsecret
    bind=127.0.0.1

    """
            + l2tp_switch_config
        )

    def test_self_loop_target_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestMalformedTargetRejected:
    """Malformed target= lines (empty or extra fields, trailing junk) are
    fatal config-load errors."""

    @pytest.fixture(
        params=[
            "acme,203.0.113.50,1701,,persistent",  # empty secret
            "acme,203.0.113.50,1701,targetsecret,persistent,extra",  # extra field
            "acme,203.0.113.50,1701abc,targetsecret",  # junk after the port
            "acme,203.0.113.50,,targetsecret",  # empty port
            "ac/me,203.0.113.50,1701,targetsecret",  # name outside [A-Za-z0-9_.-]
            "acme,203.0.113.50,1701,targetsecret,",  # trailing empty mode
        ],
        ids=["empty-secret", "extra-field", "port-junk", "empty-port", "bad-name", "empty-mode"],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    target={request.param}
    """

    def test_switch_target_malformed_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestTargetNameWithDotsDashesAccepted:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=lns-1.example_a,203.0.113.50,1701,targetsecret
    """

    def test_switch_target_name_charset_accepted(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "lns-1.example_a -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestMalformedMatchRejected:
    @pytest.fixture(
        params=[
            "Calling-Number,exact,,acme",  # empty value
            "Calling-Number,exact,472913,acme,extra",  # extra field
            "Calling-Number,exact,472913",  # missing target
        ],
        ids=["empty-value", "extra-field", "missing-target"],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    match={request.param}
    """

    def test_switch_match_malformed_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestTimingOptionsAccepted:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    idle-linger=3
    connect-timeout=7
    reconnect-interval=2
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_timing_options_accepted(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTimingOptionsInvalidRejected:
    """A value that is not a whole number of seconds in 1..3600 is a fatal
    config-load error."""

    @pytest.fixture(
        params=[
            "idle-linger=0",
            "idle-linger=-5",
            "idle-linger=abc",
            "idle-linger=2.5",
            "idle-linger=3601",
            "idle-linger=",
            "connect-timeout=0",
            "connect-timeout=10s",
            "reconnect-interval=0",
            "reconnect-interval=x",
        ],
        ids=[
            "linger-zero", "linger-negative", "linger-text", "linger-fraction",
            "linger-too-big", "linger-empty", "connect-zero", "connect-suffix",
            "reconnect-zero", "reconnect-text",
        ],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    {request.param}
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_timing_invalid_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False

@pytest.mark.l2tp_switch
class TestTargetSecretNotLeakedOnParseError:
    """The target= secret must not appear in the log when parsing fails.

    The daemon exits right after a config load error, before the log-file=
    and log-error= writers flush. log-debug= is written inline, so the test
    reads that instead of helpers.read_log().
    """

    SECRET = "SuperSecretDoNotLeak123"

    @pytest.fixture(
        params=[
            ("acme,203.0.113.50,not-a-port,{secret}", "invalid peer-port"),
            ("acme,not-an-address,1701,{secret}", "invalid peer-addr"),
            # inet_aton() takes these, the strict parser does not
            ("acme,127.1,1701,{secret}", "invalid peer-addr"),
            ("acme,0x7f.0.0.1,1701,{secret}", "invalid peer-addr"),
            ("acme,203.0.113.50,1701,{secret},bogus-mode", "unknown mode"),
        ],
        ids=["bad-port", "bad-addr", "short-addr", "hex-addr", "bad-mode"],
    )
    def target_case(self, request):
        template, expect = request.param
        return template.format(secret=self.SECRET), expect

    def _start(self, accel_pppd, accel_cmd, cli_port, l2tp_port, target_line):
        fd, cfg = tempfile.mkstemp()
        os.close(fd)
        debug = cfg + ".debug"
        with open(cfg, "w") as f:
            f.write(f"""
    [modules]
    log_file
    log_syslog
    l2tp
    [l2tp-switch]
    target={target_line}
    [core]
    log-error={cfg}.err
    [log]
    log-file={cfg}.log
    log-debug={debug}
    level=5
    copy=1
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={l2tp_port}
    secret=testsecret
    [ppp]
    verbose=1
    """)
        started, thread, ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
        )
        return started, thread, ctrl, cfg, debug

    def test_secret_not_leaked_on_target_parse_error(
        self, accel_cmd, accel_pppd, target_case
    ):
        target_line, expect = target_case
        cli_port, l2tp_port = alloc_ports(2)

        started, thread, ctrl, cfg, debug = self._start(
            accel_pppd, accel_cmd, cli_port, l2tp_port, target_line
        )
        try:
            assert started is False, (
                "malformed target= must be a fatal config-load error"
            )

            try:
                with open(debug, "r", errors="replace") as f:
                    log = f.read()
            except OSError:
                log = ""

            assert self.SECRET not in log, (
                f"target= secret leaked into the daemon log:\n{log}"
            )
            assert expect in log, (
                f"expected error ({expect!r}) not found in log:\n{log}"
            )
        finally:
            accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=cli_port)
            config.delete_tmp(cfg)


@pytest.mark.l2tp_switch
class TestSelfLoopTargetWildcardBind:
    """With no [l2tp] bind= the daemon listens on every local address, so a
    target on any local address and the daemon's own port is a loop: a fatal
    config-load error, with a log line that says why. A target on another
    port is fine."""

    LOOP_MSG = "is this host's own [l2tp] bind:port"

    def _start(self, accel_pppd, accel_cmd, cli_port, l2tp_port, target_line):
        fd, cfg = tempfile.mkstemp()
        os.close(fd)
        debug = cfg + ".debug"
        with open(cfg, "w") as f:
            f.write(f"""
    [modules]
    log_file
    log_syslog
    l2tp
    [l2tp-switch]
    target={target_line}
    match=Calling-Number,exact,472913,loopback
    [core]
    log-error={cfg}.err
    [log]
    log-file={cfg}.log
    log-debug={debug}
    level=5
    copy=1
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    port={l2tp_port}
    secret=testsecret
    [ppp]
    verbose=1
    """)
        started, thread, ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
        )
        return started, thread, ctrl, cfg, debug

    @staticmethod
    def _read(path):
        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    @pytest.mark.parametrize("addr", ["127.0.0.1", "127.0.0.2", "0.0.0.0"])
    def test_local_target_on_own_port_rejected(self, accel_cmd, accel_pppd, addr):
        cli_port, l2tp_port = alloc_ports(2)

        started, thread, ctrl, cfg, debug = self._start(
            accel_pppd, accel_cmd, cli_port, l2tp_port,
            f"loopback,{addr},{l2tp_port},targetsecret",
        )
        try:
            assert started is False, f"a target at {addr}:{l2tp_port} loops back"
            log = self._read(debug)
            assert self.LOOP_MSG in log, (
                f"rejected, but not for looping back:\n{log}"
            )
        finally:
            accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=cli_port)
            config.delete_tmp(cfg)

    def test_local_target_on_another_port_accepted(self, accel_cmd, accel_pppd):
        cli_port, l2tp_port, other_port = alloc_ports(3)

        started, thread, ctrl, cfg, debug = self._start(
            accel_pppd, accel_cmd, cli_port, l2tp_port,
            f"loopback,127.0.0.1,{other_port},targetsecret",
        )
        try:
            assert started is True, self._read(debug)
            assert self.LOOP_MSG not in self._read(debug)
        finally:
            accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=cli_port)
            config.delete_tmp(cfg)


@pytest.mark.l2tp_switch
class TestMatchAttrNeverInCallSetup:
    """match= on a string AVP that never appears in an ICRQ or ICCN is a
    fatal config-load error. The matcher only sees Called-Number,
    Calling-Number and Sub-Address (ICRQ) and Proxy-Authen-Name (ICCN), so a
    rule on Host-Name or Vendor-Name would silently never match.

    The daemon exits right after a config load error, so the test reads the
    log-debug= file, which is written inline.
    """

    @pytest.fixture(params=["Host-Name", "Vendor-Name"])
    def attr_name(self, request):
        return request.param

    def test_match_attr_outside_icrq_iccn_rejected(
        self, accel_cmd, accel_pppd, attr_name
    ):
        cli_port, l2tp_port = alloc_ports(2)
        fd, cfg = tempfile.mkstemp()
        os.close(fd)
        debug = cfg + ".debug"
        with open(cfg, "w") as f:
            f.write(f"""
    [modules]
    log_file
    log_syslog
    l2tp
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    match={attr_name},exact,lac-east,acme
    [core]
    log-error={cfg}.err
    [log]
    log-file={cfg}.log
    log-debug={debug}
    level=5
    copy=1
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={l2tp_port}
    secret=testsecret
    [ppp]
    verbose=1
    """)
        started, thread, ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
        )
        try:
            assert started is False, (
                f"match={attr_name} must be a fatal config-load error"
            )
            try:
                with open(debug, "r", errors="replace") as f:
                    log = f.read()
            except OSError:
                log = ""
            assert f"{attr_name} never appears in an ICRQ or ICCN" in log, log
        finally:
            accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=cli_port)
            config.delete_tmp(cfg)
