Tests
=====

Various ways to test PgBouncer:

- `test.sh`

    General test of basic functionality and different configuration
    parameters including timeouts, pool size, online restart,
    pause/resume, etc.  To invoke, just run `./test.sh`.  This needs
    PostgreSQL server programs (`initdb`, `pg_ctl`) in the path, so if
    you are on a system that doesn't have those in the normal path
    (e.g., Debian, Ubuntu), set `PATH` beforehand.

    This test is run by `make check`.

    Optionally, this test suite can use `iptables`/`pfctl` to simulate
    various network conditions.  To include these tests, set the
    environment variable USE_SUDO to a nonempty value, for example
    `make check USE_SUDO=1`.  This will ask for sudo access, so it
    might convenient to run `sudo -v` before the test, or set up
    `/etc/sudoers` appropriately at your peril.  Check the source if
    there are any doubts.

- `ssl/test.sh`

    Tests SSL/TLS functionality.  Otherwise very similar to `test.sh`.

    This test is run by `make check` if TLS support is enabled.

- `hba_test`

    Tests hba parsing.  Run `make all` to build and `./hba_test` to execute.

    This test is run by `make check`.

- `run-conntest.sh`

    This is a more complex setup that continuously runs queries
    through PgBouncer while messing around with the network, checking
    whether PgBouncer correctly reconnects and all the queries get
    processed.  First, run `make asynctest` to build, then see
    `run-conntest.sh` how to run the different pieces.

- `stress.py`

    Stress test, see source for details.  Requires Python and `psycopg2` module.
