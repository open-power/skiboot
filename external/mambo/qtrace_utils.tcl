source $env(LIB_DIR)/perf/qtrace.tcl

proc start_qtrace { { qtfile qtrace.qt } } {
    QTrace::Initialize p9 mysim
    QTrace::Start $qtfile mysim
}

proc stop_qtrace { } {
    QTrace::Stop mysim
}
