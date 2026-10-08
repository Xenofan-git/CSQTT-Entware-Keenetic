from pathlib import Path

candidates = [Path("csqtt-current/rust-client/dispatcher.rs"), Path("csqtt-2.1.9/rust-client/dispatcher.rs")]
p = next((x for x in candidates if x.exists()), None)
if p is None:
    raise SystemExit("dispatcher.rs not found in csqtt-current or csqtt-2.1.9")
s = p.read_text()

start = s.index("    async fn read_tun(")
end = s.index("    async fn read_udp(", start)
section = s[start:end]

old = """        let mut scheduler = FastPathScheduler::new();
        let mut flow_sequences = FlowSequencer::new();
        loop {
            let readiness = tokio::select! {
"""
new = """        let mut scheduler = FastPathScheduler::new();
        let mut flow_sequences = FlowSequencer::new();
        let mut tun_debug_reads = 0usize;
        crate::log_error!("[TUN DEBUG] read_tun task started");
        loop {
            if tun_debug_reads < 20 {
                crate::log_error!("[TUN DEBUG] waiting for TUN readable (sample={})", tun_debug_reads);
            }
            let readiness = tokio::select! {
"""
if old not in section:
    raise SystemExit("read_tun start anchor not found")
section = section.replace(old, new, 1)

old = """                Ok(guard) => guard,
"""
new = """                Ok(guard) => {
                    if tun_debug_reads < 20 {
                        crate::log_error!("[TUN DEBUG] TUN became readable (sample={})", tun_debug_reads);
                    }
                    guard
                },
"""
if old not in section:
    raise SystemExit("readable guard anchor not found")
section = section.replace(old, new, 1)

old = """                    Ok(Ok(0)) => return,
                    Ok(Ok(length)) => {
                        burst += 1;
"""
new = """                    Ok(Ok(0)) => {
                        crate::log_error!("[TUN DEBUG] libc::read returned EOF/0");
                        return;
                    }
                    Ok(Ok(length)) => {
                        if tun_debug_reads < 20 {
                            crate::log_error!("[TUN DEBUG] libc::read returned {} bytes", length);
                        }
                        tun_debug_reads += 1;
                        burst += 1;
"""
if old not in section:
    raise SystemExit("read result anchor not found")
section = section.replace(old, new, 1)

old = """                    Ok(Err(error)) if is_retryable_tun_error(&error) => {
                        break;
                    }
"""
new = """                    Ok(Err(error)) if is_retryable_tun_error(&error) => {
                        if tun_debug_reads < 20 {
                            crate::log_error!("[TUN DEBUG] libc::read retryable error: {error}");
                        }
                        tun_debug_reads += 1;
                        break;
                    }
"""
if old not in section:
    raise SystemExit("retry anchor not found")
section = section.replace(old, new, 1)

old = """                    Ok(Err(error)) => {
                        crate::log_error!("[ОШИБКА] Чтение TUN завершено: {error}");
                        return;
                    }
"""
new = """                    Ok(Err(error)) => {
                        crate::log_error!("[TUN DEBUG] libc::read fatal error: {error}");
                        crate::log_error!("[ОШИБКА] Чтение TUN завершено: {error}");
                        return;
                    }
"""
if old not in section:
    raise SystemExit("fatal anchor not found")
section = section.replace(old, new, 1)

p.write_text(s[:start] + section + s[end:])
print("TUN read diagnostics inserted")

