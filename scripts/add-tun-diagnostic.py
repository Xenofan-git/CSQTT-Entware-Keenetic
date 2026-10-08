from pathlib import Path

p = Path("csqtt-2.1.9/rust-client/dispatcher.rs")
s = p.read_text()
start = s.index("fn try_write_tun_packet")
needle = "            Ok(Err(error)) => {"
pos = s.index(needle, start)
end = s.index("            Err(_) => TunWriteState::Wait,", pos)
old = s[pos:end]
new = '''            Ok(Err(error)) => {
                if error.raw_os_error() == Some(libc::EINVAL) {
                    let data = packet.as_slice();
                    let bytes = data.iter().take(32).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                    let version = data.first().map(|b| b >> 4).unwrap_or(0);
                    let header = if version == 4 && data.len() >= 20 {
                        format!("IPv4 {}.{}.{}.{} -> {}.{}.{}.{} proto={} ihl={} total_len={}",
                            data[12], data[13], data[14], data[15],
                            data[16], data[17], data[18], data[19], data[9],
                            (data[0] & 0x0f) * 4, u16::from_be_bytes([data[2], data[3]]))
                    } else if version == 6 && data.len() >= 40 {
                        format!("IPv6 next_header={} payload_len={}", data[6], u16::from_be_bytes([data[4], data[5]]))
                    } else {
                        format!("non-IP-or-short version={} len={}", version, data.len())
                    };
                    crate::log_error!("[TUN DEBUG] EINVAL len={} {} first32={}", data.len(), header, bytes);
                }
                crate::log_error!("[ОШИБКА] Запись TUN завершена: {error}");
                TunWriteState::Failed
            }
'''
p.write_text(s[:pos] + new + s[end:])
print("TUN diagnostic inserted")
